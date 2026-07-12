//! Real, socket-backed **measured mode** for the load generator.
//!
//! The [`engine`](crate::engine) simulation is deterministic and never touches the
//! network: it composes fixed per-stage cost constants into a modelled latency. That
//! is useful for reproducible planning, but it is *not* a measurement of a running
//! node — it happily reports low latencies for a target that does not exist.
//!
//! This module closes that gap. [`run_measured`] opens a real TCP connection to the
//! configured target, submits framed order commands over the socket, reads framed
//! receipts back, and times each round trip with the wall clock. Every latency it
//! reports is an observed round-trip time; **no fixed latency constant enters this
//! path**. Two guards make a dishonest report impossible:
//!
//! 1. An unreachable target fails at connect with [`LoadError::Unreachable`].
//! 2. At end of run the generator's submitted count is reconciled against the
//!    server's own received count (and every receipt is matched to its request key);
//!    a mismatch is a hard [`LoadError::Reconciliation`] error.
//!
//! The wire protocol is intentionally tiny and framed with [`codec::Frame`] so it
//! shares the peer envelope: a `SUBMIT` frame carries a 16-byte idempotency key plus
//! a one-byte command kind; a `RECEIPT` frame echoes the key plus an accept/reject
//! status byte; a closing `RECONCILE`/`RECONCILE_ACK` exchange carries `u64` counts.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use codec::{Frame, TrafficClass, FRAME_HEADER_LEN, MAX_FRAME_PAYLOAD};

use crate::command::{CommandKind, GeneratedCommand, SessionState};
use crate::config::LoadScenario;
use crate::engine::LoadError;
use crate::metrics::{Percentiles, SampleSet};
use crate::rng::Lcg;
use crate::util::{fnv1a_64, fold_u64, json_escape};

/// Application message tag: client submits a command (`SUBMIT`).
pub const MSG_SUBMIT: u16 = 1;
/// Application message tag: server acknowledges a command (`RECEIPT`).
pub const MSG_RECEIPT: u16 = 2;
/// Application message tag: client requests end-of-run reconciliation.
pub const MSG_RECONCILE: u16 = 3;
/// Application message tag: server reports its total received count.
pub const MSG_RECONCILE_ACK: u16 = 4;

/// Connect timeout for the measured target.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Per-request read/write timeout so a stalled server cannot hang the run forever.
const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// Upper bound on measured requests so an enormous configured rate stays tractable.
/// The report's `planned` still reflects the full configured rate.
const MAX_MEASURED_REQUESTS: u64 = 200_000;

/// The result of a measured run against a live target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeasuredReport {
    /// The target the run actually connected to.
    pub target: String,
    /// Commands the plan would submit at the configured rate over its duration.
    pub planned: u64,
    /// Commands actually submitted over the socket (bounded).
    pub submitted: u64,
    /// Receipts the server acknowledged (equals `submitted` on success).
    pub receipts: u64,
    /// Commands the server accepted.
    pub accepted: u64,
    /// Commands the server rejected.
    pub rejected: u64,
    /// The count the server independently reported at reconciliation.
    pub server_received: u64,
    /// Measured round-trip receipt latency percentiles, nanoseconds.
    pub latency: Percentiles,
    /// Latency samples dropped due to the fixed-capacity buffer.
    pub dropped_samples: u64,
    /// Seed used, so the submitted command stream can be reproduced.
    pub seed: u64,
}

impl MeasuredReport {
    /// Render the report as a machine-readable JSON document. Integers and strings
    /// only — no floating point — matching the simulation report style. The `mode`
    /// field marks this as a live measurement, distinct from a simulation.
    #[must_use]
    pub fn to_json(&self) -> String {
        let p = &self.latency;
        format!(
            "{{\"mode\":\"measured\",\"target\":\"{}\",\"seed\":{},\"planned\":{},\
\"submitted\":{},\"receipts\":{},\"accepted\":{},\"rejected\":{},\
\"server_received\":{},\"dropped_samples\":{},\
\"latency\":{{\"count\":{},\"p50\":{},\"p90\":{},\"p95\":{},\"p99\":{},\"p999\":{},\"max\":{}}}}}",
            json_escape(&self.target),
            self.seed,
            self.planned,
            self.submitted,
            self.receipts,
            self.accepted,
            self.rejected,
            self.server_received,
            self.dropped_samples,
            p.count,
            p.p50,
            p.p90,
            p.p95,
            p.p99,
            p.p999,
            p.max,
        )
    }
}

/// Drive the scenario against a **live** target over a real socket and measure it.
///
/// # Errors
/// - [`LoadError::Config`] if the scenario fails validation.
/// - [`LoadError::Unreachable`] if the target cannot be resolved or connected.
/// - [`LoadError::Io`] on a socket read/write failure or a malformed server frame.
/// - [`LoadError::Reconciliation`] if a receipt key mismatches its request, or the
///   server's reported received count does not equal the submitted count.
pub fn run_measured(scenario: &LoadScenario) -> Result<MeasuredReport, LoadError> {
    scenario.validate()?;
    let mut stream = connect(&scenario.target)?;

    let planned = scenario.planned_actions();
    let budget = planned.min(MAX_MEASURED_REQUESTS);

    // A distinct RNG stream from the simulation so the two modes never alias, yet
    // still fully determined by the seed for a reproducible submitted stream.
    let mut rng = Lcg::new(fold_u64(
        scenario.seed,
        fnv1a_64(b"dexos.loadgen.measured.v1"),
    ));

    let user_count = scenario.total_users().clamp(1, MAX_MEASURED_REQUESTS);
    let mut sessions: Vec<SessionState> = (0..user_count)
        .map(|i| SessionState::new(u32::try_from(i).unwrap_or(u32::MAX)))
        .collect();

    let mut latency = SampleSet::new(scenario.sample_capacity);
    let mut submitted: u64 = 0;
    let mut receipts: u64 = 0;
    let mut accepted: u64 = 0;
    let mut rejected: u64 = 0;

    let mut cursor: usize = 0;
    let mut seq: u64 = 0;
    let session_count = sessions.len();
    for _ in 0..budget {
        let session = &mut sessions[cursor % session_count];
        cursor = cursor.wrapping_add(1);
        let cmd = session.next_command(&mut rng, scenario);
        seq = seq.wrapping_add(1);

        let request = submit_frame(seq, &cmd);
        // The timed region is exactly the round trip: write the request, read the
        // receipt. No processing-cost constant is involved.
        let started = Instant::now();
        write_frame(&mut stream, &request)?;
        let receipt = read_frame(&mut stream)?;
        let rtt_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);

        submitted = submitted.saturating_add(1);
        let (key, status) = decode_receipt(&receipt.payload)
            .ok_or_else(|| LoadError::Io("malformed receipt payload".to_string()))?;
        // A receipt whose key does not match the outstanding request means the server
        // acknowledged something we did not send: the counts cannot reconcile.
        if key != cmd.idempotency_key {
            return Err(LoadError::Reconciliation {
                submitted,
                receipts,
            });
        }
        receipts = receipts.saturating_add(1);
        if status {
            accepted = accepted.saturating_add(1);
        } else {
            rejected = rejected.saturating_add(1);
        }
        latency.record(rtt_ns);
    }

    // End-of-run reconciliation against the server's own tally.
    let server_received = reconcile(&mut stream, submitted)?;
    if submitted != receipts || server_received != submitted {
        return Err(LoadError::Reconciliation {
            submitted,
            receipts: server_received.min(receipts),
        });
    }

    Ok(MeasuredReport {
        target: scenario.target.clone(),
        planned,
        submitted,
        receipts,
        accepted,
        rejected,
        server_received,
        latency: latency.percentiles(),
        dropped_samples: latency.dropped(),
        seed: scenario.seed,
    })
}

/// Resolve and connect to `target`, mapping every failure to [`LoadError::Unreachable`].
fn connect(target: &str) -> Result<TcpStream, LoadError> {
    let unreachable = |reason: String| LoadError::Unreachable {
        target: target.to_string(),
        reason,
    };
    let addr = target
        .to_socket_addrs()
        .map_err(|e| unreachable(format!("resolve: {e}")))?
        .next()
        .ok_or_else(|| unreachable("no addresses resolved".to_string()))?;
    let stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
        .map_err(|e| unreachable(e.to_string()))?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|e| LoadError::Io(e.to_string()))?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|e| LoadError::Io(e.to_string()))?;
    Ok(stream)
}

/// Perform the closing reconciliation handshake and return the server's count.
fn reconcile(stream: &mut TcpStream, submitted: u64) -> Result<u64, LoadError> {
    let frame = Frame {
        class: TrafficClass::Sync,
        msg_type: MSG_RECONCILE,
        sequence: submitted,
        payload: submitted.to_be_bytes().to_vec(),
    };
    write_frame(stream, &frame)?;
    let ack = read_frame(stream)?;
    let bytes: [u8; 8] = ack
        .payload
        .as_slice()
        .try_into()
        .map_err(|_| LoadError::Io("malformed reconciliation ack".to_string()))?;
    Ok(u64::from_be_bytes(bytes))
}

/// Build a `SUBMIT` frame for a generated command.
#[must_use]
pub fn submit_frame(sequence: u64, cmd: &GeneratedCommand) -> Frame {
    let mut payload = Vec::with_capacity(17);
    payload.extend_from_slice(&cmd.idempotency_key.to_be_bytes());
    payload.push(kind_byte(cmd.kind));
    Frame {
        class: TrafficClass::NewOrder,
        msg_type: MSG_SUBMIT,
        sequence,
        payload,
    }
}

/// Build a `RECEIPT` frame acknowledging an idempotency key. Exposed so a conforming
/// receipt server (including the test server) can construct correct acknowledgements.
#[must_use]
pub fn receipt_frame(sequence: u64, idempotency_key: u128, accepted: bool) -> Frame {
    let mut payload = Vec::with_capacity(17);
    payload.extend_from_slice(&idempotency_key.to_be_bytes());
    payload.push(u8::from(accepted));
    Frame {
        class: TrafficClass::ExecutionReceipt,
        msg_type: MSG_RECEIPT,
        sequence,
        payload,
    }
}

/// Decode a `SUBMIT` payload into its `(idempotency_key, kind_byte)`.
#[must_use]
pub fn decode_submit(payload: &[u8]) -> Option<(u128, u8)> {
    if payload.len() != 17 {
        return None;
    }
    let key = u128::from_be_bytes(payload[..16].try_into().ok()?);
    Some((key, payload[16]))
}

/// Decode a `RECEIPT` payload into its `(idempotency_key, accepted)`.
#[must_use]
fn decode_receipt(payload: &[u8]) -> Option<(u128, bool)> {
    if payload.len() != 17 {
        return None;
    }
    let key = u128::from_be_bytes(payload[..16].try_into().ok()?);
    Some((key, payload[16] != 0))
}

/// Stable one-byte encoding of a command kind for the wire.
const fn kind_byte(kind: CommandKind) -> u8 {
    match kind {
        CommandKind::NewOrder => 0,
        CommandKind::Cancel => 1,
        CommandKind::Replace => 2,
    }
}

/// Write a whole frame to the stream, flushing it.
fn write_frame(stream: &mut TcpStream, frame: &Frame) -> Result<(), LoadError> {
    let bytes = frame
        .encode()
        .map_err(|e| LoadError::Io(format!("frame encode: {e}")))?;
    stream
        .write_all(&bytes)
        .map_err(|e| LoadError::Io(e.to_string()))?;
    stream.flush().map_err(|e| LoadError::Io(e.to_string()))?;
    Ok(())
}

/// Read exactly one frame from the stream: the fixed header, then the declared payload.
fn read_frame(stream: &mut TcpStream) -> Result<Frame, LoadError> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    stream
        .read_exact(&mut header)
        .map_err(|e| LoadError::Io(e.to_string()))?;
    // Bytes 15..19 are the little-endian payload length (see codec::Frame::encode).
    let plen = u32::from_le_bytes([header[15], header[16], header[17], header[18]]) as usize;
    if plen > MAX_FRAME_PAYLOAD {
        return Err(LoadError::Io("declared payload exceeds cap".to_string()));
    }
    let mut buf = vec![0u8; FRAME_HEADER_LEN + plen];
    buf[..FRAME_HEADER_LEN].copy_from_slice(&header);
    stream
        .read_exact(&mut buf[FRAME_HEADER_LEN..])
        .map_err(|e| LoadError::Io(e.to_string()))?;
    let (frame, _) =
        Frame::decode(&buf).map_err(|e| LoadError::Io(format!("frame decode: {e}")))?;
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RegionConfig;
    use std::net::{SocketAddr, TcpListener};
    use std::thread::{self, JoinHandle};

    /// How the test receipt server should (mis)behave, to exercise each guard.
    #[derive(Clone, Copy)]
    enum ServerMode {
        /// Honest: echo each key, accept all, report the true received count.
        Honest,
        /// Echo a corrupted key on the first receipt (reconciliation must fail).
        CorruptFirstKey,
        /// Under-report the received count at reconciliation.
        UnderReport,
        /// Reject every submitted command (still reconciles, but accepted == 0).
        RejectAll,
    }

    /// Spawn an in-process receipt server bound to an ephemeral loopback port.
    fn spawn_server(mode: ServerMode) -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let handle = thread::spawn(move || {
            let (mut stream, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(_) => return,
            };
            let mut received: u64 = 0;
            let mut first = true;
            loop {
                let frame = match read_frame(&mut stream) {
                    Ok(f) => f,
                    // EOF or timeout: the client is done or gone.
                    Err(_) => return,
                };
                match frame.msg_type {
                    MSG_SUBMIT => {
                        let Some((key, _kind)) = decode_submit(&frame.payload) else {
                            return;
                        };
                        received = received.saturating_add(1);
                        let echoed = if matches!(mode, ServerMode::CorruptFirstKey) && first {
                            key ^ 0xFFFF
                        } else {
                            key
                        };
                        first = false;
                        let accept = !matches!(mode, ServerMode::RejectAll);
                        let receipt = receipt_frame(frame.sequence, echoed, accept);
                        if write_frame(&mut stream, &receipt).is_err() {
                            return;
                        }
                    }
                    MSG_RECONCILE => {
                        let reported = match mode {
                            ServerMode::UnderReport => received.saturating_sub(1),
                            _ => received,
                        };
                        let ack = Frame {
                            class: TrafficClass::Sync,
                            msg_type: MSG_RECONCILE_ACK,
                            sequence: reported,
                            payload: reported.to_be_bytes().to_vec(),
                        };
                        let _ = write_frame(&mut stream, &ack);
                        return;
                    }
                    _ => return,
                }
            }
        });
        (addr, handle)
    }

    fn scenario_for(addr: SocketAddr) -> LoadScenario {
        LoadScenario {
            seed: 7,
            target: addr.to_string(),
            orders_per_second: 20,
            duration_secs: 1,
            sample_capacity: 4096,
            regions: vec![RegionConfig {
                name: "measured".to_string(),
                users: 8,
                ..RegionConfig::default()
            }],
            ..LoadScenario::default()
        }
    }

    #[test]
    fn honest_server_reconciles_and_measures_latency() {
        let (addr, handle) = spawn_server(ServerMode::Honest);
        let report = run_measured(&scenario_for(addr)).expect("measured run");
        handle.join().unwrap();

        assert_eq!(report.submitted, 20, "20/s * 1s");
        assert_eq!(report.receipts, report.submitted);
        assert_eq!(report.server_received, report.submitted);
        assert_eq!(report.accepted, report.submitted);
        assert_eq!(report.rejected, 0);
        // Every round trip was measured, so the latency buffer is fully populated.
        assert_eq!(report.latency.count, report.submitted);
        assert!(
            report.latency.max > 0,
            "a real round trip takes nonzero time"
        );
        assert_eq!(report.dropped_samples, 0);
        // The JSON marks the run as a live measurement.
        assert!(report.to_json().contains("\"mode\":\"measured\""));
    }

    #[test]
    fn unreachable_target_fails() {
        // Bind then immediately drop the listener so the port refuses connections.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        drop(listener);

        let err = run_measured(&scenario_for(addr)).expect_err("must fail");
        assert!(
            matches!(err, LoadError::Unreachable { .. }),
            "expected Unreachable, got {err:?}"
        );
    }

    #[test]
    fn unresolvable_target_fails_without_panic() {
        let mut s = scenario_for("127.0.0.1:1".parse().unwrap());
        s.target = "definitely-not-a-real-host.invalid:9000".to_string();
        let err = run_measured(&s).expect_err("must fail");
        assert!(matches!(err, LoadError::Unreachable { .. }), "{err:?}");
    }

    #[test]
    fn corrupt_receipt_key_fails_reconciliation() {
        let (addr, handle) = spawn_server(ServerMode::CorruptFirstKey);
        let err = run_measured(&scenario_for(addr)).expect_err("must fail");
        let _ = handle.join();
        assert!(
            matches!(err, LoadError::Reconciliation { .. }),
            "expected Reconciliation, got {err:?}"
        );
    }

    #[test]
    fn server_under_report_fails_reconciliation() {
        let (addr, handle) = spawn_server(ServerMode::UnderReport);
        let err = run_measured(&scenario_for(addr)).expect_err("must fail");
        let _ = handle.join();
        match err {
            LoadError::Reconciliation {
                submitted,
                receipts,
            } => {
                assert_eq!(submitted, 20);
                assert_eq!(receipts, 19, "server acknowledged one fewer");
            }
            other => panic!("expected Reconciliation, got {other:?}"),
        }
    }

    #[test]
    fn rejected_commands_are_counted_and_still_reconcile() {
        let (addr, handle) = spawn_server(ServerMode::RejectAll);
        let report = run_measured(&scenario_for(addr)).expect("run");
        handle.join().unwrap();
        assert_eq!(report.submitted, 20);
        assert_eq!(report.receipts, 20);
        assert_eq!(report.accepted, 0);
        assert_eq!(report.rejected, 20);
    }

    #[test]
    fn measured_stream_is_reproducible_for_a_seed() {
        let (addr1, h1) = spawn_server(ServerMode::Honest);
        let mut s1 = scenario_for(addr1);
        s1.seed = 123;
        let r1 = run_measured(&s1).unwrap();
        h1.join().unwrap();

        let (addr2, h2) = spawn_server(ServerMode::Honest);
        let mut s2 = scenario_for(addr2);
        s2.seed = 123;
        let r2 = run_measured(&s2).unwrap();
        h2.join().unwrap();

        // Same seed => same submitted/accepted counts (the command stream replays).
        assert_eq!(r1.submitted, r2.submitted);
        assert_eq!(r1.accepted, r2.accepted);
    }
}
