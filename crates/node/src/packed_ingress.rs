//! Authenticated packed-order batch admission into a lock-free shard owner.
//!
//! The compact record intentionally omits connection-owned identity material.
//! This adapter requires that material explicitly, validates it against every
//! record, lowers without allocation, and reserves the whole SPSC batch before
//! publishing its first command.

use codec::PackedOrder;
use execution::{Authorization, CancelOrder, Command, PlaceOrder, ReplaceOrder};
use network::{
    AuthenticatedOrderBatchCodec, AuthenticatedOrderBatchError, OrderBatchCodec, OrderBatchError,
    OrderBatchReplayGuard, ORDER_BATCH_MAX_UNCOMPRESSED,
};
use types::{AccountId, OrderId, OrderType, SequenceNumber};

use crate::{BatchReceiptTrackerError, ShardCommand, ShardIngress};

const MAX_BATCH_RECORDS: usize = 128;
const DEFAULT_INSTRUMENT: u16 = 0;

/// Stateful authority established by the authenticated connection/session
/// layer before packed bytes are admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackedAuthority {
    /// Account root key; its batch signature has already been verified.
    Master,
    /// Scoped session key; the engine still consumes each record nonce and
    /// applies market, expiry, and notional scope.
    Session { session_key: [u8; 32] },
}

/// Trusted connection and sequencer metadata omitted from compact records.
///
/// Construction does not authenticate anything. Callers may create this value
/// only after verifying the outer batch authenticator over the canonical
/// `PackedBatchBinding` preimage and resolving `session_ref` to `account`,
/// and `authority`. Per-command `client_id` and nonce remain in each signed
/// packed record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedPackedBatch {
    pub session_ref: u32,
    pub account: AccountId,
    pub authority: PackedAuthority,
    pub first_sequence: SequenceNumber,
    pub sequencer_now: u64,
}

/// Successful all-or-nothing batch admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackedBatchAdmission {
    /// Outer authenticated batch sequence for production admissions.
    pub batch_sequence: Option<u64>,
    pub record_count: u8,
    pub first_sequence: SequenceNumber,
    pub last_sequence: SequenceNumber,
    pub decode_backend: simd::Backend,
}

/// Identity and starting sequences established by a production session handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackedSession {
    pub destination: [u8; 32],
    pub session_ref: u32,
    pub account: AccountId,
    pub signer: [u8; 32],
    pub authority: PackedAuthority,
    pub first_batch_sequence: u64,
    pub first_command_sequence: SequenceNumber,
    pub batch_sequence_stride: u64,
    /// Zero means the admitted record count (the legacy contiguous-session
    /// default). Otherwise this divided by `batch_sequence_stride` is the exact
    /// fixed record count accepted for every session batch.
    pub command_sequence_stride: u64,
}

/// Production admission surface: verifies the outer signature and strict replay
/// state before delegating to the allocation-free decode/lower/SPSC adapter.
pub struct AuthenticatedPackedBatchIngress {
    packed: PackedBatchIngress,
    replay: OrderBatchReplayGuard,
    session: PackedSession,
}

impl AuthenticatedPackedBatchIngress {
    #[must_use]
    pub fn new(session: PackedSession) -> Self {
        Self {
            packed: PackedBatchIngress::new(),
            replay: OrderBatchReplayGuard::with_strides(
                session.first_batch_sequence,
                session.first_command_sequence.get(),
                session.batch_sequence_stride,
                session.command_sequence_stride,
            ),
            session,
        }
    }

    /// Authenticate and atomically admit one complete batch. Replay state advances
    /// only after successful SPSC publication, so a backpressured identical retry is
    /// safe while an already-admitted replay is rejected.
    pub fn try_admit(
        &mut self,
        ingress: &mut ShardIngress,
        bytes: &[u8],
        sequencer_now: u64,
    ) -> Result<PackedBatchAdmission, AuthenticatedPackedIngressError> {
        self.try_admit_after(ingress, bytes, sequencer_now, |_| Ok(()))
            .map(|(admission, ())| admission)
    }

    /// Authenticate and validate the complete batch, run one pre-publication
    /// hook with its exact admission range, then publish and advance replay
    /// state. The hook runs only after every fallible ingress check and before
    /// the first SPSC tail publication; validator callers use it to preflight
    /// receipt tracking before the durability barrier. Its output is returned
    /// with the admission, making a successful commit without its preflight
    /// token unrepresentable.
    pub fn try_admit_after<F, T>(
        &mut self,
        ingress: &mut ShardIngress,
        bytes: &[u8],
        sequencer_now: u64,
        before_publish: F,
    ) -> Result<(PackedBatchAdmission, T), AuthenticatedPackedIngressError>
    where
        F: FnOnce(PackedBatchAdmission) -> Result<T, PackedIngressError>,
    {
        let verified = AuthenticatedOrderBatchCodec::verify(bytes, &self.session.destination)?;
        if verified.signer != self.session.signer {
            return Err(AuthenticatedPackedIngressError::SignerMismatch);
        }
        if verified.binding.session_ref != self.session.session_ref {
            return Err(AuthenticatedPackedIngressError::OuterSessionMismatch);
        }
        if verified.binding.account != self.session.account {
            return Err(AuthenticatedPackedIngressError::OuterAccountMismatch);
        }
        let record_count = OrderBatchCodec::inspect_record_count(verified.envelope)
            .map_err(PackedIngressError::Envelope)?;
        self.replay
            .check_admission(&verified.binding, record_count)?;
        let (admitted, output) = self.packed.try_admit_after(
            ingress,
            verified.envelope,
            AuthenticatedPackedBatch {
                session_ref: self.session.session_ref,
                account: self.session.account,
                authority: self.session.authority,
                first_sequence: SequenceNumber::new(verified.binding.first_sequence),
                sequencer_now,
            },
            |admission| {
                before_publish(PackedBatchAdmission {
                    batch_sequence: Some(verified.binding.batch_sequence),
                    ..admission
                })
            },
        )?;
        self.replay
            .commit(&verified.binding, admitted.record_count)?;
        Ok((
            PackedBatchAdmission {
                batch_sequence: Some(verified.binding.batch_sequence),
                ..admitted
            },
            output,
        ))
    }

    #[must_use]
    pub const fn next_batch_sequence(&self) -> u64 {
        self.replay.next_batch_sequence()
    }

    #[must_use]
    pub const fn next_command_sequence(&self) -> SequenceNumber {
        SequenceNumber::new(self.replay.next_first_sequence())
    }
}

/// Failure before or during authenticated packed shard admission.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthenticatedPackedIngressError {
    #[error("authenticated packed batch failed: {0}")]
    Authentication(#[from] AuthenticatedOrderBatchError),
    #[error("authenticated packed batch signer is not the established session signer")]
    SignerMismatch,
    #[error("authenticated packed batch names another outer session")]
    OuterSessionMismatch,
    #[error("authenticated packed batch names another outer account")]
    OuterAccountMismatch,
    #[error("packed batch admission failed: {0}")]
    Admission(#[from] PackedIngressError),
}

/// Packed batch rejection. No command is published for any returned error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PackedIngressError {
    #[error("invalid order batch: {0}")]
    Envelope(#[from] OrderBatchError),
    #[error("invalid packed record: {0}")]
    Record(#[from] codec::PackedOrderError),
    #[error("record {index} names session {actual}, authenticated session is {expected}")]
    SessionMismatch {
        index: u8,
        expected: u32,
        actual: u32,
    },
    #[error("record {index} names account {actual:?}, authenticated account is {expected:?}")]
    AccountMismatch {
        index: u8,
        expected: AccountId,
        actual: AccountId,
    },
    #[error("batch sequence range overflows u64")]
    SequenceExhausted,
    #[error("shard ingress has {available} slots, batch needs {needed}")]
    Backpressure { needed: usize, available: usize },
    #[error("packed batch durability barrier failed: {0}")]
    Durability(String),
    #[error("packed receipt admission preflight failed: {0}")]
    ReceiptPreflight(#[from] BatchReceiptTrackerError),
}

/// Worker-local bounded scratch for decompress, parse, lower, and SPSC publish.
/// Construction allocates the byte buffer once; successful warmed admissions do
/// not allocate.
pub struct PackedBatchIngress {
    decoded: Vec<u8>,
    records: [PackedOrder; MAX_BATCH_RECORDS],
}

impl PackedBatchIngress {
    #[must_use]
    pub fn new() -> Self {
        let placeholder = PackedOrder::Cancel {
            session_ref: 0,
            nonce: 0,
            client_id: 0,
            account: AccountId::new(0),
            market: types::MarketId::new(0),
            order_id: OrderId::new(1),
        };
        Self {
            decoded: vec![0; ORDER_BATCH_MAX_UNCOMPRESSED],
            records: [placeholder; MAX_BATCH_RECORDS],
        }
    }

    /// Decode and atomically publish one authenticated envelope.
    ///
    /// Every fallible validation, lowering precondition, sequence-range check,
    /// and capacity check happens before the first SPSC tail publication. Once
    /// capacity is observed, the sole producer owns the reservation while the
    /// consumer can only free more slots.
    pub fn try_admit(
        &mut self,
        ingress: &mut ShardIngress,
        envelope: &[u8],
        context: AuthenticatedPackedBatch,
    ) -> Result<PackedBatchAdmission, PackedIngressError> {
        self.try_admit_after(ingress, envelope, context, |_| Ok(()))
            .map(|(admission, ())| admission)
    }

    /// Validate the complete batch and reserve ring capacity, invoke a caller's
    /// pre-publication hook with the exact range, then publish the already-
    /// validated records. The hook output is returned alongside the admission.
    pub fn try_admit_after<F, T>(
        &mut self,
        ingress: &mut ShardIngress,
        envelope: &[u8],
        context: AuthenticatedPackedBatch,
        before_publish: F,
    ) -> Result<(PackedBatchAdmission, T), PackedIngressError>
    where
        F: FnOnce(PackedBatchAdmission) -> Result<T, PackedIngressError>,
    {
        let decoded =
            OrderBatchCodec::decode_records_into(envelope, &mut self.decoded, &mut self.records)?;
        let count = decoded.records.len();
        let last_raw = context
            .first_sequence
            .get()
            .checked_add(u64::try_from(count).unwrap_or(u64::MAX) - 1)
            .ok_or(PackedIngressError::SequenceExhausted)?;

        let records = decoded.records;
        for (index, &record) in records.iter().enumerate() {
            let index = u8::try_from(index).unwrap_or(u8::MAX);
            if record.session_ref() != context.session_ref {
                return Err(PackedIngressError::SessionMismatch {
                    index,
                    expected: context.session_ref,
                    actual: record.session_ref(),
                });
            }
            if record.account() != context.account {
                return Err(PackedIngressError::AccountMismatch {
                    index,
                    expected: context.account,
                    actual: record.account(),
                });
            }
        }

        let available = ingress.available_capacity();
        if available < count {
            return Err(PackedIngressError::Backpressure {
                needed: count,
                available,
            });
        }

        let admission = PackedBatchAdmission {
            batch_sequence: None,
            record_count: u8::try_from(count).unwrap_or(u8::MAX),
            first_sequence: context.first_sequence,
            last_sequence: SequenceNumber::new(last_raw),
            decode_backend: decoded.backend,
        };
        let output = before_publish(admission)?;

        for (offset, &record) in records.iter().enumerate() {
            let sequence = SequenceNumber::new(
                context.first_sequence.get() + u64::try_from(offset).unwrap_or(u64::MAX),
            );
            let command = lower_record(record, context);
            // The sole producer preflighted the full range. A consumer may only
            // create more space, so failure here would mean the ring invariant
            // itself was violated rather than ordinary backpressure.
            assert!(
                ingress
                    .try_submit(ShardCommand { sequence, command })
                    .is_ok(),
                "preflighted SPSC batch reservation was lost"
            );
        }

        Ok((admission, output))
    }
}

impl Default for PackedBatchIngress {
    fn default() -> Self {
        Self::new()
    }
}

fn authorization(record: PackedOrder, context: AuthenticatedPackedBatch) -> Authorization {
    match context.authority {
        PackedAuthority::Master => Authorization::Master,
        PackedAuthority::Session { session_key } => Authorization::Session {
            session_key,
            nonce: record.nonce(),
            now: context.sequencer_now,
        },
    }
}

fn lower_record(record: PackedOrder, context: AuthenticatedPackedBatch) -> Command {
    let auth = authorization(record, context);
    match record {
        PackedOrder::Submit {
            nonce,
            account,
            market,
            side,
            order_type,
            price,
            quantity,
            time_in_force,
            leverage: _,
            client_id,
            session_ref: _,
        } => Command::PlaceOrder(PlaceOrder {
            account,
            market,
            order_id: OrderId::new(nonce),
            side,
            order_type,
            tif: time_in_force,
            price,
            quantity,
            client_id,
            reduce_only: order_type == OrderType::ReduceOnly,
            instrument: DEFAULT_INSTRUMENT,
            auth,
        }),
        PackedOrder::Cancel {
            account,
            market,
            order_id,
            session_ref: _,
            nonce: _,
            client_id: _,
        } => Command::CancelOrder(CancelOrder {
            market,
            account,
            order_id,
            auth,
        }),
        PackedOrder::Replace {
            account,
            market,
            order_id,
            new_price,
            new_quantity,
            session_ref: _,
            nonce: _,
            client_id: _,
        } => Command::ReplaceOrder(ReplaceOrder {
            market,
            account,
            order_id,
            price: new_price,
            quantity: new_quantity,
            auth,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::KeyPair;
    use execution::{CreateAccount, CreateMarket, DeterministicEngine, Engine, EngineConfig};
    use network::{AuthenticatedOrderBatchCodec, OrderBatchBinding};
    use types::{
        Amount, MarketId, MarketType, Price, Quantity, Ratio, Side, TimeInForce, RATIO_SCALE,
    };

    fn submit(session_ref: u32, nonce: u64, account: u32) -> PackedOrder {
        PackedOrder::Submit {
            session_ref,
            nonce,
            client_id: nonce,
            account: AccountId::new(account),
            market: MarketId::new(0),
            side: Side::Bid,
            order_type: OrderType::Limit,
            price: Price::from_raw(1),
            quantity: Quantity::from_raw(1),
            time_in_force: TimeInForce::Gtc,
            leverage: Ratio::from_raw(RATIO_SCALE),
        }
    }

    fn envelope(records: &[PackedOrder]) -> Vec<u8> {
        let mut packed = vec![0; records.len() * codec::PACKED_SUBMIT_LEN];
        let len = codec::encode_batch_into(records, &mut packed).unwrap();
        let mut codec = OrderBatchCodec::new();
        codec
            .encode(u8::try_from(records.len()).unwrap(), false, &packed[..len])
            .unwrap()
            .bytes
            .to_vec()
    }

    fn authenticated_envelope(
        records: &[PackedOrder],
        signer: &KeyPair,
        batch_sequence: u64,
        first_sequence: u64,
    ) -> Vec<u8> {
        authenticated_envelope_with_partial(records, signer, batch_sequence, first_sequence, false)
    }

    fn authenticated_envelope_with_partial(
        records: &[PackedOrder],
        signer: &KeyPair,
        batch_sequence: u64,
        first_sequence: u64,
        partial: bool,
    ) -> Vec<u8> {
        let mut packed = vec![0; records.len() * codec::PACKED_SUBMIT_LEN];
        let len = if partial {
            let mut at = 0;
            for &record in records {
                at += record.encode_into(&mut packed[at..]).unwrap();
            }
            at
        } else {
            codec::encode_batch_into(records, &mut packed).unwrap()
        };
        let mut codec = AuthenticatedOrderBatchCodec::new();
        codec
            .encode(
                OrderBatchBinding {
                    destination: [5; 32],
                    session_ref: 7,
                    account: AccountId::new(0),
                    batch_sequence,
                    first_sequence,
                },
                signer,
                u8::try_from(records.len()).unwrap(),
                partial,
                &packed[..len],
            )
            .unwrap()
            .bytes
            .to_vec()
    }

    fn packed_session(signer: &KeyPair, first_sequence: u64) -> PackedSession {
        PackedSession {
            destination: [5; 32],
            session_ref: 7,
            account: AccountId::new(0),
            signer: signer.public(),
            authority: PackedAuthority::Master,
            first_batch_sequence: 11,
            first_command_sequence: SequenceNumber::new(first_sequence),
            batch_sequence_stride: 1,
            command_sequence_stride: 0,
        }
    }

    fn context(first: u64) -> AuthenticatedPackedBatch {
        AuthenticatedPackedBatch {
            session_ref: 7,
            account: AccountId::new(0),
            authority: PackedAuthority::Master,
            first_sequence: SequenceNumber::new(first),
            sequencer_now: 123,
        }
    }

    fn engine() -> Engine {
        let mut engine = Engine::new(EngineConfig::default());
        engine
            .execute(
                SequenceNumber::new(1),
                Command::CreateAccount(CreateAccount {
                    initial_collateral: Amount::from_raw(1_000_000_000),
                }),
            )
            .unwrap();
        engine
            .execute(
                SequenceNumber::new(2),
                Command::CreateMarket(CreateMarket {
                    market: MarketId::new(0),
                    market_type: MarketType::Perpetual,
                    outcomes: 1,
                    mark_price: Price::from_raw(1_000_000),
                }),
            )
            .unwrap();
        engine
    }

    #[test]
    fn authenticated_batch_is_lowered_and_published_in_order() {
        let records: Vec<_> = (0..32)
            .map(|i| submit(7, u64::try_from(i + 10).unwrap(), 0))
            .collect();
        let envelope = envelope(&records);
        let (mut ingress, mut worker, mut egress) =
            crate::shard_pipeline(engine(), 64, 64).unwrap();
        let mut packed = PackedBatchIngress::new();
        let admitted = packed
            .try_admit(&mut ingress, &envelope, context(3))
            .unwrap();
        assert_eq!(admitted.record_count, 32);
        assert_eq!(admitted.last_sequence, SequenceNumber::new(34));
        for expected in 3..35 {
            assert_eq!(worker.step(), crate::ShardStep::Processed);
            let effect = egress.try_recv().unwrap();
            assert_eq!(effect.sequence, SequenceNumber::new(expected));
            assert!(effect.result.is_ok());
        }
    }

    #[test]
    fn context_mismatch_and_backpressure_reject_the_whole_batch() {
        let good: Vec<_> = (0..32)
            .map(|i| submit(7, u64::try_from(i + 1).unwrap(), 0))
            .collect();
        let mut bad = good.clone();
        bad[17] = submit(8, 18, 0);
        let (mut ingress, mut worker, _) = crate::shard_pipeline(engine(), 32, 64).unwrap();
        let mut packed = PackedBatchIngress::new();
        assert!(matches!(
            packed.try_admit(&mut ingress, &envelope(&bad), context(3)),
            Err(PackedIngressError::SessionMismatch { index: 17, .. })
        ));
        assert_eq!(worker.step(), crate::ShardStep::Idle);

        assert!(ingress
            .try_submit(ShardCommand {
                sequence: SequenceNumber::new(3),
                command: Command::CreateAccount(CreateAccount {
                    initial_collateral: Amount::ZERO,
                }),
            })
            .is_ok());
        assert_eq!(
            packed.try_admit(&mut ingress, &envelope(&good), context(4)),
            Err(PackedIngressError::Backpressure {
                needed: 32,
                available: 31
            })
        );
        assert_eq!(worker.step(), crate::ShardStep::Processed);
        assert_eq!(worker.step(), crate::ShardStep::Idle);
    }

    #[test]
    fn session_authority_uses_record_nonce_and_sequencer_time() {
        let record = submit(7, 55, 0);
        let context = AuthenticatedPackedBatch {
            authority: PackedAuthority::Session {
                session_key: [9; 32],
            },
            ..context(3)
        };
        let Command::PlaceOrder(order) = lower_record(record, context) else {
            panic!("submit must lower to place order");
        };
        assert_eq!(order.order_id, OrderId::new(55));
        assert_eq!(order.client_id, 55);
        assert_eq!(
            order.auth,
            Authorization::Session {
                session_key: [9; 32],
                nonce: 55,
                now: 123
            }
        );
    }

    #[test]
    fn sequence_exhaustion_precedes_publication() {
        let records: Vec<_> = (0..32)
            .map(|i| submit(7, u64::try_from(i + 1).unwrap(), 0))
            .collect();
        let (mut ingress, mut worker, _) = crate::shard_pipeline(engine(), 64, 64).unwrap();
        let mut packed = PackedBatchIngress::new();
        assert_eq!(
            packed.try_admit(&mut ingress, &envelope(&records), context(u64::MAX - 30)),
            Err(PackedIngressError::SequenceExhausted)
        );
        assert_eq!(worker.step(), crate::ShardStep::Idle);
    }

    #[test]
    fn durability_hook_precedes_publication_and_failure_preserves_replay() {
        let signer = KeyPair::from_seed(&[9; 32]);
        let records: Vec<_> = (0..32)
            .map(|i| submit(7, u64::try_from(i + 10).unwrap(), 0))
            .collect();
        let bytes = authenticated_envelope(&records, &signer, 11, 4);
        let (mut ingress, mut worker, _) = crate::shard_pipeline(engine(), 64, 64).unwrap();
        let mut authenticated = AuthenticatedPackedBatchIngress::new(packed_session(&signer, 4));
        let error = authenticated
            .try_admit_after(&mut ingress, &bytes, 123, |_| {
                Err::<(), _>(PackedIngressError::Durability("fdatasync failed".into()))
            })
            .unwrap_err();
        assert!(matches!(
            error,
            AuthenticatedPackedIngressError::Admission(PackedIngressError::Durability(_))
        ));
        assert_eq!(authenticated.next_batch_sequence(), 11);
        assert_eq!(worker.step(), crate::ShardStep::Idle);

        let mut durable = false;
        authenticated
            .try_admit_after(&mut ingress, &bytes, 123, |_| {
                durable = true;
                Ok(())
            })
            .unwrap();
        assert!(durable);
        assert_eq!(worker.step(), crate::ShardStep::Processed);
    }

    #[test]
    fn fixed_stride_width_rejects_before_hook_replay_or_publication() {
        let signer = KeyPair::from_seed(&[10; 32]);
        for (count, partial) in [(31usize, true), (33, false), (64, false)] {
            let records: Vec<_> = (0..count)
                .map(|i| submit(7, u64::try_from(i + 10).unwrap(), 0))
                .collect();
            let bytes = authenticated_envelope_with_partial(&records, &signer, 11, 4, partial);
            let (mut ingress, mut worker, _) = crate::shard_pipeline(engine(), 128, 128).unwrap();
            let mut session = packed_session(&signer, 4);
            session.batch_sequence_stride = 2;
            session.command_sequence_stride = 64;
            let mut authenticated = AuthenticatedPackedBatchIngress::new(session);
            let mut hook_called = false;

            assert!(matches!(
                authenticated.try_admit_after(&mut ingress, &bytes, 123, |_| {
                    hook_called = true;
                    Ok(())
                }),
                Err(AuthenticatedPackedIngressError::Authentication(
                    AuthenticatedOrderBatchError::BatchWidth {
                        expected: 32,
                        actual
                    }
                )) if actual == u8::try_from(count).unwrap()
            ));
            assert!(!hook_called);
            assert_eq!(authenticated.next_batch_sequence(), 11);
            assert_eq!(
                authenticated.next_command_sequence(),
                SequenceNumber::new(4)
            );
            assert_eq!(ingress.available_capacity(), 128);
            assert_eq!(worker.step(), crate::ShardStep::Idle);
        }
    }

    #[test]
    fn production_wrapper_authenticates_rejects_replay_and_preserves_retry() {
        let signer = KeyPair::from_seed(&[9; 32]);
        let records: Vec<_> = (0..32)
            .map(|i| submit(7, u64::try_from(i + 10).unwrap(), 0))
            .collect();
        let bytes = authenticated_envelope(&records, &signer, 11, 4);
        let (mut ingress, mut worker, _) = crate::shard_pipeline(engine(), 32, 64).unwrap();
        assert!(ingress
            .try_submit(ShardCommand {
                sequence: SequenceNumber::new(3),
                command: Command::CreateAccount(CreateAccount {
                    initial_collateral: Amount::ZERO,
                }),
            })
            .is_ok());
        let mut authenticated = AuthenticatedPackedBatchIngress::new(packed_session(&signer, 4));
        assert!(matches!(
            authenticated.try_admit(&mut ingress, &bytes, 123),
            Err(AuthenticatedPackedIngressError::Admission(
                PackedIngressError::Backpressure { .. }
            ))
        ));
        assert_eq!(authenticated.next_batch_sequence(), 11);
        assert_eq!(worker.step(), crate::ShardStep::Processed);
        let admitted = authenticated.try_admit(&mut ingress, &bytes, 123).unwrap();
        assert_eq!(admitted.record_count, 32);
        assert_eq!(authenticated.next_batch_sequence(), 12);
        assert_eq!(
            authenticated.next_command_sequence(),
            SequenceNumber::new(36)
        );
        assert!(matches!(
            authenticated.try_admit(&mut ingress, &bytes, 123),
            Err(AuthenticatedPackedIngressError::Authentication(
                AuthenticatedOrderBatchError::BatchSequence { .. }
            ))
        ));

        let mut tampered = bytes;
        tampered[120] ^= 1;
        let mut fresh = AuthenticatedPackedBatchIngress::new(packed_session(&signer, 4));
        assert!(matches!(
            fresh.try_admit(&mut ingress, &tampered, 123),
            Err(AuthenticatedPackedIngressError::Authentication(
                AuthenticatedOrderBatchError::Signature(_)
            ))
        ));
    }
}
