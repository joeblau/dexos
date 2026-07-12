//! End-to-end: run the compiled `dexos` binary against a live plaintext RPC
//! server (an in-process `StubBackend`) and assert it round-trips over real
//! loopback TCP. This exercises the whole client path — frame encode, socket
//! write, server decode/dispatch, response frame, decode, and render — which
//! the in-crate unit tests (parsing + signing) cannot cover on their own.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::Arc;

use rpc::{RpcBackend, RpcMode, StubBackend};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use types::AccountId;

/// Bind a plaintext (`TlsMode::Disabled` via `ServerConfig::default`) RPC server
/// on an ephemeral port, serving the given pre-built backend. Returns the
/// runtime — kept alive by the caller so its worker threads keep serving — and
/// the bound address.
fn start_server_with(backend: Arc<dyn RpcBackend>) -> (Runtime, SocketAddr) {
    let runtime = Runtime::new().expect("build tokio runtime");
    let addr = runtime.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = rpc::serve(listener, backend, RpcMode::Full).await;
        });
        addr
    });
    (runtime, addr)
}

/// [`start_server_with`] over a fresh, unconfigured [`StubBackend`].
fn start_server() -> (Runtime, SocketAddr) {
    start_server_with(Arc::new(StubBackend::new(RpcMode::Full)))
}

/// Removes the file at `path` when dropped, so a failed assertion cannot leak
/// key material into `CARGO_TARGET_TMPDIR` across runs.
struct TempFile(PathBuf);

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Write `seed` as lowercase hex to a scratch file the spawned binary can read
/// with `--key`.
fn write_seed_file(name: &str, seed: &[u8; 32]) -> TempFile {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::write(&path, hex::encode(seed)).expect("write seed file");
    TempFile(path)
}

/// Run the real `dexos` binary against `addr` with the given subcommand args.
fn run_dexos(addr: SocketAddr, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_dexos"))
        .arg("--target")
        .arg(addr.to_string())
        .args(args)
        .output()
        .expect("spawn dexos binary")
}

#[test]
fn get_node_info_round_trips_over_tcp() {
    let (_runtime, addr) = start_server();
    let out = run_dexos(addr, &["get-node-info"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "dexos exited nonzero: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("NodeInfo"), "unexpected output: {stdout}");
}

#[test]
fn get_network_status_round_trips_over_tcp() {
    let (_runtime, addr) = start_server();
    let out = run_dexos(addr, &["get-network-status"]);
    assert!(
        out.status.success(),
        "dexos exited nonzero: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("NetworkStatus"));
}

/// The authenticated write path, end to end through the shipped binary: the
/// CLI loads an ed25519 seed from `--key`, lowers `cancel-all` to a canonical
/// `Command`, signs it into a `ControlMeta`, and sends it over real loopback
/// TCP; the server verifies the signature against the account's registered
/// root key, ingests it through the `(client_id, nonce)` idempotency store,
/// and returns a `CommandAck` that the CLI renders. None of the unit tests
/// cover this chain through the compiled binary.
#[test]
fn signed_cancel_all_round_trips_a_command_ack_over_tcp() {
    // Deterministic key: fixed seed -> keypair; the seed file is what the
    // binary reads, the public key is what the server must verify against.
    let seed = [7u8; 32];
    let keypair = crypto::KeyPair::from_seed(&seed);

    // Register the account's root authorization key on the concrete stub
    // BEFORE coercing to `Arc<dyn RpcBackend>`: without it, the stub's direct
    // control path fails closed with Unauthorized.
    let stub = StubBackend::new(RpcMode::Full);
    stub.register_account_key(AccountId::new(1), keypair.public());
    let (_runtime, addr) = start_server_with(Arc::new(stub));

    let seed_file = write_seed_file("signed_cancel_all.seed", &seed);
    let seed_path = seed_file.0.to_str().expect("utf-8 scratch path");

    // `--nonce` is required for control commands; pass it explicitly.
    let out = run_dexos(
        addr,
        &[
            "--key",
            seed_path,
            "--client-id",
            "7",
            "--nonce",
            "1",
            "cancel-all",
            "--account",
            "1",
        ],
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "dexos exited nonzero: stdout={stdout} stderr={stderr}"
    );
    // The rendered payload is `RpcOk::CommandAck(..)` with an `Accepted`
    // finality — proof the signature verified and the command was ingested
    // (an InvalidSignature/Unauthorized would have been a nonzero exit).
    assert!(stdout.contains("CommandAck"), "unexpected output: {stdout}");
    assert!(stdout.contains("Accepted"), "unexpected output: {stdout}");
}

#[test]
fn connection_refused_is_a_clean_nonzero_exit() {
    // Nothing is listening on this port: the client must fail gracefully (nonzero
    // exit, error on stderr) rather than panic.
    let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let out = run_dexos(addr, &["get-node-info"]);
    assert!(!out.status.success(), "expected a nonzero exit");
    assert!(String::from_utf8_lossy(&out.stderr).contains("error:"));
}
