//! End-to-end: run the compiled `dexos` binary against a live plaintext RPC
//! server (an in-process `StubBackend`) and assert it round-trips over real
//! loopback TCP. This exercises the whole client path — frame encode, socket
//! write, server decode/dispatch, response frame, decode, and render — which
//! the in-crate unit tests (parsing + signing) cannot cover on their own.

use std::net::SocketAddr;
use std::process::{Command, Output};
use std::sync::Arc;

use rpc::{RpcBackend, RpcMode, StubBackend};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;

/// Bind a plaintext (`TlsMode::Disabled` via `ServerConfig::default`) RPC server
/// on an ephemeral port. Returns the runtime — kept alive by the caller so its
/// worker threads keep serving — and the bound address.
fn start_server() -> (Runtime, SocketAddr) {
    let runtime = Runtime::new().expect("build tokio runtime");
    let addr = runtime.block_on(async {
        let backend: Arc<dyn RpcBackend> = Arc::new(StubBackend::new(RpcMode::Full));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = rpc::serve(listener, backend, RpcMode::Full).await;
        });
        addr
    });
    (runtime, addr)
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

#[test]
fn connection_refused_is_a_clean_nonzero_exit() {
    // Nothing is listening on this port: the client must fail gracefully (nonzero
    // exit, error on stderr) rather than panic.
    let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let out = run_dexos(addr, &["get-node-info"]);
    assert!(!out.status.success(), "expected a nonzero exit");
    assert!(String::from_utf8_lossy(&out.stderr).contains("error:"));
}
