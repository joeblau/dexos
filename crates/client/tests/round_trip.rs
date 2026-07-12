//! End-to-end: drive the typed [`Client`] against a live in-process RPC server
//! (an `rpc::StubBackend` over real loopback TCP). Exercises the whole client
//! path — request build, frame encode, socket write, server decode/dispatch,
//! response frame, decode, and typed variant unwrap — without a live `marketd`.

use std::net::SocketAddr;
use std::sync::Arc;

use client::Client;
use proto::{MarketDetail, MarketSummary};
use rpc::{RpcBackend, RpcMode, StubBackend};
use tokio::net::TcpListener;
use types::{MarketId, MarketLifecycle, MarketType, Price, Quantity};

/// Bind an ephemeral plaintext RPC server for `backend` and return its address.
/// The spawned task keeps serving for the lifetime of the test runtime.
async fn serve(backend: Arc<dyn RpcBackend>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = rpc::serve(listener, backend, RpcMode::Full).await;
    });
    addr
}

fn sample_market() -> MarketDetail {
    MarketDetail {
        summary: MarketSummary {
            market_id: MarketId::new(1),
            market_type: MarketType::Perpetual,
            lifecycle: MarketLifecycle::Open,
        },
        tick_size: Price::ONE,
        lot_size: Quantity::ONE,
        symbol: "BTC-PERP".into(),
        outcomes: 1,
    }
}

#[tokio::test]
async fn client_round_trips_node_and_network_queries() {
    let addr = serve(Arc::new(StubBackend::new(RpcMode::Full))).await;
    let client = Client::new(addr);

    // Both succeed against an unconfigured stub (mirrors the dexos e2e coverage).
    client.get_node_info().await.expect("get_node_info");
    client
        .get_network_status()
        .await
        .expect("get_network_status");
}

#[tokio::test]
async fn client_lists_and_fetches_a_seeded_market() {
    let stub = StubBackend::new(RpcMode::Full);
    stub.insert_market(sample_market());
    let addr = serve(Arc::new(stub)).await;
    let client = Client::new(addr);

    let markets = client
        .get_markets(Default::default())
        .await
        .expect("get_markets");
    assert_eq!(markets.len(), 1);
    assert_eq!(markets[0].market_id, MarketId::new(1));

    let detail = client
        .get_market(MarketId::new(1))
        .await
        .expect("get_market");
    assert_eq!(detail.symbol, "BTC-PERP");
    assert_eq!(detail.outcomes, 1);
}
