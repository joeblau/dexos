//! `dexos-desktop` — the native desktop frontend.
//!
//! Links the native [`mod@client`] directly (no server-function hop) and renders the
//! shared [`dexos_ui`] components against a live node. The node endpoint is read
//! from `DEXOS_NODE_ADDR` (default `127.0.0.1:8080`); a fetch failure degrades to
//! the table's empty state rather than crashing the shell.
#![forbid(unsafe_code)]

use std::net::SocketAddr;

use client::Client;
use dexos_ui::MarketsTable;
use dioxus::prelude::*;
use proto::MarketSummary;

fn main() {
    dioxus::launch(App);
}

/// Resolve the node RPC endpoint from the environment, falling back to loopback.
fn node_addr() -> SocketAddr {
    std::env::var("DEXOS_NODE_ADDR")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| ([127, 0, 0, 1], 8080).into())
}

/// Fetch the market list from the node, degrading to an empty list on any
/// transport/RPC error so the shell always renders.
async fn fetch_markets() -> Vec<MarketSummary> {
    let client = Client::new(node_addr());
    client
        .get_markets(Default::default())
        .await
        .unwrap_or_default()
}

#[component]
fn App() -> Element {
    let markets = use_resource(fetch_markets);
    let rows = markets.read().clone().unwrap_or_default();
    rsx! {
        header { h1 { "DexOS" } }
        main {
            section {
                h2 { "Markets" }
                MarketsTable { markets: rows }
            }
        }
    }
}
