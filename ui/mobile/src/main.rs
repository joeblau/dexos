//! `dexos-mobile` — the iOS/Android frontend.
//!
//! Shares the desktop model: it links the native [`client`] and renders the
//! shared [`dexos_ui`] components against a live node. The endpoint comes from
//! `DEXOS_NODE_ADDR` (default `127.0.0.1:8080`); a fetch failure degrades to the
//! table's empty state.
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

/// Fetch the market list, degrading to an empty list on any error.
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
