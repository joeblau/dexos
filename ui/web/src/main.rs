//! `dexos-web` — the browser (wasm) frontend.
//!
//! A thin shell around the shared [`dexos_ui`] components. It renders the
//! markets view; live data will be supplied by Dioxus server functions (which
//! call the native `client` server-side) in a follow-up — for now the table
//! renders its empty state so the wasm build and layout are exercised end to end.
#![forbid(unsafe_code)]

use dexos_ui::MarketsTable;
use dioxus::prelude::*;
use proto::MarketSummary;

fn main() {
    dioxus::launch(App);
}

#[component]
fn App() -> Element {
    // Placeholder until server functions wire the live `client` query.
    let markets: Vec<MarketSummary> = Vec::new();
    rsx! {
        header { h1 { "DexOS" } }
        main {
            section {
                h2 { "Markets" }
                MarketsTable { markets }
            }
        }
    }
}
