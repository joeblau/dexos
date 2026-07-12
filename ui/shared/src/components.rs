//! Shared Dioxus components. Renderer-agnostic: the launching app (web, desktop,
//! or mobile) supplies the renderer; these components only describe the tree.

use dioxus::prelude::*;
use proto::MarketSummary;

/// A read-only table of market summaries. The app fetches the list (server
/// function on web, native `client` on desktop/mobile) and passes it in.
#[component]
pub fn MarketsTable(markets: Vec<MarketSummary>) -> Element {
    rsx! {
        table { class: "markets",
            thead {
                tr {
                    th { "Market" }
                    th { "Type" }
                    th { "Status" }
                }
            }
            tbody {
                if markets.is_empty() {
                    tr {
                        td { colspan: "3", class: "empty", "No markets" }
                    }
                } else {
                    for m in markets.iter() {
                        tr { key: "{m.market_id:?}",
                            td { "{m.market_id:?}" }
                            td { "{m.market_type:?}" }
                            td { "{m.lifecycle:?}" }
                        }
                    }
                }
            }
        }
    }
}
