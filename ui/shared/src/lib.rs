//! `dexos-ui` — renderer-agnostic Dioxus components and view models shared by
//! the DexOS web, desktop, and mobile frontends.
//!
//! This crate is deliberately **wasm-safe**: it depends only on `dioxus` (with
//! no renderer feature — each app picks web/desktop/mobile) and the
//! transport-free [`proto`] wire types. It never links the async `client`/`rpc`
//! stack. Data fetching is the app's job — the web app calls server functions,
//! desktop/mobile call the native `client` — and the results are handed to
//! these components as props.
//!
//! # Layout
//! - [`mod@format`] — integer-only fixed-point formatting (no float ever, mirroring
//!   the engine's no-float discipline for anything derived from wire scalars).
//! - [`components`] — the shared Dioxus components (e.g. [`components::MarketsTable`]).
#![forbid(unsafe_code)]

pub mod components;
pub mod format;

pub use components::MarketsTable;
