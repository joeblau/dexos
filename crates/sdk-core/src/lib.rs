#![forbid(unsafe_code)]
//! `dexos-sdk-core` — the transport-free, wasm-safe single source of truth for
//! the DexOS client SDKs.
//!
//! Every language package (npm/wasm, pip/python, native rust) is a thin shim
//! that embeds this crate and only marshals arguments and moves bytes. All wire
//! logic — types, ed25519 signing, the control-signing preimage, postcard
//! encode/decode, and frame construction — lives here and is proven once by the
//! [`poc`] and `abi_freeze` conformance surfaces.
//!
//! It is pure: no tokio, no rustls, no I/O. The whole crate is a superset of the
//! `ui/web` wasm build, so it compiles for `wasm32-unknown-unknown` as well as
//! every native target.

pub mod builders;
pub mod convert;
pub mod poc;
pub mod signer;
pub mod transport;

#[cfg(test)]
mod abi_freeze;

// The full transport-free wire surface. The `proto` glob is the only glob
// import; the `types`/`crypto`/`codec` re-exports are explicit and therefore
// win over it for any (currently non-existent) name overlap, and the local
// `transport` module shadows `proto`'s `transport` module. This is the single
// contract downstream bindings consume.
pub use codec::{self, Frame, FrameRef, TrafficClass, FRAME_HEADER_LEN};
pub use crypto::{self, verify_ed25519, EvmKeyPair, KeyPair};
pub use proto::{self, *};
pub use types::{
    self, format_amount, parse_amount, AccountId, Amount, Hash, MarketId, MarketLifecycle,
    MarketType, OrderId, OrderType, Price, Quantity, Ratio, SequenceNumber, ShardId, Side,
    SponsorId, TimeInForce, AMOUNT_SCALE, PRICE_SCALE, QTY_SCALE, RATIO_SCALE,
};

pub use signer::Signer;
pub use transport::{Client, Transport, TransportError};
