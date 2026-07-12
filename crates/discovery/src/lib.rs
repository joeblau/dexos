//! `discovery` — signed peer records, peer and market discovery.
//!
//! This crate is the membership and rendezvous layer of DexOS. It defines the
//! self-signed [`PeerRecord`] gossip primitive and a bounded [`PeerTable`] that
//! provides:
//!
//! - **Bootstrap** from static seeds and a pluggable [`SeedResolver`] (DNS/HTTP),
//!   with automatic fallback when a resolver fails.
//! - **Gossip ingestion** with signature verification, replay/duplicate
//!   suppression, and bounded re-forwarding.
//! - **Reputation** that penalizes peers sending invalid/replayed records and
//!   evicts those below a floor, with a hard capacity cap.
//! - **Liveness** tracking (alive/stale/dead) and pruning of expired records.
//! - **Selection** that is role-aware, region-aware, and latency-aware, always
//!   including a geographically diverse fallback when one exists.
//! - **Market discovery** indexing which peers advertise which [`MarketId`].
//!
//! Every decode/verify path is total: adversarial bytes yield a typed error,
//! never a panic. No floating point, no `unsafe`, no `unwrap` on untrusted input.
//!
//! [`MarketId`]: types::MarketId

#![deny(unsafe_code)]

mod record;
mod service;
mod table;

/// Crate identity, used by the node composition root for a startup manifest.
pub const CRATE_NAME: &str = "discovery";

pub use record::{
    NodeId, PeerRecord, RecordError, Region, Role, RoleSet, MAX_ADDRESSES, MAX_ADDRESS_BYTES,
    MAX_ADDRESSES_TOTAL_BYTES, MAX_MARKET_IDS, MAX_PROTOCOLS, MAX_REGIONS, MAX_STATIC_SEEDS,
};
pub use service::{
    bootstrap, run_liveness_loop, FailingResolver, SeedError, SeedResolver, StaticSeedResolver,
    TRANSPORT_CRATE,
};
pub use table::{
    signed_record, IngestOutcome, Liveness, PeerConfig, PeerEntry, PeerTable, DEFAULT_ANNOUNCE_MIN_INTERVAL,
    REP_BAD, REP_DUP, REP_GOOD, REP_INITIAL,
};

#[cfg(test)]
mod tests {
    #[test]
    fn crate_name_is_stable() {
        assert_eq!(super::CRATE_NAME, "discovery");
    }
}
