//! Peer and market discovery ingestion.
//!
//! A light node learns which markets exist and which peers serve a shard from
//! advertised metadata. This metadata is *unverified by nature* — it is a hint
//! about where to sync from, not a trusted fact — so discovery results are
//! surfaced with [`Verification::Unverified`] by the client. Discovery storage
//! is bounded: past capacity the oldest advertisements are evicted so a flood of
//! advertisements cannot grow memory without limit.

use serde::{Deserialize, Serialize};

use types::{MarketId, MarketType, ShardId};

use crate::cache::BoundedCache;

/// Default cap on retained market advertisements.
pub const DEFAULT_MARKET_LIMIT: usize = 4096;
/// Default cap on retained peer advertisements.
pub const DEFAULT_PEER_LIMIT: usize = 1024;

/// An advertised market plus the checkpoint metadata a peer claims for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketAdvertisement {
    /// The advertised market id.
    pub market_id: MarketId,
    /// The shard the market lives on.
    pub shard_id: ShardId,
    /// The market kind.
    pub market_type: MarketType,
    /// The highest checkpoint height the advertiser claims for this market.
    pub checkpoint_height: u64,
}

/// An advertised peer serving one or more markets on a shard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerAdvertisement {
    /// Opaque peer identity (e.g. a node-id hash prefix).
    pub peer_id: u64,
    /// The shard this peer serves.
    pub shard_id: ShardId,
    /// The highest checkpoint height this peer claims to have.
    pub tip_height: u64,
}

/// Bounded registry of discovered markets and peers.
#[derive(Debug, Clone)]
pub struct Discovery {
    markets: BoundedCache<u32, MarketAdvertisement>,
    peers: BoundedCache<u64, PeerAdvertisement>,
}

impl Discovery {
    /// A discovery registry with default bounds.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_MARKET_LIMIT, DEFAULT_PEER_LIMIT)
    }

    /// A discovery registry with explicit market / peer bounds.
    #[must_use]
    pub fn with_limits(market_limit: usize, peer_limit: usize) -> Self {
        Self {
            markets: BoundedCache::new(market_limit),
            peers: BoundedCache::new(peer_limit),
        }
    }

    /// Ingest a market advertisement. A repeat of a known market updates its
    /// metadata (e.g. a higher advertised checkpoint height).
    pub fn ingest_market(&mut self, ad: MarketAdvertisement) {
        self.markets.insert(ad.market_id.get(), ad);
    }

    /// Ingest a peer advertisement.
    pub fn ingest_peer(&mut self, ad: PeerAdvertisement) {
        self.peers.insert(ad.peer_id, ad);
    }

    /// Whether a market has been discovered.
    #[must_use]
    pub fn knows_market(&self, id: MarketId) -> bool {
        self.markets.contains(&id.get())
    }

    /// A discovered market's advertisement, if known.
    #[must_use]
    pub fn market(&self, id: MarketId) -> Option<&MarketAdvertisement> {
        self.markets.get(&id.get())
    }

    /// All discovered markets, in id order.
    #[must_use]
    pub fn markets(&self) -> Vec<MarketAdvertisement> {
        self.markets.values().cloned().collect()
    }

    /// All discovered peers.
    #[must_use]
    pub fn peers(&self) -> Vec<PeerAdvertisement> {
        self.peers.values().cloned().collect()
    }

    /// Number of discovered markets.
    #[must_use]
    pub fn market_count(&self) -> usize {
        self.markets.len()
    }

    /// Number of discovered peers.
    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }
}

impl Default for Discovery {
    fn default() -> Self {
        Self::new()
    }
}
