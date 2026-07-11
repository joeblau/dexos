//! The composed light-node client: multi-shard checkpoint sync, proof-backed
//! reads, market discovery, bounded caches, and refusal of write operations.
//!
//! [`LightClient`] wires the pieces together. It follows one or more shards
//! (each a [`ShardSync`]), routes ingested checkpoints to the right shard,
//! caches recent verified checkpoints and account responses under hard bounds,
//! and answers read RPCs with a [`Verification`]-tagged payload. Every write /
//! order-entry method returns [`LightClientError::Unsupported`]; nothing is
//! executed or persisted as a canonical command log.

use std::collections::BTreeMap;

use consensus::Checkpoint;
use crypto::ValidatorSet;
use types::{AccountId, Hash, MarketId, ShardId};

use crate::discovery::{Discovery, MarketAdvertisement, PeerAdvertisement};
use crate::error::{LightClientError, UnsupportedOp};
use crate::proofs::{verify_account_value, verify_market_value};
use crate::rpc::{RpcRequest, RpcResponse};
use crate::sync::{IngestOutcome, ShardSync, VerifiedTip};
use crate::verification::VerifiedValue;
use crate::BoundedCache;

/// Default account-response cache capacity.
pub const DEFAULT_ACCOUNT_CACHE: usize = 4096;
/// Default recent-checkpoint cache capacity (per client).
pub const DEFAULT_CHECKPOINT_CACHE: usize = 512;

/// Light-node runtime configuration.
///
/// `light` selects the light runtime: when set, the node follows checkpoints
/// and serves proof-backed reads only — it spawns no consensus / execution /
/// journal subsystems and persists no command log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LightConfig {
    /// Whether the light runtime is selected.
    pub light: bool,
    /// Account-response cache capacity.
    pub account_cache_capacity: usize,
    /// Recent-checkpoint cache capacity.
    pub checkpoint_cache_capacity: usize,
}

impl Default for LightConfig {
    fn default() -> Self {
        Self {
            light: true,
            account_cache_capacity: DEFAULT_ACCOUNT_CACHE,
            checkpoint_cache_capacity: DEFAULT_CHECKPOINT_CACHE,
        }
    }
}

/// A composed light client over one or more shards.
#[derive(Debug, Clone)]
pub struct LightClient {
    config: LightConfig,
    shards: BTreeMap<u16, ShardSync>,
    discovery: Discovery,
    /// `(shard, account) -> last verified/looked-up account leaf`.
    account_cache: BoundedCache<(u16, u32), VerifiedValue<Vec<u8>>>,
    /// `(shard, height) -> recent verified checkpoint`.
    checkpoint_cache: BoundedCache<(u16, u64), Checkpoint>,
}

impl LightClient {
    /// A light client with the given configuration.
    #[must_use]
    pub fn new(config: LightConfig) -> Self {
        Self {
            config,
            shards: BTreeMap::new(),
            discovery: Discovery::new(),
            account_cache: BoundedCache::new(config.account_cache_capacity),
            checkpoint_cache: BoundedCache::new(config.checkpoint_cache_capacity),
        }
    }

    /// A light client with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(LightConfig::default())
    }

    /// Whether the light runtime is selected.
    #[must_use]
    pub fn is_light(&self) -> bool {
        self.config.light
    }

    /// A light node never persists the full command log.
    #[must_use]
    pub fn persists_command_log(&self) -> bool {
        false
    }

    /// A light node never spawns consensus / execution / journal subsystems.
    #[must_use]
    pub fn spawns_consensus(&self) -> bool {
        false
    }

    /// The active configuration.
    #[must_use]
    pub fn config(&self) -> LightConfig {
        self.config
    }

    // ---- shard management -------------------------------------------------

    /// Begin following `shard_id`, anchored at `trusted_root`. Replaces any
    /// existing sync for that shard.
    pub fn follow_shard(&mut self, shard_id: ShardId, trusted_root: Hash) {
        self.shards
            .insert(shard_id.get(), ShardSync::new(shard_id, trusted_root));
    }

    /// Register the validator set trusted for `epoch` on `shard_id`.
    pub fn register_validator_set(
        &mut self,
        shard_id: ShardId,
        epoch: u64,
        set: ValidatorSet,
    ) -> Result<(), LightClientError> {
        self.shard_mut(shard_id)?.register_validator_set(epoch, set);
        Ok(())
    }

    /// Access a followed shard's sync state.
    #[must_use]
    pub fn shard(&self, shard_id: ShardId) -> Option<&ShardSync> {
        self.shards.get(&shard_id.get())
    }

    /// The verified tip for a shard, if any.
    #[must_use]
    pub fn verified_tip(&self, shard_id: ShardId) -> Option<VerifiedTip> {
        self.shards
            .get(&shard_id.get())
            .and_then(ShardSync::verified_tip)
    }

    fn shard_mut(&mut self, shard_id: ShardId) -> Result<&mut ShardSync, LightClientError> {
        self.shards
            .get_mut(&shard_id.get())
            .ok_or(LightClientError::ShardMismatch {
                expected: shard_id.get(),
                got: shard_id.get(),
            })
    }

    // ---- ingestion --------------------------------------------------------

    /// Ingest a checkpoint, routing it to its shard. On advance, caches the
    /// checkpoint and invalidates now-stale account-cache entries.
    pub fn ingest_checkpoint(
        &mut self,
        checkpoint: Checkpoint,
    ) -> Result<IngestOutcome, LightClientError> {
        let shard = checkpoint.shard_id.get();
        let cp_for_cache = checkpoint.clone();
        let outcome = self.shard_mut(checkpoint.shard_id)?.ingest(checkpoint)?;
        if let IngestOutcome::Advanced { height, .. } = outcome {
            self.checkpoint_cache.insert((shard, height), cp_for_cache);
            // Drop account-cache entries for this shard that are no longer at the
            // new verified height (they would now be stale).
            self.account_cache
                .retain(|k, v| k.0 != shard || v.verification().height() == Some(height));
        }
        Ok(outcome)
    }

    /// Ingest a market advertisement (peer/market discovery).
    pub fn ingest_market_advertisement(&mut self, ad: MarketAdvertisement) {
        self.discovery.ingest_market(ad);
    }

    /// Ingest a peer advertisement.
    pub fn ingest_peer_advertisement(&mut self, ad: PeerAdvertisement) {
        self.discovery.ingest_peer(ad);
    }

    /// The discovery registry.
    #[must_use]
    pub fn discovery(&self) -> &Discovery {
        &self.discovery
    }

    // ---- caches -----------------------------------------------------------

    /// A recently verified checkpoint, if cached.
    #[must_use]
    pub fn cached_checkpoint(&self, shard_id: ShardId, height: u64) -> Option<&Checkpoint> {
        self.checkpoint_cache.get(&(shard_id.get(), height))
    }

    /// A cached account response, if present.
    #[must_use]
    pub fn cached_account(
        &self,
        shard_id: ShardId,
        id: AccountId,
    ) -> Option<&VerifiedValue<Vec<u8>>> {
        self.account_cache.get(&(shard_id.get(), id.get()))
    }

    /// Recent-checkpoint cache size.
    #[must_use]
    pub fn checkpoint_cache_len(&self) -> usize {
        self.checkpoint_cache.len()
    }

    /// Account-response cache size.
    #[must_use]
    pub fn account_cache_len(&self) -> usize {
        self.account_cache.len()
    }

    // ---- read queries -----------------------------------------------------

    /// The highest verified checkpoint for a shard, tagged verified.
    pub fn get_latest_checkpoint(
        &self,
        shard_id: ShardId,
    ) -> Result<VerifiedValue<VerifiedTip>, LightClientError> {
        let sync = self
            .shards
            .get(&shard_id.get())
            .ok_or(LightClientError::NoVerifiedCheckpoint)?;
        let tip = sync
            .verified_tip()
            .ok_or(LightClientError::NoVerifiedCheckpoint)?;
        Ok(VerifiedValue::verified(tip, tip.height))
    }

    /// Verify an account leaf + proof, returning a status-tagged value. Also
    /// caches the response. Errors only if the shard is not followed.
    pub fn get_account_proof(
        &mut self,
        shard_id: ShardId,
        id: AccountId,
        leaf_bytes: &[u8],
        proof: &[Hash],
    ) -> Result<VerifiedValue<Vec<u8>>, LightClientError> {
        let sync = self
            .shards
            .get(&shard_id.get())
            .ok_or(LightClientError::NoVerifiedCheckpoint)?;
        let value = verify_account_value(sync, id, leaf_bytes, proof);
        self.account_cache
            .insert((shard_id.get(), id.get()), value.clone());
        Ok(value)
    }

    /// Verify a market leaf + proof, returning a status-tagged value.
    pub fn get_market_proof(
        &self,
        shard_id: ShardId,
        id: MarketId,
        leaf_bytes: &[u8],
        proof: &[Hash],
    ) -> Result<VerifiedValue<Vec<u8>>, LightClientError> {
        let sync = self
            .shards
            .get(&shard_id.get())
            .ok_or(LightClientError::NoVerifiedCheckpoint)?;
        Ok(verify_market_value(sync, id, leaf_bytes, proof))
    }

    /// The discovered markets, tagged unverified (advertisement metadata is a
    /// hint, never trusted).
    #[must_use]
    pub fn get_discovered_markets(&self) -> VerifiedValue<Vec<MarketAdvertisement>> {
        VerifiedValue::unverified(self.discovery.markets())
    }

    // ---- write refusals ---------------------------------------------------

    /// Refuse a write / control operation with a typed reason.
    pub fn refuse(&self, op: UnsupportedOp) -> Result<(), LightClientError> {
        Err(LightClientError::Unsupported(op))
    }

    /// Order entry is not supported in light mode.
    pub fn submit_order(&self) -> Result<(), LightClientError> {
        self.refuse(UnsupportedOp::SubmitOrder)
    }

    /// Order cancellation is not supported in light mode.
    pub fn cancel_order(&self) -> Result<(), LightClientError> {
        self.refuse(UnsupportedOp::CancelOrder)
    }

    /// Deposits are not supported in light mode.
    pub fn deposit(&self) -> Result<(), LightClientError> {
        self.refuse(UnsupportedOp::Deposit)
    }

    /// Withdrawals are not supported in light mode.
    pub fn withdraw(&self) -> Result<(), LightClientError> {
        self.refuse(UnsupportedOp::Withdraw)
    }

    // ---- RPC dispatch -----------------------------------------------------

    /// Dispatch an [`RpcRequest`]. Read methods return a status-tagged
    /// [`RpcResponse`]; write methods return [`LightClientError::Unsupported`].
    pub fn handle(&mut self, request: RpcRequest) -> Result<RpcResponse, LightClientError> {
        if let Some(op) = request.unsupported_op() {
            return Err(LightClientError::Unsupported(op));
        }
        match request {
            RpcRequest::GetLatestCheckpoint { shard } => {
                let tip = self.get_latest_checkpoint(ShardId::new(shard))?;
                Ok(RpcResponse::LatestCheckpoint(tip))
            }
            RpcRequest::GetAccountProof {
                shard,
                account,
                leaf,
                proof,
            } => {
                let v = self.get_account_proof(
                    ShardId::new(shard),
                    AccountId::new(account),
                    &leaf,
                    &proof,
                )?;
                Ok(RpcResponse::AccountProof(v))
            }
            RpcRequest::GetMarketProof {
                shard,
                market,
                leaf,
                proof,
            } => {
                let v = self.get_market_proof(
                    ShardId::new(shard),
                    MarketId::new(market),
                    &leaf,
                    &proof,
                )?;
                Ok(RpcResponse::MarketProof(v))
            }
            RpcRequest::GetDiscoveredMarkets => Ok(RpcResponse::DiscoveredMarkets(
                self.get_discovered_markets(),
            )),
            // Write variants handled above.
            RpcRequest::SubmitOrder
            | RpcRequest::CancelOrder
            | RpcRequest::AmendOrder
            | RpcRequest::Deposit
            | RpcRequest::Withdraw => {
                Err(LightClientError::Unsupported(UnsupportedOp::SubmitOrder))
            }
        }
    }
}
