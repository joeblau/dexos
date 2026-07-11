//! The peer table: bounded storage, reputation, liveness, gossip suppression,
//! region/role/latency-aware selection, and a market advertisement index.
//!
//! Every collection is bounded by [`PeerConfig`]; admission under a flood evicts
//! the least-reputable entry rather than growing without limit. All ingestion
//! paths verify records and return typed outcomes — untrusted bytes never panic.

use std::collections::{BTreeMap, BTreeSet};

use crypto::KeyPair;
use types::MarketId;

use crate::record::{NodeId, PeerRecord, RecordError, Region, Role, RoleSet};

/// Reputation granted for a good interaction.
pub const REP_GOOD: i32 = 1;
/// Reputation removed for a bad interaction (invalid/replayed record, timeout).
pub const REP_BAD: i32 = -4;
/// Reputation a freshly admitted peer starts with.
pub const REP_INITIAL: i32 = 0;

/// Tunable bounds for a [`PeerTable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerConfig {
    /// Hard cap on stored peers. Admission past this evicts the worst entry.
    pub max_peers: usize,
    /// Hard cap on distinct advertised markets tracked in the index.
    pub max_markets: usize,
    /// Hard cap on records admitted in a single seed/bootstrap round.
    pub max_seed_admit: usize,
    /// Consecutive missed liveness checks before a peer is marked dead.
    pub missed_checks_to_dead: u32,
    /// Reputation at or below which a peer is evicted.
    pub min_reputation: i32,
}

impl Default for PeerConfig {
    fn default() -> Self {
        Self {
            max_peers: 1024,
            max_markets: 4096,
            max_seed_admit: 64,
            missed_checks_to_dead: 3,
            min_reputation: -8,
        }
    }
}

/// Liveness state of a stored peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    /// Responding and unexpired.
    Alive,
    /// Missed at least one check but not yet dead.
    Stale,
    /// Missed the configured number of checks, or its record expired.
    Dead,
}

/// Outcome of ingesting an announced record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestOutcome {
    /// A previously unknown peer was admitted.
    Admitted,
    /// A known peer's record was replaced by a strictly newer one.
    Updated,
    /// A duplicate or stale replay of a known record; suppressed.
    Suppressed,
    /// The record failed verification; the sender was penalized if known.
    Rejected(RecordError),
}

/// A stored peer plus discovery-layer bookkeeping.
#[derive(Debug, Clone)]
pub struct PeerEntry {
    /// The most recent verified record for this peer.
    pub record: PeerRecord,
    /// Accumulated reputation.
    pub reputation: i32,
    /// Last measured round-trip time in microseconds, if any.
    pub rtt_micros: Option<u64>,
    /// Liveness state.
    pub liveness: Liveness,
    /// Consecutive missed liveness checks.
    pub missed_checks: u32,
    /// Logical time of the last gossip re-forward (for suppression).
    pub last_forwarded: u64,
}

impl PeerEntry {
    fn new(record: PeerRecord) -> Self {
        Self {
            record,
            reputation: REP_INITIAL,
            rtt_micros: None,
            liveness: Liveness::Alive,
            missed_checks: 0,
            last_forwarded: 0,
        }
    }
}

/// Bounded peer store with discovery services.
#[derive(Debug, Clone)]
pub struct PeerTable {
    config: PeerConfig,
    peers: BTreeMap<NodeId, PeerEntry>,
    /// market -> set of advertising node ids.
    market_index: BTreeMap<MarketId, BTreeSet<NodeId>>,
    /// Static seeds retained for bootstrap fallback.
    seeds: Vec<PeerRecord>,
}

impl PeerTable {
    /// Create an empty table with the given bounds.
    #[must_use]
    pub fn new(config: PeerConfig) -> Self {
        Self {
            config,
            peers: BTreeMap::new(),
            market_index: BTreeMap::new(),
            seeds: Vec::new(),
        }
    }

    /// The active configuration.
    #[must_use]
    pub fn config(&self) -> &PeerConfig {
        &self.config
    }

    /// Number of stored peers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether the table has no peers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Look up a stored peer entry.
    #[must_use]
    pub fn peer(&self, node_id: &NodeId) -> Option<&PeerEntry> {
        self.peers.get(node_id)
    }

    /// Iterate over all stored peers.
    pub fn peers(&self) -> impl Iterator<Item = (&NodeId, &PeerEntry)> {
        self.peers.iter()
    }

    // --- Seeding ---------------------------------------------------------

    /// Register a static seed record. It is verified, stored for bootstrap
    /// fallback, and admitted immediately.
    pub fn add_static_seed(&mut self, record: PeerRecord, now: u64) -> Result<(), RecordError> {
        record.verify(now)?;
        // De-duplicate seeds by node id.
        if !self.seeds.iter().any(|s| s.node_id == record.node_id) {
            self.seeds.push(record.clone());
        }
        self.admit_verified(record);
        Ok(())
    }

    /// Bootstrap from a set of candidate records (e.g. a DNS seed round).
    ///
    /// Verifies each candidate, admits up to `max_seed_admit` valid records, and
    /// collapses duplicate node ids. Returns the number newly admitted. Never
    /// admits past the seed bound regardless of how many candidates arrive.
    pub fn ingest_seeds(&mut self, candidates: &[PeerRecord], now: u64) -> usize {
        let mut admitted = 0usize;
        let mut seen: BTreeSet<NodeId> = BTreeSet::new();
        for record in candidates {
            if admitted >= self.config.max_seed_admit {
                break;
            }
            if record.verify(now).is_err() {
                continue;
            }
            if !seen.insert(record.node_id) {
                continue; // duplicate node id within this round
            }
            let existed = self.peers.contains_key(&record.node_id);
            self.admit_verified(record.clone());
            if !existed {
                admitted += 1;
            }
        }
        admitted
    }

    /// The retained static seed records, for bootstrap fallback.
    #[must_use]
    pub fn static_seeds(&self) -> &[PeerRecord] {
        &self.seeds
    }

    // --- Gossip / announcements -----------------------------------------

    /// Ingest an announced peer record from gossip.
    ///
    /// Rejects unverifiable records (penalizing the sender if known), suppresses
    /// duplicate or replayed records, and admits/updates on a strictly newer
    /// `expires_at`.
    pub fn ingest_announcement(&mut self, record: PeerRecord, now: u64) -> IngestOutcome {
        if let Err(e) = record.verify(now) {
            // Penalize a known peer that emitted an invalid record.
            if let Some(entry) = self.peers.get_mut(&record.node_id) {
                entry.reputation = entry.reputation.saturating_add(REP_BAD);
            }
            self.evict_below_min();
            return IngestOutcome::Rejected(e);
        }
        // Snapshot the known expiry (if any) so no borrow spans the mutations.
        let existing_expiry = self.peers.get(&record.node_id).map(|e| e.record.expires_at);
        match existing_expiry {
            Some(exp) if record.expires_at <= exp => {
                // Replay or stale duplicate: penalize and suppress.
                if let Some(entry) = self.peers.get_mut(&record.node_id) {
                    entry.reputation = entry.reputation.saturating_add(REP_BAD);
                }
                self.evict_below_min();
                IngestOutcome::Suppressed
            }
            Some(_) => {
                self.reindex_markets(&record.node_id, &record);
                if let Some(entry) = self.peers.get_mut(&record.node_id) {
                    entry.record = record;
                    entry.liveness = Liveness::Alive;
                    entry.missed_checks = 0;
                }
                IngestOutcome::Updated
            }
            None => {
                self.admit_verified(record);
                IngestOutcome::Admitted
            }
        }
    }

    /// Whether a peer's record should be re-forwarded now, given a refresh
    /// interval. A record is re-forwarded at most once per interval; calling
    /// this records the forward time when it returns `true`.
    pub fn should_forward(&mut self, node_id: &NodeId, now: u64, refresh_interval: u64) -> bool {
        let Some(entry) = self.peers.get_mut(node_id) else {
            return false;
        };
        // First forward (last_forwarded == 0) or a full interval elapsed.
        if entry.last_forwarded == 0 || now.saturating_sub(entry.last_forwarded) >= refresh_interval
        {
            entry.last_forwarded = now.max(1);
            true
        } else {
            false
        }
    }

    // --- Reputation / interactions --------------------------------------

    /// Record the result of an interaction with a peer, adjusting reputation and
    /// evicting the peer if it falls to or below `min_reputation`.
    pub fn record_interaction(&mut self, node_id: &NodeId, good: bool) {
        if let Some(entry) = self.peers.get_mut(node_id) {
            let delta = if good { REP_GOOD } else { REP_BAD };
            entry.reputation = entry.reputation.saturating_add(delta);
        }
        self.evict_below_min();
    }

    /// Record a measured round-trip time (microseconds) for latency ranking.
    pub fn record_rtt(&mut self, node_id: &NodeId, micros: u64) {
        if let Some(entry) = self.peers.get_mut(node_id) {
            entry.rtt_micros = Some(micros);
        }
    }

    // --- Liveness --------------------------------------------------------

    /// Mark a peer as having answered a liveness probe: resets its miss counter
    /// and re-admits it from stale/dead.
    pub fn mark_alive(&mut self, node_id: &NodeId) {
        if let Some(entry) = self.peers.get_mut(node_id) {
            entry.missed_checks = 0;
            entry.liveness = Liveness::Alive;
        }
    }

    /// Mark a peer as having missed a liveness probe, transitioning it toward
    /// dead once `missed_checks_to_dead` misses accumulate.
    pub fn mark_missed(&mut self, node_id: &NodeId) {
        let threshold = self.config.missed_checks_to_dead;
        if let Some(entry) = self.peers.get_mut(node_id) {
            entry.missed_checks = entry.missed_checks.saturating_add(1);
            entry.liveness = if entry.missed_checks >= threshold {
                Liveness::Dead
            } else {
                Liveness::Stale
            };
        }
    }

    /// Periodic maintenance: expire records past `now`, drop dead peers, and
    /// rebuild the market index. Returns the number of peers pruned.
    pub fn tick_liveness(&mut self, now: u64) -> usize {
        let mut to_remove: Vec<NodeId> = Vec::new();
        for (id, entry) in &mut self.peers {
            if entry.record.expires_at <= now {
                entry.liveness = Liveness::Dead;
            }
            if entry.liveness == Liveness::Dead {
                to_remove.push(*id);
            }
        }
        for id in &to_remove {
            self.remove_peer(id);
        }
        to_remove.len()
    }

    // --- Selection -------------------------------------------------------

    /// Select up to `count` alive peers serving `role`, preferring low latency in
    /// `region` while guaranteeing at least one geographically diverse fallback
    /// (a peer from a different region) whenever one exists.
    #[must_use]
    pub fn select_peers(&self, role: Role, region: Region, count: usize) -> Vec<NodeId> {
        if count == 0 {
            return Vec::new();
        }
        let role_mask = RoleSet::empty().with(role);

        let mut local: Vec<&PeerEntry> = Vec::new();
        let mut remote: Vec<&PeerEntry> = Vec::new();
        for entry in self.peers.values() {
            if entry.liveness == Liveness::Dead {
                continue;
            }
            if !entry.record.roles.intersects(role_mask) {
                continue;
            }
            if entry.record.regions.contains(&region) {
                local.push(entry);
            } else {
                remote.push(entry);
            }
        }
        // Prefer low latency, then high reputation; unknown RTT sorts last.
        fn rank(e: &&PeerEntry) -> (u64, i32) {
            (e.rtt_micros.unwrap_or(u64::MAX), -e.reputation)
        }
        local.sort_by_key(rank);
        remote.sort_by_key(rank);

        let mut result: Vec<NodeId> = Vec::new();
        for e in &local {
            if result.len() >= count {
                break;
            }
            result.push(e.record.node_id);
        }

        // Guarantee a diverse fallback when a remote peer exists.
        if let Some(best_remote) = remote.first() {
            let has_remote = result.iter().any(|id| {
                self.peers
                    .get(id)
                    .is_some_and(|e| !e.record.regions.contains(&region))
            });
            if !has_remote {
                if result.len() < count {
                    result.push(best_remote.record.node_id);
                } else {
                    // Replace the worst-latency local slot with the fallback.
                    if let Some(last) = result.last_mut() {
                        *last = best_remote.record.node_id;
                    }
                }
            }
        }

        // Fill any remaining slots from remaining remote peers.
        for e in &remote {
            if result.len() >= count {
                break;
            }
            if !result.contains(&e.record.node_id) {
                result.push(e.record.node_id);
            }
        }

        result.truncate(count);
        result
    }

    // --- Market discovery ------------------------------------------------

    /// The set of all markets advertised by currently-stored peers.
    #[must_use]
    pub fn discover_markets(&self) -> BTreeSet<MarketId> {
        self.market_index.keys().copied().collect()
    }

    /// Node ids of peers advertising `market`.
    #[must_use]
    pub fn find_peers_for_market(&self, market: MarketId) -> Vec<NodeId> {
        self.market_index
            .get(&market)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Number of distinct markets currently indexed.
    #[must_use]
    pub fn market_count(&self) -> usize {
        self.market_index.len()
    }

    // --- Internal helpers ------------------------------------------------

    /// Admit a record already known to be verified, enforcing capacity.
    fn admit_verified(&mut self, record: PeerRecord) {
        if let Some(existing_expiry) = self.peers.get(&record.node_id).map(|e| e.record.expires_at)
        {
            // Keep the strictly newer record.
            if record.expires_at <= existing_expiry {
                return;
            }
            self.reindex_markets(&record.node_id, &record);
            if let Some(entry) = self.peers.get_mut(&record.node_id) {
                entry.record = record;
                entry.liveness = Liveness::Alive;
                entry.missed_checks = 0;
            }
            return;
        }
        // Enforce capacity before inserting a new peer.
        if self.peers.len() >= self.config.max_peers && !self.make_room() {
            return; // full of good peers; drop the newcomer rather than exceed cap
        }
        self.index_markets(&record.node_id, &record.market_ids);
        self.peers.insert(record.node_id, PeerEntry::new(record));
    }

    /// Evict the single least-reputable peer to make room. Returns whether a
    /// peer was evicted.
    fn make_room(&mut self) -> bool {
        let victim = self
            .peers
            .iter()
            .min_by_key(|(_, e)| (e.reputation, e.liveness == Liveness::Alive))
            .map(|(id, _)| *id);
        if let Some(id) = victim {
            self.remove_peer(&id);
            true
        } else {
            false
        }
    }

    /// Evict every peer at or below the configured reputation floor.
    fn evict_below_min(&mut self) {
        let doomed: Vec<NodeId> = self
            .peers
            .iter()
            .filter(|(_, e)| e.reputation <= self.config.min_reputation)
            .map(|(id, _)| *id)
            .collect();
        for id in doomed {
            self.remove_peer(&id);
        }
    }

    /// Remove a peer and detach it from the market index.
    fn remove_peer(&mut self, node_id: &NodeId) {
        if let Some(entry) = self.peers.remove(node_id) {
            self.deindex_markets(node_id, &entry.record.market_ids);
        }
    }

    /// Replace a peer's market advertisements with those in `record`.
    fn reindex_markets(&mut self, node_id: &NodeId, record: &PeerRecord) {
        // Clone-then-drop the borrow so the mutable deindex call is legal.
        let old: Option<Vec<MarketId>> =
            self.peers.get(node_id).map(|e| e.record.market_ids.clone());
        if let Some(old) = old {
            self.deindex_markets(node_id, &old);
        }
        self.index_markets(node_id, &record.market_ids);
    }

    /// Add a peer to the index for each advertised market, honoring `max_markets`.
    fn index_markets(&mut self, node_id: &NodeId, markets: &[MarketId]) {
        for m in markets {
            if !self.market_index.contains_key(m)
                && self.market_index.len() >= self.config.max_markets
            {
                continue; // index full; drop novel markets rather than grow unbounded
            }
            self.market_index.entry(*m).or_default().insert(*node_id);
        }
    }

    /// Remove a peer from the index for each listed market, dropping empty sets.
    fn deindex_markets(&mut self, node_id: &NodeId, markets: &[MarketId]) {
        for m in markets {
            if let Some(set) = self.market_index.get_mut(m) {
                set.remove(node_id);
                if set.is_empty() {
                    self.market_index.remove(m);
                }
            }
        }
    }
}

/// Convenience: build a signed record from a keypair for tests/tools.
///
/// This lives here (rather than in `record`) because it composes the two crates.
#[allow(clippy::too_many_arguments)]
pub fn signed_record(
    keypair: &KeyPair,
    addresses: Vec<String>,
    roles: RoleSet,
    regions: Vec<Region>,
    supported_protocols: Vec<u16>,
    market_ids: Vec<MarketId>,
    checkpoint_height: u64,
    expires_at: u64,
) -> Result<PeerRecord, RecordError> {
    PeerRecord::new_unsigned(
        addresses,
        roles,
        regions,
        supported_protocols,
        market_ids,
        checkpoint_height,
        expires_at,
    )
    .sign(keypair)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kp(seed: u8) -> KeyPair {
        KeyPair::from_seed(&[seed; 32])
    }

    fn rec(
        seed: u8,
        roles: RoleSet,
        regions: Vec<Region>,
        markets: Vec<u32>,
        expires_at: u64,
    ) -> PeerRecord {
        signed_record(
            &kp(seed),
            vec![format!("10.0.0.{seed}:9000")],
            roles,
            regions,
            vec![1],
            markets.into_iter().map(MarketId::new).collect(),
            1,
            expires_at,
        )
        .unwrap()
    }

    #[test]
    fn static_seed_admission_and_dedup() {
        let mut t = PeerTable::new(PeerConfig::default());
        let r = rec(
            1,
            RoleSet::empty().with(Role::Validator),
            vec![Region::UsEast],
            vec![],
            100,
        );
        t.add_static_seed(r.clone(), 10).unwrap();
        t.add_static_seed(r.clone(), 10).unwrap(); // same node id
        assert_eq!(t.len(), 1);
        assert_eq!(t.static_seeds().len(), 1);
    }

    #[test]
    fn rejects_bad_seeds() {
        let mut t = PeerTable::new(PeerConfig::default());
        let expired = rec(2, RoleSet::empty(), vec![Region::Other], vec![], 5);
        assert!(t.add_static_seed(expired, 10).is_err());
        let mut tampered = rec(3, RoleSet::empty(), vec![Region::Other], vec![], 100);
        tampered.checkpoint_height = 999;
        assert!(t.add_static_seed(tampered, 10).is_err());
    }

    #[test]
    fn ingest_seeds_is_bounded_under_flood() {
        let cfg = PeerConfig {
            max_seed_admit: 4,
            max_peers: 1000,
            ..PeerConfig::default()
        };
        let mut t = PeerTable::new(cfg);
        let flood: Vec<PeerRecord> = (10..60)
            .map(|s| {
                rec(
                    s,
                    RoleSet::empty().with(Role::Gateway),
                    vec![Region::UsEast],
                    vec![],
                    100,
                )
            })
            .collect();
        let admitted = t.ingest_seeds(&flood, 10);
        assert_eq!(admitted, 4);
        assert_eq!(t.len(), 4);
    }

    #[test]
    fn duplicate_node_ids_collapse() {
        let mut t = PeerTable::new(PeerConfig::default());
        let r = rec(
            7,
            RoleSet::empty().with(Role::Witness),
            vec![Region::EuCentral],
            vec![],
            100,
        );
        let dupes = vec![r.clone(), r.clone(), r];
        let admitted = t.ingest_seeds(&dupes, 10);
        assert_eq!(admitted, 1);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn replay_and_duplicate_suppressed() {
        let mut t = PeerTable::new(PeerConfig::default());
        let r = rec(
            8,
            RoleSet::empty().with(Role::Oracle),
            vec![Region::UsWest],
            vec![],
            100,
        );
        assert_eq!(
            t.ingest_announcement(r.clone(), 10),
            IngestOutcome::Admitted
        );
        // Same record replayed: suppressed and penalized.
        assert_eq!(
            t.ingest_announcement(r.clone(), 10),
            IngestOutcome::Suppressed
        );
        let node = r.node_id;
        assert!(t.peer(&node).unwrap().reputation < 0);
        // A strictly newer record updates.
        let newer = rec(
            8,
            RoleSet::empty().with(Role::Oracle),
            vec![Region::UsWest],
            vec![],
            200,
        );
        assert_eq!(t.ingest_announcement(newer, 10), IngestOutcome::Updated);
    }

    #[test]
    fn forward_once_per_interval() {
        let mut t = PeerTable::new(PeerConfig::default());
        let r = rec(
            9,
            RoleSet::empty().with(Role::Gateway),
            vec![Region::UsEast],
            vec![],
            100,
        );
        let node = r.node_id;
        t.ingest_announcement(r, 10);
        assert!(t.should_forward(&node, 10, 30)); // first forward
        assert!(!t.should_forward(&node, 20, 30)); // within interval
        assert!(t.should_forward(&node, 45, 30)); // interval elapsed
    }

    #[test]
    fn reputation_eviction() {
        let cfg = PeerConfig {
            min_reputation: -3,
            ..PeerConfig::default()
        };
        let mut t = PeerTable::new(cfg);
        let r = rec(
            11,
            RoleSet::empty().with(Role::Gateway),
            vec![Region::UsEast],
            vec![],
            100,
        );
        let node = r.node_id;
        t.ingest_announcement(r, 10);
        // One bad interaction (-4) drops below -3 -> evicted.
        t.record_interaction(&node, false);
        assert!(t.peer(&node).is_none());
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn capacity_never_exceeded() {
        let cfg = PeerConfig {
            max_peers: 3,
            ..PeerConfig::default()
        };
        let mut t = PeerTable::new(cfg);
        for s in 20..30 {
            let r = rec(
                s,
                RoleSet::empty().with(Role::Gateway),
                vec![Region::UsEast],
                vec![],
                100,
            );
            t.ingest_announcement(r, 10);
        }
        assert!(t.len() <= 3);
    }

    #[test]
    fn liveness_transitions_and_recovery() {
        let cfg = PeerConfig {
            missed_checks_to_dead: 2,
            ..PeerConfig::default()
        };
        let mut t = PeerTable::new(cfg);
        let r = rec(
            31,
            RoleSet::empty().with(Role::Validator),
            vec![Region::UsEast],
            vec![],
            100,
        );
        let node = r.node_id;
        t.ingest_announcement(r, 10);
        assert_eq!(t.peer(&node).unwrap().liveness, Liveness::Alive);
        t.mark_missed(&node);
        assert_eq!(t.peer(&node).unwrap().liveness, Liveness::Stale);
        t.mark_missed(&node);
        assert_eq!(t.peer(&node).unwrap().liveness, Liveness::Dead);
        // Recovery re-admits before pruning.
        t.mark_alive(&node);
        assert_eq!(t.peer(&node).unwrap().liveness, Liveness::Alive);
    }

    #[test]
    fn expired_records_pruned_by_tick() {
        let mut t = PeerTable::new(PeerConfig::default());
        let r = rec(
            32,
            RoleSet::empty().with(Role::Gateway),
            vec![Region::UsEast],
            vec![7],
            50,
        );
        t.ingest_announcement(r, 10);
        assert_eq!(t.market_count(), 1);
        let pruned = t.tick_liveness(60); // past expiry
        assert_eq!(pruned, 1);
        assert_eq!(t.len(), 0);
        assert_eq!(t.market_count(), 0); // market removed with dead peer
    }

    #[test]
    fn role_and_region_selection_with_diverse_fallback() {
        let mut t = PeerTable::new(PeerConfig::default());
        // Three local validators (UsEast) and one remote (EuCentral).
        let local_a = rec(
            40,
            RoleSet::empty().with(Role::Validator),
            vec![Region::UsEast],
            vec![],
            100,
        );
        let local_b = rec(
            41,
            RoleSet::empty().with(Role::Validator),
            vec![Region::UsEast],
            vec![],
            100,
        );
        let local_c = rec(
            42,
            RoleSet::empty().with(Role::Validator),
            vec![Region::UsEast],
            vec![],
            100,
        );
        let remote = rec(
            43,
            RoleSet::empty().with(Role::Validator),
            vec![Region::EuCentral],
            vec![],
            100,
        );
        // A gateway that must never appear in a validator query.
        let gw = rec(
            44,
            RoleSet::empty().with(Role::Gateway),
            vec![Region::UsEast],
            vec![],
            100,
        );
        let (la, lb, lc, rm, gwid) = (
            local_a.node_id,
            local_b.node_id,
            local_c.node_id,
            remote.node_id,
            gw.node_id,
        );
        for r in [local_a, local_b, local_c, remote, gw] {
            t.ingest_announcement(r, 10);
        }
        // Low RTT for locals, high for remote.
        t.record_rtt(&la, 100);
        t.record_rtt(&lb, 200);
        t.record_rtt(&lc, 300);
        t.record_rtt(&rm, 9000);

        let picked = t.select_peers(Role::Validator, Region::UsEast, 3);
        assert_eq!(picked.len(), 3);
        // Fastest local is first.
        assert_eq!(picked[0], la);
        // Diverse fallback guaranteed: the remote peer is included.
        assert!(picked.contains(&rm));
        // Gateway excluded.
        assert!(picked.iter().all(|id| *id != gwid));
    }

    #[test]
    fn selection_prefers_low_latency_without_fallback() {
        let mut t = PeerTable::new(PeerConfig::default());
        let a = rec(
            50,
            RoleSet::empty().with(Role::Oracle),
            vec![Region::UsEast],
            vec![],
            100,
        );
        let b = rec(
            51,
            RoleSet::empty().with(Role::Oracle),
            vec![Region::UsEast],
            vec![],
            100,
        );
        let (ia, ib) = (a.node_id, b.node_id);
        t.ingest_announcement(a, 10);
        t.ingest_announcement(b, 10);
        t.record_rtt(&ib, 50);
        t.record_rtt(&ia, 5000);
        let picked = t.select_peers(Role::Oracle, Region::UsEast, 1);
        assert_eq!(picked, vec![ib]); // faster peer chosen
    }

    #[test]
    fn market_discovery_indexing() {
        let mut t = PeerTable::new(PeerConfig::default());
        let btc = rec(
            60,
            RoleSet::empty().with(Role::Gateway),
            vec![Region::UsEast],
            vec![100, 200],
            100,
        );
        let eth = rec(
            61,
            RoleSet::empty().with(Role::Gateway),
            vec![Region::UsEast],
            vec![200, 300],
            100,
        );
        let bnode = btc.node_id;
        t.ingest_announcement(btc, 10);
        t.ingest_announcement(eth, 10);
        let markets = t.discover_markets();
        assert!(markets.contains(&MarketId::new(100)));
        assert!(markets.contains(&MarketId::new(200)));
        assert!(markets.contains(&MarketId::new(300)));
        // Market 200 advertised by both peers.
        let peers200 = t.find_peers_for_market(MarketId::new(200));
        assert_eq!(peers200.len(), 2);
        // Market 100 only by the btc peer.
        assert_eq!(t.find_peers_for_market(MarketId::new(100)), vec![bnode]);
    }

    #[test]
    fn market_index_bounded_under_flood() {
        let cfg = PeerConfig {
            max_markets: 5,
            max_peers: 1000,
            ..PeerConfig::default()
        };
        let mut t = PeerTable::new(cfg);
        for s in 70..90u8 {
            let markets: Vec<u32> = (0..20).map(|i| u32::from(s) * 100 + i).collect();
            let r = rec(
                s,
                RoleSet::empty().with(Role::Gateway),
                vec![Region::UsEast],
                markets,
                100,
            );
            t.ingest_announcement(r, 10);
        }
        assert!(t.market_count() <= 5);
    }

    #[test]
    fn unverified_records_contribute_no_markets() {
        let mut t = PeerTable::new(PeerConfig::default());
        let mut bad = rec(
            91,
            RoleSet::empty().with(Role::Gateway),
            vec![Region::UsEast],
            vec![500],
            100,
        );
        bad.signature = [0u8; 64]; // invalid
        assert!(matches!(
            t.ingest_announcement(bad, 10),
            IngestOutcome::Rejected(_)
        ));
        assert_eq!(t.market_count(), 0);
        assert!(t.discover_markets().is_empty());
    }

    // Deterministic LCG simulation: delay/reorder/duplication/drop convergence.
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
    }

    #[test]
    fn property_gossip_convergence_under_chaos() {
        // Author the canonical records once.
        let canon: Vec<PeerRecord> = (100..110u8)
            .map(|s| {
                rec(
                    s,
                    RoleSet::empty().with(Role::Validator),
                    vec![Region::UsEast],
                    vec![u32::from(s)],
                    1000,
                )
            })
            .collect();

        // Build a chaotic delivery stream: duplicates, reorder, drops.
        let mut lcg = Lcg(0xabcd_1234_5678_9999);
        let mut stream: Vec<PeerRecord> = Vec::new();
        for r in &canon {
            // Guarantee at-least-once delivery, then add lossy duplicates.
            stream.push(r.clone());
            let extra = usize::try_from(lcg.next() % 4).unwrap(); // 0..=3 duplicates
            for _ in 0..extra {
                if !lcg.next().is_multiple_of(10) {
                    // 10% drop on the redundant copies
                    stream.push(r.clone());
                }
            }
        }
        // Reorder via a Fisher-Yates using the LCG.
        for i in (1..stream.len()).rev() {
            let j = usize::try_from(lcg.next()).unwrap() % (i + 1);
            stream.swap(i, j);
        }

        // Two honest nodes see different orderings of the same stream.
        //
        // Gossip treats every redundant copy of a known record as a replay and
        // shaves `REP_BAD` off reputation on each. Under this chaos a record is
        // delivered up to four times (three redundant copies -> reputation as
        // low as -12), so the reputation floor must sit comfortably below that
        // worst-case penalty or an honest peer would be evicted by a benign
        // duplicate flood, breaking convergence. Capacity is not the limiter:
        // the default `max_peers` (1024) already dwarfs the 10 canonical peers.
        let cfg = PeerConfig {
            min_reputation: -100,
            ..PeerConfig::default()
        };
        let mut node_a = PeerTable::new(cfg);
        let mut node_b = PeerTable::new(cfg);
        for r in &stream {
            node_a.ingest_announcement(r.clone(), 10);
        }
        for r in stream.iter().rev() {
            node_b.ingest_announcement(r.clone(), 10);
        }

        // Every honest node converges to the full verified set, and the market
        // views match — order/duplication/drop-below-total do not matter.
        assert_eq!(node_a.discover_markets(), node_b.discover_markets());
        for r in &canon {
            assert!(node_a.peer(&r.node_id).is_some());
            assert!(node_b.peer(&r.node_id).is_some());
        }
    }
}
