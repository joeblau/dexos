//! Bootstrap seeding (static + DNS) and the async liveness service.
//!
//! [`SeedResolver`] abstracts a seed source (DNS TXT records, a hardcoded list,
//! a mock in tests). [`bootstrap`] resolves candidates, admits the verified ones
//! within the configured bound, and falls back to retained static seeds if the
//! resolver errors — a resolver failure is never fatal.
//!
//! [`run_liveness_loop`] is a small `tokio` driver that periodically prunes
//! expired/dead peers; it is bounded by a tick budget so tests terminate.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;

use crate::record::PeerRecord;
use crate::table::PeerTable;

/// The transport crate this discovery layer feeds peers into.
pub const TRANSPORT_CRATE: &str = network::CRATE_NAME;

/// A seed source failure (DNS lookup error, malformed response, etc.).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SeedError {
    /// The underlying resolver could not be reached or failed.
    #[error("seed resolver unavailable")]
    Unavailable,
    /// The resolver returned data that could not be parsed into records.
    #[error("seed response malformed")]
    Malformed,
}

/// A source of candidate peer records for bootstrap.
///
/// Implementations are synchronous so the discovery core stays deterministic and
/// trivially testable; real DNS/HTTP resolvers can wrap async lookups and block
/// on their own runtime, or be adapted at the call site.
pub trait SeedResolver {
    /// Resolve the current candidate seed records.
    fn resolve(&self) -> Result<Vec<PeerRecord>, SeedError>;
}

/// A fixed in-memory resolver (hardcoded seeds or a test fixture).
#[derive(Debug, Clone, Default)]
pub struct StaticSeedResolver {
    records: Vec<PeerRecord>,
}

impl StaticSeedResolver {
    /// Build from a list of records.
    #[must_use]
    pub fn new(records: Vec<PeerRecord>) -> Self {
        Self { records }
    }
}

impl SeedResolver for StaticSeedResolver {
    fn resolve(&self) -> Result<Vec<PeerRecord>, SeedError> {
        Ok(self.records.clone())
    }
}

/// A resolver that always fails, for exercising the fallback path.
#[derive(Debug, Clone, Copy, Default)]
pub struct FailingResolver;

impl SeedResolver for FailingResolver {
    fn resolve(&self) -> Result<Vec<PeerRecord>, SeedError> {
        Err(SeedError::Unavailable)
    }
}

/// Bootstrap `table` from `resolver` at time `now`.
///
/// On success, verified candidates are admitted up to `max_seed_admit`. On
/// resolver failure, the table's retained static seeds are re-admitted instead.
/// Returns the number of peers admitted in this round.
pub fn bootstrap<R: SeedResolver>(table: &mut PeerTable, resolver: &R, now: u64) -> usize {
    match resolver.resolve() {
        Ok(candidates) => table.ingest_seeds(&candidates, now),
        Err(_) => {
            // Fall back to previously retained static seeds; cloning detaches the
            // borrow so we can feed them back through the bounded admission path.
            let fallback = table.static_seeds().to_vec();
            table.ingest_seeds(&fallback, now)
        }
    }
}

/// Run periodic liveness maintenance on a shared table.
///
/// Ticks every `period`, invoking `now_fn` for the current unix time and pruning
/// expired/dead peers. Stops after `max_ticks` iterations (use `u64::MAX` for an
/// effectively unbounded service). Returns the total number of peers pruned.
pub async fn run_liveness_loop<F>(
    table: Arc<Mutex<PeerTable>>,
    period: Duration,
    now_fn: F,
    max_ticks: u64,
) -> usize
where
    F: Fn() -> u64 + Send,
{
    let mut ticker = tokio::time::interval(period);
    let mut pruned_total = 0usize;
    let mut ticks = 0u64;
    while ticks < max_ticks {
        ticker.tick().await;
        let now = now_fn();
        {
            let mut guard = table.lock().await;
            pruned_total += guard.tick_liveness(now);
        }
        ticks += 1;
    }
    pruned_total
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{Region, Role, RoleSet};
    use crate::table::{signed_record, PeerConfig};
    use crypto::KeyPair;
    use types::MarketId;

    fn rec(seed: u8, markets: Vec<u32>, expires_at: u64) -> PeerRecord {
        signed_record(
            &KeyPair::from_seed(&[seed; 32]),
            vec![format!("10.0.0.{seed}:9000")],
            RoleSet::empty().with(Role::Validator),
            vec![Region::UsEast],
            vec![1],
            markets.into_iter().map(MarketId::new).collect(),
            1,
            expires_at,
        )
        .unwrap()
    }

    #[test]
    fn bootstrap_admits_verified_dns_candidates() {
        let mut t = PeerTable::new(PeerConfig::default());
        let resolver = StaticSeedResolver::new(vec![rec(1, vec![], 100), rec(2, vec![], 100)]);
        let admitted = bootstrap(&mut t, &resolver, 10);
        assert_eq!(admitted, 2);
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn bootstrap_falls_back_to_static_seeds_on_failure() {
        let mut t = PeerTable::new(PeerConfig::default());
        // Register static seeds first.
        t.add_static_seed(rec(3, vec![], 100), 10).unwrap();
        t.add_static_seed(rec(4, vec![], 100), 10).unwrap();
        // Simulate resolver failure: table still has its seed-backed peer set.
        let admitted = bootstrap(&mut t, &FailingResolver, 10);
        assert_eq!(admitted, 0); // already present, no new admissions
        assert_eq!(t.len(), 2); // fallback kept the set non-empty, no error
    }

    #[test]
    fn seeds_only_node_has_non_empty_verified_set() {
        // Deterministic-simulation flavor: a node with only seeds bootstraps a set.
        let mut t = PeerTable::new(PeerConfig::default());
        let resolver = StaticSeedResolver::new(vec![rec(5, vec![7], 100), rec(6, vec![8], 100)]);
        bootstrap(&mut t, &resolver, 10);
        assert!(!t.is_empty());
        assert!(!t.discover_markets().is_empty());
        // Every stored peer verifies at the bootstrap time.
        for (_, entry) in t.peers() {
            entry.record.verify(10).unwrap();
        }
    }

    #[tokio::test]
    async fn liveness_loop_prunes_expired() {
        let mut table = PeerTable::new(PeerConfig::default());
        // One peer expiring at 50, one at 500.
        table.ingest_seeds(&[rec(7, vec![], 50), rec(8, vec![], 500)], 10);
        assert_eq!(table.len(), 2);
        let shared = Arc::new(Mutex::new(table));

        // Clock advances past the first peer's expiry.
        let pruned = run_liveness_loop(
            Arc::clone(&shared),
            Duration::from_millis(1),
            || 100, // now = 100: peer 7 (exp 50) is dead, peer 8 (exp 500) lives
            2,
        )
        .await;

        assert_eq!(pruned, 1);
        let guard = shared.lock().await;
        assert_eq!(guard.len(), 1);
    }

    #[test]
    fn transport_crate_wired() {
        assert_eq!(TRANSPORT_CRATE, "network");
    }
}
