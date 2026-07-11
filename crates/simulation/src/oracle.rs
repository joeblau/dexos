//! Safety oracle: checks that surviving honest nodes agree.
//!
//! The single most important property of the simulator is *agreement*: after a
//! run, every surviving honest node must hold a bit-identical finalized state
//! root (and checkpoint chain). [`StateRootOracle`] compares the reported roots
//! and returns a precise [`Divergence`] naming the outliers if they disagree —
//! this both proves safety on clean runs and *fails closed* the instant any
//! node diverges (e.g. an injected mutation).

use types::Hash;

use crate::node::NodeId;

/// Evidence that nodes disagreed on the finalized state.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Divergence {
    /// No nodes were supplied to compare.
    #[error("no nodes to compare")]
    Empty,
    /// Nodes reported differing roots. `majority` is the most common root;
    /// `outliers` are the nodes that disagreed with it.
    #[error("state-root divergence: {} node(s) disagree with the majority", .outliers.len())]
    Disagreement {
        /// The most common (majority) root.
        majority: Hash,
        /// Nodes that reported a different root.
        outliers: Vec<(NodeId, Hash)>,
    },
}

/// Compares finalized roots across nodes.
#[derive(Debug, Clone, Copy, Default)]
pub struct StateRootOracle;

impl StateRootOracle {
    /// Check that every `(node, root)` pair reports the identical root. On
    /// success returns the agreed root; on failure returns the majority root
    /// and the dissenting nodes.
    ///
    /// # Errors
    /// Returns [`Divergence::Empty`] if `roots` is empty, or
    /// [`Divergence::Disagreement`] if any node disagrees.
    pub fn agree(roots: &[(NodeId, Hash)]) -> Result<Hash, Divergence> {
        let Some(&(_, first)) = roots.first() else {
            return Err(Divergence::Empty);
        };
        if roots.iter().all(|&(_, r)| r == first) {
            return Ok(first);
        }

        // Determine the majority root deterministically: tally by value, then
        // pick the highest count, breaking ties by the smaller hash bytes.
        let mut tally: Vec<(Hash, u64)> = Vec::new();
        for &(_, r) in roots {
            if let Some(entry) = tally.iter_mut().find(|(h, _)| *h == r) {
                entry.1 += 1;
            } else {
                tally.push((r, 1));
            }
        }
        tally.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let majority = tally.first().map(|(h, _)| *h).unwrap_or(Hash::ZERO);
        let outliers: Vec<(NodeId, Hash)> = roots
            .iter()
            .copied()
            .filter(|&(_, r)| r != majority)
            .collect();
        Err(Divergence::Disagreement { majority, outliers })
    }
}
