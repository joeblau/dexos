//! Minimmit consensus engine (migration in progress; additive beside HotStuff).
//!
//! Minimmit is a two-threshold BFT protocol over a committee of total voting
//! weight `W` tolerating at most `B` Byzantine weight (`W >= 5B + 1`; unit
//! weight: `n >= 5f + 1`, minimum committee **6** at `f = 1`, and `f = 3` at
//! the [`crate::MAX_VALIDATORS`] = 16 cap):
//!
//! - an **M**-certificate (`M = 2B + 1` weight, notarization or nullification)
//!   advances the view;
//! - an **L**-notarization (`L = W − B` weight) finalizes the block and its
//!   ancestors.
//!
//! Both certificate kinds are the same [`committee::Certificate`] verified at
//! two thresholds. This module lands **additively**: no HotStuff type is
//! removed before Phase 5 of the migration. Protocol authority:
//! `docs/CONSENSUS_MINIMMIT.md`.

pub mod committee;

pub use committee::{Certificate, MinimmitCommittee, ThresholdKind};
