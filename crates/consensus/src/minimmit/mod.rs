//! The single Minimmit consensus engine.
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
//! two thresholds. The protocol is driven by the clock-free
//! [`replica::MinimmitReplica`] reactor — `step(Input) -> Vec<Effect>` — with
//! all wall-clock time, delivery, block build, and block verify owned by the
//! node outside the core. Protocol authority: `docs/CONSENSUS_MINIMMIT.md`.

pub mod block;
pub mod committee;
pub mod digest;
pub mod replica;
pub mod wire;

pub use block::{BlockHeader, DOMAIN_BLOCK};
pub use committee::{Certificate, MinimmitCommittee, ThresholdKind};
pub use digest::{
    notarize_digest, nullify_digest, propose_auth, DOMAIN_NOTARIZE, DOMAIN_NULLIFY, DOMAIN_PROPOSE,
};
pub use replica::{Effect, EpochError, FinalityStage, Input, MinimmitReplica, Tally, TallyOutcome};
pub use wire::{
    msg_type, CertError, ConsensusMessage, ExecAttest, Notarization, Notarize, Nullification,
    Nullify, ParentRef, Proof, Propose, WireError, BOTTOM_VIEW,
};
