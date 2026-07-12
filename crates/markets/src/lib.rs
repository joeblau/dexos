//! `markets` — the generic market registry, sponsorship, lifecycle, generic
//! payout vectors, complete-set accounting, perpetual funding, and the
//! resolution framework for DexOS.
//!
//! Part of the DexOS decentralized market operating system and its deterministic
//! execution core: no async runtime, no networking, no floating point,
//! fixed-point integers only. Every fallible operation returns a typed error
//! (see [`error`]); nothing panics on adversarial input, and decoding untrusted
//! bytes is total.
//!
//! # Modules
//! * [`registry`] — [`MarketDefinition`], the [`MarketRegistry`], commands, and
//!   the deterministic state-root commitment.
//! * [`lifecycle`] — the validated 12-state lifecycle machine.
//! * [`sponsor`] — multi-sponsor stake accounting, revenue share, and slashing
//!   restricted to objectively-measurable faults.
//! * [`payout`] — payout-rule constructors, complete-set mint/redeem, settlement
//!   distribution, and worst-case liability (reusing the `risk` scenario engine).
//! * [`perpetual`] — deterministic mark price, signed funding, and realized PnL.
//! * [`resolution`] — threshold resolution committee, evidence-bound
//!   certificates, and staked challenge windows, kept separate from the price
//!   oracle.
#![forbid(unsafe_code)]

pub mod config;
pub mod error;
pub mod escrow;
pub mod lifecycle;
pub mod payout;
pub mod perpetual;
pub mod registry;
pub mod resolution;
pub mod sponsor;

pub use config::{FeeSchedule, LifecycleConfig, OracleConfig, ResolverConfig, MAX_BPS};
pub use error::{
    EscrowError, LifecycleError, MarketError, PayoutError, PerpError, ResolutionError, SponsorError,
};
pub use escrow::EscrowLedger;
pub use lifecycle::{
    accepts_orders, advance, is_legal_transition, is_terminal, HaltReason, HaltState,
    ALL_LIFECYCLE_STATES,
};
pub use payout::{
    dead_heat, invalid_refund, payout_sum, scalar_payout, winner_takes_all, worst_case_liability,
    CompleteSetPool, PayoutRule, Settlement,
};
pub use perpetual::{
    apply_funding, book_mid, derive_mark, fill_fee, funding_payment, realized_pnl, FundingEpochReceipt,
    FundingUpdate, PerpMarketState,
};
pub use registry::{LifecycleEvent, MarketCommand, MarketDefinition, MarketRegistry};
pub use resolution::{
    resolution_message, Challenge, ChallengeBook, ChallengeWindow, ResolutionAdapter,
    ResolutionCertificate, ResolutionPhase, ResolutionPolicy, MAX_CHALLENGES, RESOLUTION_DOMAIN,
    RESOLUTION_POLICY_DOMAIN,
};
pub use sponsor::{SlashableFault, SponsorSet, SponsorShare};

/// Crate identity, used by the node composition root for a startup manifest.
pub const CRATE_NAME: &str = "markets";

#[cfg(test)]
mod tests {
    #[test]
    fn crate_name_is_stable() {
        assert_eq!(super::CRATE_NAME, "markets");
    }

    /// Guard: the deterministic market modules contain no floating-point types.
    /// Needles are built at runtime so this test file does not trip its own scan.
    #[test]
    fn no_floating_point_in_source() {
        let f = 'f';
        let needle32 = format!("{f}32");
        let needle64 = format!("{f}64");
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
        let mut checked = 0usize;
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let src = std::fs::read_to_string(&path).unwrap();
            assert!(
                !src.contains(&needle32),
                "found {needle32} in {}",
                path.display()
            );
            assert!(
                !src.contains(&needle64),
                "found {needle64} in {}",
                path.display()
            );
            checked += 1;
        }
        assert!(checked >= 8, "expected to scan every market module");
    }

    /// Structural separation: the mark-price path takes prices and health, never
    /// a certificate; the resolution path binds an outcome vector over an
    /// independent hash domain. The two never share a certificate type.
    #[test]
    fn resolution_and_price_oracle_types_are_separate() {
        let mark = super::derive_mark(
            types::Price::from_raw(1_000_000),
            None,
            types::OracleHealth::Normal,
        )
        .unwrap();
        assert_eq!(mark, types::Price::from_raw(1_000_000));
        let msg = super::resolution_message(
            types::MarketId::new(1),
            types::Hash::ZERO,
            0,
            types::SequenceNumber::new(1),
            super::ResolutionPhase::Propose,
            &types::PayoutVector::new(vec![types::Amount::ONE]).unwrap(),
            types::Hash::ZERO,
        );
        assert!(!msg.is_zero());
    }
}
