//! `simd` — the sanctioned isolated-performance crate for DexOS.
//!
//! It hosts a **runtime CPU-feature dispatch framework** and the performance
//! kernels that hang off it. Every kernel ships in two bit-identical forms:
//!
//! * a plain **scalar reference** (the canonical answer), and
//! * a lane-structured **vectorized** implementation the optimizer can lower to
//!   real SIMD registers.
//!
//! The vectorized reductions use only *associative and commutative* integer
//! operations ([`i128::wrapping_add`], `min`, `max`) and side-effect-free
//! per-element maps, so lane striding can never change the result. That is the
//! headline invariant, exercised by large deterministic LCG corpora in every
//! module: `scalar == vectorized == dispatched`, bit for bit.
//!
//! # Design choice: portable, no `unsafe`
//!
//! This crate could carry `core::arch` intrinsics behind a documented
//! crate-level `#![allow(unsafe_code)]`. It deliberately does **not**: the
//! kernels are written so the compiler auto-vectorizes them, which keeps the
//! crate compiling cleanly under the workspace `unsafe_code = "deny"` lint with
//! zero `unsafe` blocks while still providing genuine vector code paths (see the
//! lane-structured reductions in [`risk`] and the mask map in [`oracle`]). The
//! [`Backend`] selector is the seam where future hand-written intrinsic kernels
//! would slot in without changing any observable result.
//!
//! # Kernels
//!
//! | Module      | Kernel                                             |
//! |-------------|----------------------------------------------------|
//! | [`digest`]  | batch signature pre-hashing / message digests      |
//! | [`risk`]    | scenario-vector reduction (sum / min / max, i128)  |
//! | [`oracle`]  | integer median / MAD + outlier mask                |
//! | [`merkle`]  | batched Merkle-update / from-scratch root helper    |
//!
//! Each kernel exposes a `*_scalar` reference, a `(Backend, …)` selector, and a
//! `*_dispatch` convenience that runs on the best backend [`detect`] finds.

pub mod backend;
pub mod digest;
pub mod merkle;
pub mod oracle;
pub mod risk;

pub use backend::{detect, Backend};
pub use digest::{
    batch_hash_domain, batch_hash_domain_dispatch, batch_hash_domain_scalar, batch_hash_leaves,
    batch_hash_leaves_dispatch, batch_hash_leaves_scalar, batch_keccak256,
    batch_keccak256_dispatch, batch_keccak256_scalar,
};
pub use merkle::{
    apply_updates, batch_merkle_root, batch_merkle_root_dispatch, batch_merkle_root_scalar,
};
pub use oracle::{
    filter_outliers, mad_i64, median_i64, outlier_mask, outlier_mask_dispatch, outlier_mask_scalar,
    outlier_mask_vectorized, OracleFilter,
};
pub use risk::{
    scenario_stats, scenario_stats_amounts, scenario_stats_dispatch, scenario_stats_scalar,
    scenario_stats_vectorized, ScenarioStats,
};

/// Crate identity, referenced by the node composition root for a startup manifest.
pub const CRATE_NAME: &str = "simd";

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic LCG shared by the cross-kernel smoke test.
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
        fn len(&mut self, bound: usize) -> usize {
            usize::try_from(self.next() % (bound as u64 + 1)).unwrap_or(0)
        }
    }

    #[test]
    fn crate_name_is_stable() {
        assert_eq!(CRATE_NAME, "simd");
    }

    #[test]
    fn dispatch_runs_a_valid_backend_for_every_kernel() {
        let b = detect();
        assert!(b.is_available());

        // Each kernel's dispatched result must equal its scalar reference.
        let payouts = [1i128, -2, 3, -4, 5, 6, 7, 8, 9];
        assert_eq!(scenario_stats(b, &payouts), scenario_stats_scalar(&payouts));

        let vals = [10i64, 12, 9, 500, 11];
        assert_eq!(
            outlier_mask(b, &vals, 11, 5),
            outlier_mask_scalar(&vals, 11, 5)
        );

        let msgs: Vec<&[u8]> = vec![b"x", b"yy"];
        assert_eq!(batch_keccak256(b, &msgs), batch_keccak256_scalar(&msgs));

        let leaves = [
            types::Hash::from_bytes([1; 32]),
            types::Hash::from_bytes([2; 32]),
        ];
        assert_eq!(
            batch_merkle_root(b, &leaves),
            batch_merkle_root_scalar(&leaves)
        );
    }

    #[test]
    fn forcing_each_backend_yields_the_reference_result() {
        let mut r = Lcg(0x9e37_79b9_7f4a_7c15);
        for _ in 0..1_000 {
            let n = r.len(64);
            let payouts: Vec<i128> = (0..n)
                .map(|_| i128::from(r.next()) - i128::from(u64::MAX / 2))
                .collect();
            let reference = scenario_stats_scalar(&payouts);
            for b in [
                Backend::Scalar,
                Backend::Avx2,
                Backend::Avx512,
                Backend::Neon,
            ] {
                assert_eq!(scenario_stats(b, &payouts), reference, "backend {b:?}");
            }
        }
    }
}
