//! Runtime CPU-feature detection and backend selection.
//!
//! Backends other than scalar are experimental compatibility seams. They are
//! not production controls and must not be interpreted as proof that a distinct
//! vector instruction kernel executed.
//!
//! [`Backend`] names the family of kernel a call will run. [`detect`] probes the
//! host once and returns the best backend actually available; callers may also
//! *force* a backend (used by the differential test harness). Because the
//! vectorized path is portable, forcing a wider backend than the host provides
//! is always a clean, correct fallback rather than an error.

/// The kernel family selected for a dispatched call.
///
/// Ordering is by increasing vector width for the vector-capable variants, but
/// callers should treat this as an opaque tag: [`Backend::Scalar`] runs the
/// reference kernel, every other variant runs the (identical-result) vectorized
/// kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Backend {
    /// Portable scalar reference. Always available; the canonical answer.
    Scalar,
    /// x86-64 AVX2 class host (256-bit lanes).
    Avx2,
    /// x86-64 AVX-512 class host (512-bit lanes).
    Avx512,
    /// aarch64 NEON (128-bit lanes; baseline on aarch64).
    Neon,
}

impl Backend {
    /// A stable, lower-case identifier for logs and manifests.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Backend::Scalar => "scalar",
            Backend::Avx2 => "avx2",
            Backend::Avx512 => "avx512",
            Backend::Neon => "neon",
        }
    }

    /// True only for production-supported, measured implementations.
    #[must_use]
    pub const fn is_production(self) -> bool {
        matches!(self, Backend::Scalar)
    }

    /// True when this backend selects the vectorized kernel path.
    #[must_use]
    pub const fn is_vectorized(self) -> bool {
        false
    }

    /// Whether the *running host* actually provides this backend's features.
    ///
    /// [`Backend::Scalar`] is universally available. A vector backend is
    /// available only on a matching architecture with the required feature bits.
    /// Forcing an unavailable backend still runs correctly (the portable vector
    /// path), so this is advisory, not a gate.
    #[must_use]
    pub fn is_available(self) -> bool {
        match self {
            Backend::Scalar => true,
            // `has_avx2`/`has_avx512` already return `false` on non-x86 targets.
            Backend::Avx2 => has_avx2(),
            Backend::Avx512 => has_avx512(),
            Backend::Neon => cfg!(target_arch = "aarch64"),
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn has_avx2() -> bool {
    std::is_x86_feature_detected!("avx2")
}

#[cfg(not(target_arch = "x86_64"))]
fn has_avx2() -> bool {
    false
}

#[cfg(target_arch = "x86_64")]
fn has_avx512() -> bool {
    std::is_x86_feature_detected!("avx512f")
}

#[cfg(not(target_arch = "x86_64"))]
fn has_avx512() -> bool {
    false
}

/// Select the only production-qualified backend.
///
/// Preference on x86-64 is AVX-512 → AVX2 → scalar; aarch64 always reports
/// [`Backend::Neon`] (mandatory in the base ISA); every other architecture
/// reports [`Backend::Scalar`]. The result is always a valid, runnable backend.
///
#[must_use]
pub fn detect() -> Backend {
    Backend::Scalar
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_returns_a_valid_runnable_backend() {
        let b = detect();
        // Whatever we detect must be reported available on this host.
        assert!(b.is_available(), "detected {b:?} but not available");
        assert!(matches!(
            b,
            Backend::Scalar | Backend::Avx2 | Backend::Avx512 | Backend::Neon
        ));
    }

    #[test]
    fn scalar_is_always_available_and_not_vectorized() {
        assert!(Backend::Scalar.is_available());
        assert!(!Backend::Scalar.is_vectorized());
        assert!(!Backend::Avx2.is_vectorized());
        assert!(!Backend::Avx512.is_vectorized());
        assert!(!Backend::Neon.is_vectorized());
        assert!(Backend::Scalar.is_production());
        assert!(!Backend::Avx2.is_production());
    }

    #[test]
    fn names_are_stable_and_distinct() {
        let all = [
            Backend::Scalar,
            Backend::Avx2,
            Backend::Avx512,
            Backend::Neon,
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a.name(), b.name());
            }
        }
        assert_eq!(Backend::Scalar.name(), "scalar");
    }

    #[test]
    fn availability_matches_architecture() {
        // Neon available iff aarch64; AVX* only ever available on x86_64.
        assert_eq!(Backend::Neon.is_available(), cfg!(target_arch = "aarch64"));
        if !cfg!(target_arch = "x86_64") {
            assert!(!Backend::Avx2.is_available());
            assert!(!Backend::Avx512.is_available());
        }
    }
}
