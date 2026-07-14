//! Runtime CPU-feature detection and backend selection.
//!
//! [`Backend`] names the family of kernel a call will run. [`detect`] probes the
//! host once and returns the best backend actually available. Operator-requested
//! forcing goes through [`Backend::force`], which fails if the named backend is
//! unknown or unavailable instead of silently running another implementation.

use std::sync::OnceLock;

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

    /// True only for production-supported implementation families.
    #[must_use]
    pub const fn is_production(self) -> bool {
        matches!(
            self,
            Backend::Scalar | Backend::Avx2 | Backend::Avx512 | Backend::Neon
        )
    }

    /// True when this backend selects the vectorized kernel path.
    #[must_use]
    pub const fn is_vectorized(self) -> bool {
        !matches!(self, Backend::Scalar)
    }

    /// Whether the *running host* actually provides this backend's features.
    ///
    /// [`Backend::Scalar`] is universally available. A vector backend is
    /// available only on a matching architecture with the required feature bits.
    /// Direct enum construction is intended for differential tests. Operator
    /// configuration must use [`Backend::force`] so availability is a gate.
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

    /// Strictly select an explicitly requested backend.
    ///
    /// # Errors
    /// Returns [`BackendError::Unknown`] for an unknown name and
    /// [`BackendError::Unavailable`] when the running host lacks its feature set.
    pub fn force(name: &str) -> Result<Self, BackendError> {
        let backend = match name {
            "scalar" => Backend::Scalar,
            "avx2" => Backend::Avx2,
            "avx512" => Backend::Avx512,
            "neon" => Backend::Neon,
            _ => return Err(BackendError::Unknown(name.to_string())),
        };
        if backend.is_available() {
            Ok(backend)
        } else {
            Err(BackendError::Unavailable(backend))
        }
    }
}

/// Runtime backend selection failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BackendError {
    /// The configured backend name is not recognized.
    #[error("unknown SIMD backend '{0}'")]
    Unknown(String),
    /// The backend is known but cannot execute on this host.
    #[error("SIMD backend '{}' is unavailable on this host", .0.name())]
    Unavailable(Backend),
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

/// Select and cache the best runnable backend for this process.
///
/// Preference on x86-64 is AVX-512 → AVX2 → scalar; aarch64 always reports
/// [`Backend::Neon`] (mandatory in the base ISA); every other architecture
/// reports [`Backend::Scalar`]. The result is always a valid, runnable backend.
///
#[must_use]
pub fn detect() -> Backend {
    static DETECTED: OnceLock<Backend> = OnceLock::new();
    *DETECTED.get_or_init(detect_uncached)
}

fn detect_uncached() -> Backend {
    if Backend::Avx512.is_available() {
        Backend::Avx512
    } else if Backend::Avx2.is_available() {
        Backend::Avx2
    } else if Backend::Neon.is_available() {
        Backend::Neon
    } else {
        Backend::Scalar
    }
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
    fn scalar_is_always_available_and_vector_tags_are_distinct() {
        assert!(Backend::Scalar.is_available());
        assert!(!Backend::Scalar.is_vectorized());
        assert!(Backend::Avx2.is_vectorized());
        assert!(Backend::Avx512.is_vectorized());
        assert!(Backend::Neon.is_vectorized());
        assert!(Backend::Scalar.is_production());
        assert!(Backend::Avx2.is_production());
        assert!(Backend::Avx512.is_production());
        assert!(Backend::Neon.is_production());
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

    #[test]
    fn forced_backend_never_silently_falls_back() {
        assert_eq!(Backend::force("scalar"), Ok(Backend::Scalar));
        assert!(matches!(
            Backend::force("not-a-backend"),
            Err(BackendError::Unknown(_))
        ));
        for backend in [Backend::Avx2, Backend::Avx512, Backend::Neon] {
            let forced = Backend::force(backend.name());
            if backend.is_available() {
                assert_eq!(forced, Ok(backend));
            } else {
                assert_eq!(forced, Err(BackendError::Unavailable(backend)));
            }
        }
    }
}
