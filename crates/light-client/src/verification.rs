//! Verification status attached to every value a light client returns.
//!
//! The core invariant of a light node is the *no-trusted-proxy* rule: it must
//! never present unverified data as if it were trusted. Every read therefore
//! returns a [`VerifiedValue<T>`] carrying an explicit [`Verification`] tag, and
//! there is no code path that stamps [`Verification::Verified`] onto a value
//! that did not verify against the current verified checkpoint root.

/// The trust status of a returned value.
///
/// - [`Verification::Verified`] — proven against the *current* highest verified
///   checkpoint's state root.
/// - [`Verification::Stale`] — proven against a *previously* verified root that
///   the tip has since advanced past; still cryptographically sound at that
///   height, but no longer current.
/// - [`Verification::Unverified`] — not backed by any verified proof (e.g.
///   peer-advertised discovery metadata, or a proof that did not verify).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verification {
    /// Proven against the current verified checkpoint at this height.
    Verified {
        /// Height (last covered sequence) of the checkpoint proven against.
        checkpoint_height: u64,
    },
    /// Proven against an older, now-superseded verified checkpoint.
    Stale {
        /// Height of the older checkpoint the value was proven against.
        checkpoint_height: u64,
    },
    /// Not backed by a verified proof.
    Unverified,
}

impl Verification {
    /// Whether this is the strongest, current-tip status.
    #[must_use]
    pub fn is_verified(&self) -> bool {
        matches!(self, Verification::Verified { .. })
    }

    /// Whether this value is trustworthy at *some* height (verified or stale).
    #[must_use]
    pub fn is_proven(&self) -> bool {
        matches!(
            self,
            Verification::Verified { .. } | Verification::Stale { .. }
        )
    }

    /// The checkpoint height a proven value is anchored to, if any.
    #[must_use]
    pub fn height(&self) -> Option<u64> {
        match self {
            Verification::Verified { checkpoint_height }
            | Verification::Stale { checkpoint_height } => Some(*checkpoint_height),
            Verification::Unverified => None,
        }
    }
}

/// A value paired with its [`Verification`] status.
///
/// The status is immutable once constructed and there is no constructor that
/// upgrades an [`Verification::Unverified`] value to verified, preserving the
/// no-trusted-proxy invariant by construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedValue<T> {
    value: T,
    verification: Verification,
}

impl<T> VerifiedValue<T> {
    /// A value proven against the current verified tip at `checkpoint_height`.
    #[must_use]
    pub fn verified(value: T, checkpoint_height: u64) -> Self {
        Self {
            value,
            verification: Verification::Verified { checkpoint_height },
        }
    }

    /// A value proven against an older, now-superseded checkpoint.
    #[must_use]
    pub fn stale(value: T, checkpoint_height: u64) -> Self {
        Self {
            value,
            verification: Verification::Stale { checkpoint_height },
        }
    }

    /// A value with no verified backing.
    #[must_use]
    pub fn unverified(value: T) -> Self {
        Self {
            value,
            verification: Verification::Unverified,
        }
    }

    /// The wrapped value.
    #[must_use]
    pub fn value(&self) -> &T {
        &self.value
    }

    /// The verification status.
    #[must_use]
    pub fn verification(&self) -> Verification {
        self.verification
    }

    /// Whether the value is verified against the current tip.
    #[must_use]
    pub fn is_verified(&self) -> bool {
        self.verification.is_verified()
    }

    /// Consume the wrapper, returning the inner value.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.value
    }

    /// Map the inner value while preserving the verification status.
    #[must_use]
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> VerifiedValue<U> {
        VerifiedValue {
            value: f(self.value),
            verification: self.verification,
        }
    }
}
