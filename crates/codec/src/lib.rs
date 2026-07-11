//! `codec` — compact binary wire codec (no JSON in latency paths).
//!
//! Part of the DexOS decentralized market operating system.

/// Crate identity, used by the node composition root for a startup manifest.
pub const CRATE_NAME: &str = "codec";

#[cfg(test)]
mod tests {
    #[test]
    fn crate_name_is_stable() {
        assert_eq!(super::CRATE_NAME, "codec");
    }
}
