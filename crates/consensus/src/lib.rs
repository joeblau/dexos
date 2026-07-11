//! `consensus` — BFT consensus, sequencing, and quorum-signed checkpoints.
//!
//! Part of the DexOS decentralized market operating system.

/// Crate identity, used by the node composition root for a startup manifest.
pub const CRATE_NAME: &str = "consensus";

#[cfg(test)]
mod tests {
    #[test]
    fn crate_name_is_stable() {
        assert_eq!(super::CRATE_NAME, "consensus");
    }
}
