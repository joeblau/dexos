//! `state-tree` — incremental state commitments and Merkle roots.
//!
//! Part of the DexOS decentralized market operating system.
//! This crate is part of the deterministic execution core: no async runtime,
//! no networking, no floating point, fixed-point integers only.

/// Crate identity, used by the node composition root for a startup manifest.
pub const CRATE_NAME: &str = "state-tree";

#[cfg(test)]
mod tests {
    #[test]
    fn crate_name_is_stable() {
        assert_eq!(super::CRATE_NAME, "state-tree");
    }
}
