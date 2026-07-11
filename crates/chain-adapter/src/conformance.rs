//! A reusable conformance harness so every [`ChainAdapter`] implementation can
//! be checked against the same behavioral contract.
//!
//! The harness drives an adapter purely through `&dyn ChainAdapter`, proving
//! object-safety and the shared invariants. It returns a descriptive `Err` on
//! any violation so downstream test crates can `unwrap()` it.

use crate::adapter::ChainAdapter;
use crate::error::AdapterError;
use crate::ids::TxId;
use crate::withdrawal::WithdrawalRequest;

/// Inputs required to run the shared conformance checks against an adapter.
pub struct ConformanceFixture<'a> {
    /// The adapter under test, as a trait object.
    pub adapter: &'a dyn ChainAdapter,
    /// A transaction id that has a finalized deposit.
    pub finalized_deposit_tx: TxId,
    /// A transaction id the adapter does not know about.
    pub unknown_tx: TxId,
    /// A well-formed, unexpired withdrawal request with a supported asset.
    pub valid_withdrawal: WithdrawalRequest,
}

/// Run the shared conformance suite. Returns `Err(reason)` on any violation.
///
/// # Errors
/// A human-readable description of the first invariant that failed.
pub fn run_conformance(f: &ConformanceFixture<'_>) -> Result<(), String> {
    let chain = f.adapter.chain_id();

    // observe_deposits must succeed and only report deposits for this chain.
    let deposits = f
        .adapter
        .observe_deposits()
        .map_err(|e| format!("observe_deposits failed: {e}"))?;
    for d in &deposits {
        if d.source_chain != chain {
            return Err("observe_deposits returned a foreign-chain deposit".into());
        }
    }

    // A known finalized deposit must verify and match the adapter's chain.
    let verified = f
        .adapter
        .verify_deposit(&f.finalized_deposit_tx)
        .map_err(|e| format!("verify_deposit(finalized) failed: {e}"))?;
    if verified.source_chain != chain {
        return Err("verify_deposit returned a foreign-chain deposit".into());
    }

    // An unknown tx must be reported as UnknownTx, never a panic.
    match f.adapter.verify_deposit(&f.unknown_tx) {
        Err(AdapterError::UnknownTx) => {}
        Err(other) => return Err(format!("verify_deposit(unknown) wrong error: {other}")),
        Ok(_) => return Err("verify_deposit(unknown) unexpectedly succeeded".into()),
    }
    match f.adapter.observe_withdrawal(&f.unknown_tx) {
        Err(AdapterError::UnknownTx) => {}
        Err(other) => return Err(format!("observe_withdrawal(unknown) wrong error: {other}")),
        Ok(_) => return Err("observe_withdrawal(unknown) unexpectedly succeeded".into()),
    }

    // build_withdrawal must be deterministic and carry the deterministic id.
    let tx1 = f
        .adapter
        .build_withdrawal(&f.valid_withdrawal)
        .map_err(|e| format!("build_withdrawal failed: {e}"))?;
    let tx2 = f
        .adapter
        .build_withdrawal(&f.valid_withdrawal)
        .map_err(|e| format!("build_withdrawal (2nd) failed: {e}"))?;
    if tx1 != tx2 {
        return Err("build_withdrawal is not deterministic".into());
    }
    if tx1.withdrawal_id != f.valid_withdrawal.id() {
        return Err("unsigned tx carries the wrong withdrawal id".into());
    }
    if tx1.destination_chain != f.valid_withdrawal.destination_chain {
        return Err("unsigned tx has wrong destination chain".into());
    }

    Ok(())
}
