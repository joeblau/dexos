//! `custody` — the DexOS custody edge: wallet binding and the threshold custody
//! signer subsystem.
//!
//! Two cooperating halves:
//!
//! - **Wallet binding** ([`binding`], [`session`], [`chain`]) binds external
//!   EVM/SVM wallets to an internal [`AccountId`](types::AccountId), verifying
//!   EIP-712 secp256k1, EIP-1271 smart-wallet, and Solana ed25519 signatures;
//!   derives EVM addresses from public keys; authorizes scoped trading sessions;
//!   and gates withdrawals on a `withdrawals_allowed` wallet flag.
//!
//! - **Custody signing** ([`signer`], [`policy`], [`withdrawal`], [`controller`])
//!   runs a `t`-of-`n` threshold signer set behind a [`Signer`] HSM boundary,
//!   with a deterministic software simulator. Consensus *authorizes* a finalized
//!   [`WithdrawalCertificate`]; the custody controller *independently verifies*
//!   it, applies per-chain policy, prevents duplicate signing, supports signer
//!   rotation and emergency halt, and maintains an audit-root over every event.
//!
//! Pure, integer-only, and deterministic: no floating point, no async, no I/O.
//! Every fallible operation returns [`CustodyError`]; decoding arbitrary bytes
//! never panics.
#![forbid(unsafe_code)]

mod error;
mod wire;

pub mod binding;
pub mod chain;
pub mod controller;
pub mod policy;
pub mod session;
pub mod signer;
pub mod withdrawal;

pub use error::CustodyError;

pub use binding::{
    bind_authorization_message, revoke_authorization_message, rotate_master_authorization_message,
    set_privileges_authorization_message, BindWallet, WalletBinding, WalletKey, WalletProof,
    WalletRegistry, BIND_AUTH_DOMAIN, BIND_DOMAIN,
};
pub use chain::{evm_address_from_pubkey, ChainId, ChainKind, WalletAddress};
pub use controller::{ControlCommand, CustodyController, SignedWithdrawal};
pub use policy::ChainPolicy;
pub use session::{AuthorizeSession, SessionKey, SessionRegistry, SessionScope, SESSION_DOMAIN};
pub use signer::{HsmBackend, HsmSigner, KeyHandle, KeyRef, Signer, SignerSet, MAX_SIGNERS};
#[cfg(any(feature = "mock-signers", test))]
pub use signer::{MockHsm, SoftSigner};
pub use withdrawal::{
    verify_certificate, withdrawal_authorization_digest, ReservationProof, WithdrawalCertificate,
    WithdrawalId, WithdrawalRequest, WITHDRAWAL_AUTH_DOMAIN, WITHDRAWAL_DOMAIN,
};

/// Crate identity, used by the node composition root for a startup manifest.
pub const CRATE_NAME: &str = "custody";

#[cfg(test)]
mod tests {
    #[test]
    fn crate_name_is_stable() {
        assert_eq!(super::CRATE_NAME, "custody");
    }
}
