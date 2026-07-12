//! Withdrawal authorization: chain-specific wallet-signature verification and
//! exact destination-address format enforcement.
//!
//! A withdrawal is only buildable if the debited account's *bound wallet* signed
//! its [`WithdrawalRequest::signing_hash`] — the authorization digest — under the
//! chain's signature scheme, the destination chain equals the adapter's chain,
//! and the destination address has the exact chain-specific length. This is the
//! "correctly bound wallet/session signature with chain-specific rules" path:
//! empty/random signatures, a wrong account, a wrong destination address, a
//! wrong chain, or a tampered authorization digest all fail verification.

use crate::error::AdapterError;
use crate::ids::ChainId;
use crate::withdrawal::WithdrawalRequest;
use crypto::{verify_ed25519, verify_secp256k1_evm};
use serde::{Deserialize, Serialize};
use types::AccountId;

/// The signature scheme a chain uses to authorize a withdrawal from a wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WalletScheme {
    /// secp256k1 ECDSA over a keccak-256 message digest — EVM wallets. The
    /// destination address is the 20-byte account.
    Secp256k1Evm,
    /// ed25519 over the raw message — SVM (Solana) wallets. The destination
    /// address is the 32-byte ed25519 public key.
    Ed25519,
}

impl WalletScheme {
    /// The exact destination-address length this chain requires, in bytes.
    #[must_use]
    pub const fn address_len(self) -> usize {
        match self {
            WalletScheme::Secp256k1Evm => 20,
            WalletScheme::Ed25519 => 32,
        }
    }

    /// The exact authorizing-signature length this chain requires, in bytes.
    #[must_use]
    pub const fn signature_len(self) -> usize {
        // secp256k1 is verified as raw `r || s` and ed25519 as `R || s`; both are
        // fixed 64-byte encodings (no recovery byte).
        64
    }

    /// Verify that `signature` authorizes `message` under `public_key`.
    ///
    /// # Errors
    /// [`AdapterError::InvalidSignature`] on a wrong-length signature, a
    /// malformed key/signature, or a signature that does not verify.
    pub fn verify(
        self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), AdapterError> {
        if signature.len() != self.signature_len() {
            return Err(AdapterError::InvalidSignature);
        }
        match self {
            WalletScheme::Secp256k1Evm => verify_secp256k1_evm(public_key, message, signature)
                .map_err(|_| AdapterError::InvalidSignature),
            WalletScheme::Ed25519 => {
                let pk: [u8; 32] = public_key
                    .try_into()
                    .map_err(|_| AdapterError::InvalidSignature)?;
                let sig: [u8; 64] = signature
                    .try_into()
                    .map_err(|_| AdapterError::InvalidSignature)?;
                verify_ed25519(&pk, message, &sig).map_err(|_| AdapterError::InvalidSignature)
            }
        }
    }
}

/// The wallet authorized to sign withdrawals for a single account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletBinding {
    /// The account this wallet is bound to.
    pub account: AccountId,
    /// The signature scheme the wallet uses.
    pub scheme: WalletScheme,
    /// The wallet public key (SEC1-encoded for secp256k1, the 32-byte key for
    /// ed25519).
    pub public_key: Vec<u8>,
}

/// Verify a withdrawal request's authorization against a bound wallet.
///
/// Enforces, in order: the binding is for the debited account, the destination
/// chain equals `adapter_chain`, the destination address has the exact
/// chain-specific length, and the user signature over
/// [`WithdrawalRequest::signing_hash`] verifies under the bound wallet with the
/// binding's scheme.
///
/// # Errors
/// - [`AdapterError::Unauthorized`] if the binding is for a different account.
/// - [`AdapterError::WrongChain`] if the destination chain is not this chain.
/// - [`AdapterError::InvalidRequest`] if the destination-address length is wrong.
/// - [`AdapterError::InvalidSignature`] if the signature does not verify.
pub fn verify_withdrawal_authorization(
    req: &WithdrawalRequest,
    adapter_chain: ChainId,
    binding: &WalletBinding,
) -> Result<(), AdapterError> {
    if binding.account != req.account_id {
        return Err(AdapterError::Unauthorized);
    }
    if req.destination_chain != adapter_chain {
        return Err(AdapterError::WrongChain);
    }
    if req.destination_address.len() != binding.scheme.address_len() {
        return Err(AdapterError::InvalidRequest);
    }
    let digest = req.signing_hash();
    binding
        .scheme
        .verify(&binding.public_key, digest.as_bytes(), &req.user_signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::{EvmKeyPair, KeyPair};
    use types::Amount;

    fn evm_request(nonce: u64) -> WithdrawalRequest {
        WithdrawalRequest {
            account_id: AccountId::new(5),
            destination_chain: ChainId::new(1),
            destination_address: vec![0xAB; 20],
            asset: crate::ids::AssetId::new(7),
            amount: Amount::from_raw(1_000_000),
            nonce,
            expires_at: 1_000,
            user_signature: vec![],
        }
    }

    fn evm_binding(kp: &EvmKeyPair) -> WalletBinding {
        WalletBinding {
            account: AccountId::new(5),
            scheme: WalletScheme::Secp256k1Evm,
            public_key: kp.public_sec1(),
        }
    }

    fn sign_evm(kp: &EvmKeyPair, req: &mut WithdrawalRequest) {
        req.user_signature = kp.sign_evm(req.signing_hash().as_bytes()).unwrap().to_vec();
    }

    #[test]
    fn evm_valid_authorization_accepted() {
        let kp = EvmKeyPair::from_seed(&[0x11; 32]).unwrap();
        let mut req = evm_request(1);
        sign_evm(&kp, &mut req);
        assert_eq!(
            verify_withdrawal_authorization(&req, ChainId::new(1), &evm_binding(&kp)),
            Ok(())
        );
    }

    #[test]
    fn evm_empty_and_random_signatures_rejected() {
        let kp = EvmKeyPair::from_seed(&[0x11; 32]).unwrap();
        let binding = evm_binding(&kp);
        // Empty signature.
        let req = evm_request(1);
        assert_eq!(
            verify_withdrawal_authorization(&req, ChainId::new(1), &binding),
            Err(AdapterError::InvalidSignature)
        );
        // Random 64-byte signature.
        let mut random = evm_request(1);
        random.user_signature = vec![0x42; 64];
        assert_eq!(
            verify_withdrawal_authorization(&random, ChainId::new(1), &binding),
            Err(AdapterError::InvalidSignature)
        );
    }

    #[test]
    fn evm_wrong_account_chain_and_destination_rejected() {
        let kp = EvmKeyPair::from_seed(&[0x11; 32]).unwrap();
        let binding = evm_binding(&kp);

        // Wrong account: binding is for account 5, request debits account 6.
        let mut wrong_acct = evm_request(1);
        wrong_acct.account_id = AccountId::new(6);
        sign_evm(&kp, &mut wrong_acct);
        assert_eq!(
            verify_withdrawal_authorization(&wrong_acct, ChainId::new(1), &binding),
            Err(AdapterError::Unauthorized)
        );

        // Wrong destination chain.
        let mut wrong_chain = evm_request(1);
        sign_evm(&kp, &mut wrong_chain);
        assert_eq!(
            verify_withdrawal_authorization(&wrong_chain, ChainId::new(2), &binding),
            Err(AdapterError::WrongChain)
        );

        // Wrong destination-address length (not exactly 20 bytes).
        let mut wrong_addr = evm_request(1);
        wrong_addr.destination_address = vec![0xAB; 32];
        sign_evm(&kp, &mut wrong_addr);
        assert_eq!(
            verify_withdrawal_authorization(&wrong_addr, ChainId::new(1), &binding),
            Err(AdapterError::InvalidRequest)
        );
    }

    #[test]
    fn evm_tampered_authorization_digest_rejected() {
        // Sign the original request, then mutate an authorized field so the
        // recomputed digest no longer matches the signature.
        let kp = EvmKeyPair::from_seed(&[0x11; 32]).unwrap();
        let binding = evm_binding(&kp);
        let mut req = evm_request(1);
        sign_evm(&kp, &mut req);
        req.amount = Amount::from_raw(2_000_000);
        assert_eq!(
            verify_withdrawal_authorization(&req, ChainId::new(1), &binding),
            Err(AdapterError::InvalidSignature)
        );
    }

    #[test]
    fn evm_signature_from_another_wallet_rejected() {
        let owner = EvmKeyPair::from_seed(&[0x11; 32]).unwrap();
        let attacker = EvmKeyPair::from_seed(&[0x22; 32]).unwrap();
        let mut req = evm_request(1);
        sign_evm(&attacker, &mut req);
        assert_eq!(
            verify_withdrawal_authorization(&req, ChainId::new(1), &evm_binding(&owner)),
            Err(AdapterError::InvalidSignature)
        );
    }

    #[test]
    fn ed25519_valid_and_tampered() {
        let kp = KeyPair::from_seed(&[0x33; 32]);
        let binding = WalletBinding {
            account: AccountId::new(5),
            scheme: WalletScheme::Ed25519,
            public_key: kp.public().to_vec(),
        };
        let mut req = WithdrawalRequest {
            account_id: AccountId::new(5),
            destination_chain: ChainId::new(900),
            destination_address: vec![0xCD; 32],
            asset: crate::ids::AssetId::new(3),
            amount: Amount::from_raw(500),
            nonce: 1,
            expires_at: 1_000,
            user_signature: vec![],
        };
        req.user_signature = kp.sign(req.signing_hash().as_bytes()).to_vec();
        assert_eq!(
            verify_withdrawal_authorization(&req, ChainId::new(900), &binding),
            Ok(())
        );

        // Tamper the nonce: digest changes, signature no longer verifies.
        let mut bad = req.clone();
        bad.nonce = 2;
        assert_eq!(
            verify_withdrawal_authorization(&bad, ChainId::new(900), &binding),
            Err(AdapterError::InvalidSignature)
        );

        // Wrong address length (not exactly 32 bytes).
        let mut short = req;
        short.destination_address = vec![0xCD; 20];
        assert_eq!(
            verify_withdrawal_authorization(&short, ChainId::new(900), &binding),
            Err(AdapterError::InvalidRequest)
        );
    }

    #[test]
    fn verification_never_panics_on_garbage() {
        let mut state = 0x1234_5678u64;
        let kp = EvmKeyPair::from_seed(&[0x11; 32]).unwrap();
        let binding = evm_binding(&kp);
        for _ in 0..5_000 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            let len = usize::try_from(state % 130).unwrap_or_default();
            let mut req = evm_request(state);
            req.user_signature = (0..len).map(|i| state.to_le_bytes()[i % 8]).collect();
            let _ = verify_withdrawal_authorization(&req, ChainId::new(1), &binding);
        }
    }
}
