//! Binding external EVM/SVM wallets to an internal [`AccountId`].
//!
//! A [`BindWallet`] command carries a [`WalletProof`] — an EIP-712 secp256k1
//! signature, an EIP-1271 smart-wallet signature, or a Solana ed25519 signature
//! — over a domain-separated binding message. The [`WalletRegistry`] verifies
//! it, derives/checks the address, enforces the per-account cap, and rejects
//! duplicate or replayed bindings. Master designation and the
//! `withdrawals_allowed` flag drive the withdrawal-authorization policy.

use std::collections::BTreeSet;

use crypto::{hash_leaf, hash_node, verify_ed25519, verify_eip1271, verify_secp256k1_evm};
use types::{AccountId, Hash, SequenceNumber};

use crate::chain::{evm_address_from_pubkey, ChainKind, WalletAddress};
use crate::error::CustodyError;
use crate::wire::{Reader, Writer};

/// Domain tag separating binding messages from every other signed payload.
pub const BIND_DOMAIN: &[u8] = b"DEXOS/BIND-WALLET/v1";

/// The verifying key an external wallet authorizes with. Retained on the
/// binding so later authorizations (sessions, withdrawals) can re-check that a
/// fresh proof carries the same key that was originally bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletKey {
    /// SEC1-encoded secp256k1 key (EIP-712 signer or EIP-1271 owner key).
    Secp256k1Sec1(Vec<u8>),
    /// A 32-byte ed25519 public key (Solana / SVM).
    Ed25519([u8; 32]),
}

/// A signature proving control of an external wallet over a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletProof {
    /// EIP-712: secp256k1 ECDSA over `keccak256(message)`.
    Eip712 {
        /// SEC1 public key (65-byte uncompressed, so the address can be derived).
        public_key_sec1: Vec<u8>,
        /// 64-byte `r || s` signature.
        signature: Vec<u8>,
    },
    /// EIP-1271: smart-wallet authorization modeled as the owner secp256k1 key.
    Eip1271 {
        /// SEC1 owner public key.
        owner_public_key_sec1: Vec<u8>,
        /// 64-byte `r || s` signature.
        signature: Vec<u8>,
    },
    /// Solana ed25519 signature; the wallet address is the public key itself.
    Ed25519 {
        /// 32-byte ed25519 public key.
        public_key: [u8; 32],
        /// 64-byte ed25519 signature.
        signature: [u8; 64],
    },
}

const PROOF_EIP712: u8 = 1;
const PROOF_EIP1271: u8 = 2;
const PROOF_ED25519: u8 = 3;

impl WalletProof {
    /// The verifying key carried by this proof.
    pub fn key(&self) -> WalletKey {
        match self {
            Self::Eip712 {
                public_key_sec1, ..
            } => WalletKey::Secp256k1Sec1(public_key_sec1.clone()),
            Self::Eip1271 {
                owner_public_key_sec1,
                ..
            } => WalletKey::Secp256k1Sec1(owner_public_key_sec1.clone()),
            Self::Ed25519 { public_key, .. } => WalletKey::Ed25519(*public_key),
        }
    }

    /// Verify this proof over `message`, returning the typed error on failure.
    pub fn verify(&self, message: &[u8]) -> Result<(), CustodyError> {
        match self {
            Self::Eip712 {
                public_key_sec1,
                signature,
            } => Ok(verify_secp256k1_evm(public_key_sec1, message, signature)?),
            Self::Eip1271 {
                owner_public_key_sec1,
                signature,
            } => Ok(verify_eip1271(owner_public_key_sec1, message, signature)?),
            Self::Ed25519 {
                public_key,
                signature,
            } => Ok(verify_ed25519(public_key, message, signature)?),
        }
    }

    fn encode_into(&self, w: &mut Writer) -> Result<(), CustodyError> {
        match self {
            Self::Eip712 {
                public_key_sec1,
                signature,
            } => {
                w.u8(PROOF_EIP712);
                w.var_bytes(public_key_sec1)?;
                w.var_bytes(signature)?;
            }
            Self::Eip1271 {
                owner_public_key_sec1,
                signature,
            } => {
                w.u8(PROOF_EIP1271);
                w.var_bytes(owner_public_key_sec1)?;
                w.var_bytes(signature)?;
            }
            Self::Ed25519 {
                public_key,
                signature,
            } => {
                w.u8(PROOF_ED25519);
                w.raw(public_key);
                w.raw(signature);
            }
        }
        Ok(())
    }

    fn decode_from(r: &mut Reader<'_>) -> Result<Self, CustodyError> {
        match r.u8()? {
            PROOF_EIP712 => Ok(Self::Eip712 {
                public_key_sec1: r.var_bytes()?,
                signature: r.var_bytes()?,
            }),
            PROOF_EIP1271 => Ok(Self::Eip1271 {
                owner_public_key_sec1: r.var_bytes()?,
                signature: r.var_bytes()?,
            }),
            PROOF_ED25519 => Ok(Self::Ed25519 {
                public_key: r.array::<32>()?,
                signature: r.array::<64>()?,
            }),
            _ => Err(CustodyError::Decode),
        }
    }
}

/// A command binding an external wallet to an account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindWallet {
    /// The internal account to bind to.
    pub account: AccountId,
    /// The external wallet address.
    pub address: WalletAddress,
    /// Whether this wallet is the account's master (control) wallet.
    pub is_master: bool,
    /// Whether this wallet may authorize withdrawals.
    pub withdrawals_allowed: bool,
    /// A per-account monotone nonce guarding against binding replay.
    pub nonce: u64,
    /// Proof of control over the wallet.
    pub proof: WalletProof,
}

impl BindWallet {
    /// The canonical message the wallet must sign to authorize this binding.
    pub fn binding_message(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.raw(BIND_DOMAIN);
        w.u32(self.account.get());
        self.address.encode_into(&mut w);
        w.u8(u8::from(self.is_master));
        w.u8(u8::from(self.withdrawals_allowed));
        w.u64(self.nonce);
        w.into_vec()
    }

    /// Canonical byte encoding of the command (for fuzzing / transport).
    pub fn encode(&self) -> Result<Vec<u8>, CustodyError> {
        let mut w = Writer::new();
        w.u32(self.account.get());
        self.address.encode_into(&mut w);
        w.u8(u8::from(self.is_master));
        w.u8(u8::from(self.withdrawals_allowed));
        w.u64(self.nonce);
        self.proof.encode_into(&mut w)?;
        Ok(w.into_vec())
    }

    /// Decode a command from bytes. Total: arbitrary input yields `Err`.
    pub fn decode(bytes: &[u8]) -> Result<Self, CustodyError> {
        let mut r = Reader::new(bytes);
        let account = AccountId::new(r.u32()?);
        let address = WalletAddress::decode_from(&mut r)?;
        let is_master = r.u8()? != 0;
        let withdrawals_allowed = r.u8()? != 0;
        let nonce = r.u64()?;
        let proof = WalletProof::decode_from(&mut r)?;
        r.finish()?;
        Ok(Self {
            account,
            address,
            is_master,
            withdrawals_allowed,
            nonce,
            proof,
        })
    }
}

/// A stored, verified wallet binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletBinding {
    /// The account this wallet is bound to.
    pub account: AccountId,
    /// The external wallet address.
    pub address: WalletAddress,
    /// The chain family (derived from the address).
    pub chain: ChainKind,
    /// The verifying key authorized at bind time.
    pub key: WalletKey,
    /// Whether this is the account's master wallet.
    pub is_master: bool,
    /// Whether this wallet may authorize withdrawals.
    pub withdrawals_allowed: bool,
    /// The sequence at which the binding was created.
    pub bound_at: SequenceNumber,
    /// The sequence at which it was revoked, if any.
    pub revoked_at: Option<SequenceNumber>,
}

impl WalletBinding {
    /// Whether the binding is active (not revoked as of `at`).
    pub fn is_active(&self, at: SequenceNumber) -> bool {
        match self.revoked_at {
            None => true,
            Some(r) => at < r,
        }
    }
}

/// A registry of wallet bindings across accounts.
///
/// Enforces a per-account cap, rejects duplicate active bindings, and prevents
/// binding-nonce replay. All mutations are deterministic, so replaying the same
/// command sequence on two instances yields an identical [`state_root`].
///
/// [`state_root`]: WalletRegistry::state_root
#[derive(Debug, Clone)]
pub struct WalletRegistry {
    max_per_account: usize,
    bindings: Vec<WalletBinding>,
    used_nonces: BTreeSet<(u32, u64)>,
}

impl WalletRegistry {
    /// A new registry allowing at most `max_per_account` active wallets each.
    pub fn new(max_per_account: usize) -> Self {
        Self {
            max_per_account,
            bindings: Vec::new(),
            used_nonces: BTreeSet::new(),
        }
    }

    fn index_of(&self, account: AccountId, address: &WalletAddress) -> Option<usize> {
        self.bindings
            .iter()
            .position(|b| b.account == account && &b.address == address)
    }

    /// Verify and apply a [`BindWallet`] command at sequence `seq`.
    ///
    /// Verifies the proof, checks that the proof key matches the address
    /// (EIP-712 derives the address; ed25519's address is the key; EIP-1271
    /// trusts the smart-wallet address after verifying the owner signature),
    /// and enforces the replay, duplicate, and cap rules.
    pub fn bind(&mut self, cmd: &BindWallet, seq: SequenceNumber) -> Result<(), CustodyError> {
        // Replay guard: a (account, nonce) may be consumed at most once.
        let nonce_key = (cmd.account.get(), cmd.nonce);
        if self.used_nonces.contains(&nonce_key) {
            return Err(CustodyError::ReplayedBinding);
        }

        // Verify the signature over the canonical binding message.
        let message = cmd.binding_message();
        cmd.proof.verify(&message)?;

        // Address must be consistent with the proof and the declared chain.
        match (&cmd.address, &cmd.proof) {
            (
                WalletAddress::Evm(addr),
                WalletProof::Eip712 {
                    public_key_sec1, ..
                },
            ) => {
                let derived = evm_address_from_pubkey(public_key_sec1)?;
                if &derived != addr {
                    return Err(CustodyError::AddressMismatch);
                }
            }
            (WalletAddress::Evm(_), WalletProof::Eip1271 { .. }) => {
                // Smart-wallet contract address is independent of the owner key;
                // the owner signature has already been verified above.
            }
            (WalletAddress::Svm(addr), WalletProof::Ed25519 { public_key, .. }) => {
                if addr != public_key {
                    return Err(CustodyError::AddressMismatch);
                }
            }
            _ => return Err(CustodyError::MalformedAddress),
        }

        // Duplicate active binding of the same (account, address).
        if let Some(i) = self.index_of(cmd.account, &cmd.address) {
            if self.bindings[i].is_active(seq) {
                return Err(CustodyError::DuplicateBinding);
            }
        }

        // Per-account cap over active bindings.
        let active = self
            .bindings
            .iter()
            .filter(|b| b.account == cmd.account && b.is_active(seq))
            .count();
        if active >= self.max_per_account {
            return Err(CustodyError::BindingCapExceeded);
        }

        self.used_nonces.insert(nonce_key);
        self.bindings.push(WalletBinding {
            account: cmd.account,
            address: cmd.address,
            chain: cmd.address.kind(),
            key: cmd.proof.key(),
            is_master: cmd.is_master,
            withdrawals_allowed: cmd.withdrawals_allowed,
            bound_at: seq,
            revoked_at: None,
        });
        Ok(())
    }

    /// Revoke an active binding at `seq`. Idempotent errors: unknown/inactive.
    pub fn revoke(
        &mut self,
        account: AccountId,
        address: &WalletAddress,
        seq: SequenceNumber,
    ) -> Result<(), CustodyError> {
        let i = self
            .index_of(account, address)
            .ok_or(CustodyError::UnknownWallet)?;
        if !self.bindings[i].is_active(seq) {
            return Err(CustodyError::UnknownWallet);
        }
        self.bindings[i].revoked_at = Some(seq);
        Ok(())
    }

    /// The active binding for a wallet, if any.
    pub fn binding(
        &self,
        account: AccountId,
        address: &WalletAddress,
        at: SequenceNumber,
    ) -> Option<&WalletBinding> {
        self.index_of(account, address)
            .map(|i| &self.bindings[i])
            .filter(|b| b.is_active(at))
    }

    /// All active bindings for an account.
    pub fn wallets_for(&self, account: AccountId, at: SequenceNumber) -> Vec<&WalletBinding> {
        self.bindings
            .iter()
            .filter(|b| b.account == account && b.is_active(at))
            .collect()
    }

    /// The account's active master wallet, if one is designated.
    pub fn master(&self, account: AccountId, at: SequenceNumber) -> Option<&WalletBinding> {
        self.bindings
            .iter()
            .find(|b| b.account == account && b.is_master && b.is_active(at))
    }

    /// Authorize a withdrawal via a bound wallet.
    ///
    /// Succeeds only when the wallet is actively bound, flagged
    /// `withdrawals_allowed`, the proof carries the bound key, and the proof
    /// verifies over `message`. This is the wallet-layer gate that must pass
    /// before the custody signer set is consulted.
    pub fn authorize_withdrawal(
        &self,
        account: AccountId,
        address: &WalletAddress,
        proof: &WalletProof,
        message: &[u8],
        at: SequenceNumber,
    ) -> Result<(), CustodyError> {
        let binding = self
            .binding(account, address, at)
            .ok_or(CustodyError::UnknownWallet)?;
        if !binding.withdrawals_allowed {
            return Err(CustodyError::WithdrawalNotAllowed);
        }
        if proof.key() != binding.key {
            return Err(CustodyError::NotMaster);
        }
        proof.verify(message)
    }

    /// A deterministic commitment over all active bindings, order-independent.
    ///
    /// Two registries that consumed the same command set (in any order that
    /// produces the same active set) commit to the same root.
    pub fn state_root(&self) -> Hash {
        let mut leaves: Vec<Hash> = self
            .bindings
            .iter()
            .filter(|b| b.revoked_at.is_none())
            .map(binding_leaf)
            .collect();
        leaves.sort_unstable();
        let mut root = Hash::ZERO;
        for leaf in leaves {
            root = hash_node(root, leaf);
        }
        root
    }
}

fn binding_leaf(b: &WalletBinding) -> Hash {
    let mut w = Writer::new();
    w.u32(b.account.get());
    b.address.encode_into(&mut w);
    w.u8(u8::from(b.is_master));
    w.u8(u8::from(b.withdrawals_allowed));
    w.u64(b.bound_at.get());
    hash_leaf(&w.into_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::{EvmKeyPair, KeyPair};
    use k256::ecdsa::SigningKey;

    fn evm_uncompressed(seed: &[u8; 32]) -> Vec<u8> {
        let sk = SigningKey::from_slice(seed).unwrap();
        sk.verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    fn evm_bind(seed: &[u8; 32], account: u32, master: bool, wd: bool, nonce: u64) -> BindWallet {
        let uncompressed = evm_uncompressed(seed);
        let addr = evm_address_from_pubkey(&uncompressed).unwrap();
        let mut cmd = BindWallet {
            account: AccountId::new(account),
            address: WalletAddress::Evm(addr),
            is_master: master,
            withdrawals_allowed: wd,
            nonce,
            proof: WalletProof::Eip712 {
                public_key_sec1: uncompressed,
                signature: vec![0u8; 64],
            },
        };
        let kp = EvmKeyPair::from_seed(seed).unwrap();
        let sig = kp.sign_evm(&cmd.binding_message()).unwrap();
        if let WalletProof::Eip712 { signature, .. } = &mut cmd.proof {
            *signature = sig.to_vec();
        }
        cmd
    }

    fn svm_bind(seed: &[u8; 32], account: u32, wd: bool, nonce: u64) -> BindWallet {
        let kp = KeyPair::from_seed(seed);
        let pk = kp.public();
        let mut cmd = BindWallet {
            account: AccountId::new(account),
            address: WalletAddress::Svm(pk),
            is_master: false,
            withdrawals_allowed: wd,
            nonce,
            proof: WalletProof::Ed25519 {
                public_key: pk,
                signature: [0u8; 64],
            },
        };
        let sig = kp.sign(&cmd.binding_message());
        if let WalletProof::Ed25519 { signature, .. } = &mut cmd.proof {
            *signature = sig;
        }
        cmd
    }

    #[test]
    fn evm_bind_accepts_and_tamper_rejects() {
        let mut reg = WalletRegistry::new(4);
        let cmd = evm_bind(&[1u8; 32], 1, true, true, 0);
        assert!(reg.bind(&cmd, SequenceNumber::new(1)).is_ok());

        // Tampered signature is rejected.
        let mut bad = evm_bind(&[2u8; 32], 2, true, true, 0);
        if let WalletProof::Eip712 { signature, .. } = &mut bad.proof {
            signature[0] ^= 1;
        }
        assert_eq!(
            reg.bind(&bad, SequenceNumber::new(2)),
            Err(CustodyError::InvalidSignature)
        );
    }

    #[test]
    fn evm_address_mismatch_rejected() {
        let mut reg = WalletRegistry::new(4);
        let mut cmd = evm_bind(&[1u8; 32], 1, true, true, 0);
        cmd.address = WalletAddress::Evm([0xAA; 20]); // wrong address
                                                      // re-sign over the (now different) message so the sig is valid but addr wrong
        let kp = EvmKeyPair::from_seed(&[1u8; 32]).unwrap();
        let sig = kp.sign_evm(&cmd.binding_message()).unwrap();
        if let WalletProof::Eip712 { signature, .. } = &mut cmd.proof {
            *signature = sig.to_vec();
        }
        assert_eq!(
            reg.bind(&cmd, SequenceNumber::new(1)),
            Err(CustodyError::AddressMismatch)
        );
    }

    #[test]
    fn solana_bind_accepts_and_tamper_rejects() {
        let mut reg = WalletRegistry::new(4);
        let cmd = svm_bind(&[5u8; 32], 7, true, 0);
        assert!(reg.bind(&cmd, SequenceNumber::new(1)).is_ok());

        let mut bad = svm_bind(&[6u8; 32], 8, true, 0);
        if let WalletProof::Ed25519 { signature, .. } = &mut bad.proof {
            signature[0] ^= 1;
        }
        assert!(reg.bind(&bad, SequenceNumber::new(2)).is_err());
    }

    #[test]
    fn multi_wallet_binding_and_only_flagged_wallet_authorizes_withdrawal() {
        let mut reg = WalletRegistry::new(4);
        let master = evm_bind(&[1u8; 32], 1, true, false, 0); // master, NO withdrawals
        let hot = svm_bind(&[2u8; 32], 1, true, 1); // withdrawals allowed
        reg.bind(&master, SequenceNumber::new(1)).unwrap();
        reg.bind(&hot, SequenceNumber::new(2)).unwrap();
        assert_eq!(
            reg.wallets_for(AccountId::new(1), SequenceNumber::new(3))
                .len(),
            2
        );

        // A withdrawal message signed by the hot wallet is authorized.
        let msg = b"withdraw-1";
        let kp = KeyPair::from_seed(&[2u8; 32]);
        let proof = WalletProof::Ed25519 {
            public_key: kp.public(),
            signature: kp.sign(msg),
        };
        let hot_addr = WalletAddress::Svm(kp.public());
        assert!(reg
            .authorize_withdrawal(
                AccountId::new(1),
                &hot_addr,
                &proof,
                msg,
                SequenceNumber::new(3)
            )
            .is_ok());

        // The master wallet is NOT flagged for withdrawals -> rejected.
        let master_addr = master.address;
        let mkp = EvmKeyPair::from_seed(&[1u8; 32]).unwrap();
        let mproof = WalletProof::Eip712 {
            public_key_sec1: evm_uncompressed(&[1u8; 32]),
            signature: mkp.sign_evm(msg).unwrap().to_vec(),
        };
        assert_eq!(
            reg.authorize_withdrawal(
                AccountId::new(1),
                &master_addr,
                &mproof,
                msg,
                SequenceNumber::new(3)
            ),
            Err(CustodyError::WithdrawalNotAllowed)
        );
    }

    #[test]
    fn duplicate_replay_cap_and_revoke() {
        let mut reg = WalletRegistry::new(1);
        let cmd = evm_bind(&[1u8; 32], 1, true, true, 0);
        reg.bind(&cmd, SequenceNumber::new(1)).unwrap();

        // Same (account,nonce) replayed.
        assert_eq!(
            reg.bind(&cmd, SequenceNumber::new(2)),
            Err(CustodyError::ReplayedBinding)
        );

        // A second distinct wallet exceeds the cap of 1.
        let second = svm_bind(&[9u8; 32], 1, true, 1);
        assert_eq!(
            reg.bind(&second, SequenceNumber::new(3)),
            Err(CustodyError::BindingCapExceeded)
        );

        // Revoke frees the slot; the same wallet cannot be re-bound with an old
        // nonce, but a fresh nonce works.
        reg.revoke(cmd.account, &cmd.address, SequenceNumber::new(4))
            .unwrap();
        let readd = evm_bind(&[1u8; 32], 1, true, true, 2);
        assert!(reg.bind(&readd, SequenceNumber::new(5)).is_ok());
    }

    #[test]
    fn deterministic_replay_yields_identical_state_root() {
        let cmds = [
            evm_bind(&[1u8; 32], 1, true, true, 0),
            svm_bind(&[2u8; 32], 1, false, 1),
            evm_bind(&[3u8; 32], 2, true, false, 2),
        ];
        // Two independent instances replaying the identical command+sequence
        // stream must commit to the same state root.
        let replay = || {
            let mut reg = WalletRegistry::new(8);
            for (s, cmd) in cmds.iter().enumerate() {
                let seq = SequenceNumber::new(u64::try_from(s).unwrap() + 1);
                reg.bind(cmd, seq).unwrap();
            }
            reg.state_root()
        };
        assert_eq!(replay(), replay());
        // A revoked binding drops out of the committed root.
        let mut reg = WalletRegistry::new(8);
        for (s, cmd) in cmds.iter().enumerate() {
            reg.bind(cmd, SequenceNumber::new(u64::try_from(s).unwrap() + 1))
                .unwrap();
        }
        let before = reg.state_root();
        reg.revoke(cmds[1].account, &cmds[1].address, SequenceNumber::new(10))
            .unwrap();
        assert_ne!(before, reg.state_root());
    }

    #[test]
    fn decode_never_panics_on_arbitrary_bytes() {
        let mut state = 0x1234_5678u64;
        for _ in 0..20_000 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let len = usize::try_from(state % 96).unwrap();
            let bytes: Vec<u8> = (0..len)
                .map(|_| {
                    state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                    state.to_le_bytes()[0]
                })
                .collect();
            let _ = BindWallet::decode(&bytes);
        }
    }

    #[test]
    fn bind_command_round_trips() {
        let cmd = evm_bind(&[4u8; 32], 3, true, true, 42);
        let bytes = cmd.encode().unwrap();
        assert_eq!(BindWallet::decode(&bytes).unwrap(), cmd);
        let svm = svm_bind(&[8u8; 32], 4, true, 7);
        let bytes = svm.encode().unwrap();
        assert_eq!(BindWallet::decode(&bytes).unwrap(), svm);
    }
}
