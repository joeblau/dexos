//! Binding external EVM/SVM wallets to an internal [`AccountId`].
//!
//! A [`BindWallet`] command carries a [`WalletProof`] — an EIP-712 secp256k1
//! signature, an EIP-1271 smart-wallet signature, or a Solana ed25519 signature
//! — over a domain-separated binding message that proves *control* of the new
//! wallet. Control alone is not authority: attaching a wallet to an account is a
//! privileged act, so the authorization model is:
//!
//! - The **first** wallet of an account is its master, and is established
//!   atomically with authenticated account creation via
//!   [`WalletRegistry::establish_master`]. This is the *only* path that
//!   introduces an account into the registry, so an account can never exist with
//!   wallets but no master, and a wallet can never make itself the master of an
//!   account that already has one.
//! - Every **later** mutation — binding another wallet, changing a wallet's
//!   privileges, revoking a wallet, or rotating the master — requires a fresh
//!   signature from the account's *current* master over a domain-separated
//!   authorization message, with a per-account nonce consumed atomically so the
//!   authorization cannot be replayed.
//!
//! Cross-account uniqueness: a wallet address is permanently owned by the first
//! account that binds it and can never be bound to a different account, even
//! after it is revoked. Master designation and the `withdrawals_allowed` flag
//! drive the withdrawal-authorization policy. All mutations are deterministic
//! and the full binding history (including revoked bindings and current
//! privileges) is committed by [`WalletRegistry::state_root`], so snapshot and
//! replay reproduce an identical state.

use std::collections::{BTreeMap, BTreeSet};

use crypto::{hash_leaf, hash_node, verify_ed25519, verify_eip1271, verify_secp256k1_evm};
use types::{AccountId, Hash, SequenceNumber};

use crate::chain::{evm_address_from_pubkey, ChainKind, WalletAddress};
use crate::error::CustodyError;
use crate::wire::{Reader, Writer};

/// Domain tag separating binding messages from every other signed payload.
pub const BIND_DOMAIN: &[u8] = b"DEXOS/BIND-WALLET/v1";

/// Domain tag separating a current-master authorization (over a later bind,
/// privilege change, revoke, or rotation) from every other signed payload.
pub const BIND_AUTH_DOMAIN: &[u8] = b"DEXOS/BIND-AUTH/v1";

// Operation tags fixing the shape of a master authorization message.
const OP_BIND: u8 = 1;
const OP_REVOKE: u8 = 2;
const OP_SET_PRIVILEGES: u8 = 3;
const OP_ROTATE: u8 = 4;

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
    /// EIP-1271: smart-wallet authorization modeled as the owner secp256k1 key,
    /// bound to the contract address (see [`crypto::verify_eip1271`] trust model).
    Eip1271 {
        /// Smart-wallet contract address (20 bytes); must equal the bound wallet.
        contract_address: [u8; 20],
        /// SEC1 owner public key.
        owner_public_key_sec1: Vec<u8>,
        /// 64-byte `r || s` low-S signature.
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
    ///
    /// For [`Self::Eip1271`], `claimed_address` must be supplied as the EVM
    /// wallet address being bound; verification fails if it disagrees with the
    /// proof's `contract_address`.
    pub fn verify(&self, message: &[u8]) -> Result<(), CustodyError> {
        match self {
            Self::Eip712 {
                public_key_sec1,
                signature,
            } => Ok(verify_secp256k1_evm(public_key_sec1, message, signature)?),
            Self::Eip1271 {
                contract_address,
                owner_public_key_sec1,
                signature,
            } => {
                // Without a claimed address, still require contract self-binding
                // (contract == contract) and a valid owner signature.
                Ok(verify_eip1271(
                    contract_address,
                    contract_address,
                    owner_public_key_sec1,
                    message,
                    signature,
                )?)
            }
            Self::Ed25519 {
                public_key,
                signature,
            } => Ok(verify_ed25519(public_key, message, signature)?),
        }
    }

    /// Verify, binding an EIP-1271 proof to `claimed_evm` when present.
    pub fn verify_for_address(
        &self,
        message: &[u8],
        claimed_evm: Option<&[u8; 20]>,
    ) -> Result<(), CustodyError> {
        match self {
            Self::Eip1271 {
                contract_address,
                owner_public_key_sec1,
                signature,
            } => {
                let claimed = claimed_evm.ok_or(CustodyError::AddressMismatch)?;
                Ok(verify_eip1271(
                    contract_address,
                    claimed,
                    owner_public_key_sec1,
                    message,
                    signature,
                )?)
            }
            _ => self.verify(message),
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
                contract_address,
                owner_public_key_sec1,
                signature,
            } => {
                w.u8(PROOF_EIP1271);
                w.raw(contract_address);
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
                contract_address: r.array::<20>()?,
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
///
/// The [`proof`](Self::proof) is the *new wallet's own* signature and proves
/// control of the wallet. It does not by itself authorize attaching to an
/// account: [`WalletRegistry::establish_master`] accepts it only for a brand-new
/// account's genesis master, and [`WalletRegistry::bind`] additionally requires
/// the account's current master to authorize the command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindWallet {
    /// The internal account to bind to.
    pub account: AccountId,
    /// The external wallet address.
    pub address: WalletAddress,
    /// Whether this wallet is the account's master (control) wallet. Only the
    /// genesis binding may set this; later masters are designated by rotation.
    pub is_master: bool,
    /// Whether this wallet may authorize withdrawals.
    pub withdrawals_allowed: bool,
    /// A per-account nonce. For the genesis master it guards the establishing
    /// command; for a later bind it is the authorizing master's nonce. A given
    /// `(account, nonce)` is consumed at most once across every operation.
    pub nonce: u64,
    /// Proof of control over the new wallet.
    pub proof: WalletProof,
}

impl BindWallet {
    /// The canonical message the new wallet must sign to prove control.
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

/// The canonical message a current master signs to authorize binding a new
/// wallet with the given privileges. Callers have the master sign this; the
/// registry re-derives and verifies it inside [`WalletRegistry::bind`].
pub fn bind_authorization_message(
    account: AccountId,
    nonce: u64,
    address: &WalletAddress,
    withdrawals_allowed: bool,
) -> Vec<u8> {
    auth_message(account, nonce, OP_BIND, |w| {
        address.encode_into(w);
        w.u8(u8::from(withdrawals_allowed));
    })
}

/// The canonical message a current master signs to authorize revoking a wallet.
pub fn revoke_authorization_message(
    account: AccountId,
    nonce: u64,
    address: &WalletAddress,
) -> Vec<u8> {
    auth_message(account, nonce, OP_REVOKE, |w| address.encode_into(w))
}

/// The canonical message a current master signs to authorize changing a
/// wallet's `withdrawals_allowed` privilege.
pub fn set_privileges_authorization_message(
    account: AccountId,
    nonce: u64,
    address: &WalletAddress,
    withdrawals_allowed: bool,
) -> Vec<u8> {
    auth_message(account, nonce, OP_SET_PRIVILEGES, |w| {
        address.encode_into(w);
        w.u8(u8::from(withdrawals_allowed));
    })
}

/// The canonical message a current master signs to authorize rotating the
/// master designation to another already-bound wallet.
pub fn rotate_master_authorization_message(
    account: AccountId,
    nonce: u64,
    new_master: &WalletAddress,
) -> Vec<u8> {
    auth_message(account, nonce, OP_ROTATE, |w| new_master.encode_into(w))
}

fn auth_message(
    account: AccountId,
    nonce: u64,
    op_tag: u8,
    body: impl FnOnce(&mut Writer),
) -> Vec<u8> {
    let mut w = Writer::new();
    w.raw(BIND_AUTH_DOMAIN);
    w.u32(account.get());
    w.u64(nonce);
    w.u8(op_tag);
    body(&mut w);
    w.into_vec()
}

fn address_key(address: &WalletAddress) -> Vec<u8> {
    let mut w = Writer::new();
    address.encode_into(&mut w);
    w.into_vec()
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
    /// Whether this is the account's master wallet (current designation).
    pub is_master: bool,
    /// Whether this wallet may authorize withdrawals (current privilege).
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
/// The first wallet of an account is established as its master atomically with
/// authenticated account creation ([`establish_master`]); every later mutation
/// requires the current master's authorization and consumes a per-account nonce
/// ([`bind`], [`set_privileges`], [`revoke`], [`rotate_master`]). A wallet
/// address is permanently owned by the first account that binds it. All
/// mutations are deterministic, so replaying the same command sequence on two
/// instances yields an identical [`state_root`] that commits the full binding
/// history and current privileges.
///
/// [`establish_master`]: WalletRegistry::establish_master
/// [`bind`]: WalletRegistry::bind
/// [`set_privileges`]: WalletRegistry::set_privileges
/// [`revoke`]: WalletRegistry::revoke
/// [`rotate_master`]: WalletRegistry::rotate_master
/// [`state_root`]: WalletRegistry::state_root
#[derive(Debug, Clone)]
pub struct WalletRegistry {
    max_per_account: usize,
    bindings: Vec<WalletBinding>,
    used_nonces: BTreeSet<(u32, u64)>,
    /// Canonical address bytes -> owning account. A wallet address is owned by
    /// the first account that binds it and may never migrate to another.
    address_owner: BTreeMap<Vec<u8>, u32>,
}

impl WalletRegistry {
    /// A new registry allowing at most `max_per_account` active wallets each.
    pub fn new(max_per_account: usize) -> Self {
        Self {
            max_per_account,
            bindings: Vec::new(),
            used_nonces: BTreeSet::new(),
            address_owner: BTreeMap::new(),
        }
    }

    fn active_index_of(
        &self,
        account: AccountId,
        address: &WalletAddress,
        at: SequenceNumber,
    ) -> Option<usize> {
        self.bindings
            .iter()
            .position(|b| b.account == account && &b.address == address && b.is_active(at))
    }

    fn active_master_index(&self, account: AccountId, at: SequenceNumber) -> Option<usize> {
        self.bindings
            .iter()
            .position(|b| b.account == account && b.is_master && b.is_active(at))
    }

    /// Reject binding an address that is already owned by a different account.
    fn check_cross_account(
        &self,
        account: AccountId,
        address: &WalletAddress,
    ) -> Result<(), CustodyError> {
        if let Some(&owner) = self.address_owner.get(&address_key(address)) {
            if owner != account.get() {
                return Err(CustodyError::CrossAccountReuse);
            }
        }
        Ok(())
    }

    /// Verify the new wallet's own proof of control and that its declared address
    /// is consistent with the proof and chain family.
    fn verify_control(&self, cmd: &BindWallet) -> Result<(), CustodyError> {
        let message = cmd.binding_message();
        match (&cmd.address, &cmd.proof) {
            (
                WalletAddress::Evm(addr),
                WalletProof::Eip712 {
                    public_key_sec1, ..
                },
            ) => {
                cmd.proof.verify(&message)?;
                let derived = evm_address_from_pubkey(public_key_sec1)?;
                if &derived != addr {
                    return Err(CustodyError::AddressMismatch);
                }
            }
            (
                WalletAddress::Evm(addr),
                WalletProof::Eip1271 {
                    contract_address, ..
                },
            ) => {
                // Contract address is bound into the proof and must equal the
                // claimed wallet address (owner key alone is insufficient).
                cmd.proof.verify_for_address(&message, Some(addr))?;
                if contract_address != addr {
                    return Err(CustodyError::ContractAddressMismatch);
                }
            }
            (WalletAddress::Svm(addr), WalletProof::Ed25519 { public_key, .. }) => {
                cmd.proof.verify(&message)?;
                if addr != public_key {
                    return Err(CustodyError::AddressMismatch);
                }
            }
            _ => return Err(CustodyError::MalformedAddress),
        }
        Ok(())
    }

    /// Verify that `master_proof` is the account's current active master and
    /// that it signed `message`. Read-only: consuming the nonce and applying the
    /// mutation is the caller's final, atomic step.
    fn verify_master_authorization(
        &self,
        account: AccountId,
        master_proof: &WalletProof,
        message: &[u8],
        at: SequenceNumber,
    ) -> Result<(), CustodyError> {
        let master = self
            .active_master_index(account, at)
            .map(|i| &self.bindings[i])
            .ok_or(CustodyError::NotMaster)?;
        if master_proof.key() != master.key {
            return Err(CustodyError::NotMaster);
        }
        master_proof.verify(message)
    }

    /// Establish the account's genesis master wallet.
    ///
    /// This is the sole path that introduces an account into the registry and is
    /// meant to run atomically with authenticated account creation. It succeeds
    /// only when the account has no existing binding, the command designates a
    /// master, the new wallet proves control of itself, the address is not owned
    /// by another account, and the nonce is fresh. There is therefore no way to
    /// obtain an account with wallets but no master, and no way for a wallet to
    /// make itself master of an account that already exists.
    pub fn establish_master(
        &mut self,
        cmd: &BindWallet,
        seq: SequenceNumber,
    ) -> Result<(), CustodyError> {
        if self.bindings.iter().any(|b| b.account == cmd.account) {
            return Err(CustodyError::AccountAlreadyEstablished);
        }
        if !cmd.is_master {
            return Err(CustodyError::MasterRequired);
        }
        let nonce_key = (cmd.account.get(), cmd.nonce);
        if self.used_nonces.contains(&nonce_key) {
            return Err(CustodyError::ReplayedBinding);
        }
        self.verify_control(cmd)?;
        self.check_cross_account(cmd.account, &cmd.address)?;

        self.commit_binding(cmd, seq);
        Ok(())
    }

    /// Bind an additional (non-master) wallet, authorized by the current master.
    ///
    /// The account must already have an active master whose key matches
    /// `master_proof`, and `master_proof` must sign the
    /// [`bind_authorization_message`] for this command. The new wallet must also
    /// prove control of itself. A wallet cannot attach to an existing account
    /// using only its own signature, and cannot make itself master here — the
    /// master is changed only by [`rotate_master`](Self::rotate_master).
    pub fn bind(
        &mut self,
        cmd: &BindWallet,
        master_proof: &WalletProof,
        seq: SequenceNumber,
    ) -> Result<(), CustodyError> {
        if cmd.is_master {
            // Binding never creates a second master; the account already has one.
            return Err(CustodyError::AccountAlreadyEstablished);
        }
        let nonce_key = (cmd.account.get(), cmd.nonce);
        if self.used_nonces.contains(&nonce_key) {
            return Err(CustodyError::ReplayedBinding);
        }

        // The current master must authorize this exact wallet + privileges.
        let auth = bind_authorization_message(
            cmd.account,
            cmd.nonce,
            &cmd.address,
            cmd.withdrawals_allowed,
        );
        self.verify_master_authorization(cmd.account, master_proof, &auth, seq)?;

        // The new wallet must prove control of itself.
        self.verify_control(cmd)?;

        // Cross-account reuse and structural limits.
        self.check_cross_account(cmd.account, &cmd.address)?;
        if self
            .active_index_of(cmd.account, &cmd.address, seq)
            .is_some()
        {
            return Err(CustodyError::DuplicateBinding);
        }
        let active = self
            .bindings
            .iter()
            .filter(|b| b.account == cmd.account && b.is_active(seq))
            .count();
        if active >= self.max_per_account {
            return Err(CustodyError::BindingCapExceeded);
        }

        self.commit_binding(cmd, seq);
        Ok(())
    }

    /// Insert a verified binding and record its nonce and address ownership.
    fn commit_binding(&mut self, cmd: &BindWallet, seq: SequenceNumber) {
        self.used_nonces.insert((cmd.account.get(), cmd.nonce));
        self.address_owner
            .entry(address_key(&cmd.address))
            .or_insert(cmd.account.get());
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
    }

    /// Change a bound wallet's `withdrawals_allowed` privilege, authorized by the
    /// current master over the [`set_privileges_authorization_message`].
    pub fn set_privileges(
        &mut self,
        account: AccountId,
        address: &WalletAddress,
        withdrawals_allowed: bool,
        master_proof: &WalletProof,
        nonce: u64,
        seq: SequenceNumber,
    ) -> Result<(), CustodyError> {
        let nonce_key = (account.get(), nonce);
        if self.used_nonces.contains(&nonce_key) {
            return Err(CustodyError::ReplayedBinding);
        }
        let i = self
            .active_index_of(account, address, seq)
            .ok_or(CustodyError::UnknownWallet)?;
        let auth =
            set_privileges_authorization_message(account, nonce, address, withdrawals_allowed);
        self.verify_master_authorization(account, master_proof, &auth, seq)?;

        self.used_nonces.insert(nonce_key);
        self.bindings[i].withdrawals_allowed = withdrawals_allowed;
        Ok(())
    }

    /// Revoke an active binding, authorized by the current master over the
    /// [`revoke_authorization_message`] with an atomically consumed nonce.
    ///
    /// The active master cannot be revoked directly (that would leave the account
    /// master-less); rotate the master first with
    /// [`rotate_master`](Self::rotate_master).
    pub fn revoke(
        &mut self,
        account: AccountId,
        address: &WalletAddress,
        master_proof: &WalletProof,
        nonce: u64,
        seq: SequenceNumber,
    ) -> Result<(), CustodyError> {
        let nonce_key = (account.get(), nonce);
        if self.used_nonces.contains(&nonce_key) {
            return Err(CustodyError::ReplayedBinding);
        }
        let i = self
            .active_index_of(account, address, seq)
            .ok_or(CustodyError::UnknownWallet)?;
        if self.bindings[i].is_master {
            return Err(CustodyError::MasterNotRevocable);
        }
        let auth = revoke_authorization_message(account, nonce, address);
        self.verify_master_authorization(account, master_proof, &auth, seq)?;

        self.used_nonces.insert(nonce_key);
        self.bindings[i].revoked_at = Some(seq);
        Ok(())
    }

    /// Rotate the master designation to another already-bound, active wallet of
    /// the account, authorized by the *current* master over the
    /// [`rotate_master_authorization_message`] with an atomically consumed nonce.
    pub fn rotate_master(
        &mut self,
        account: AccountId,
        new_master: &WalletAddress,
        master_proof: &WalletProof,
        nonce: u64,
        seq: SequenceNumber,
    ) -> Result<(), CustodyError> {
        let nonce_key = (account.get(), nonce);
        if self.used_nonces.contains(&nonce_key) {
            return Err(CustodyError::ReplayedBinding);
        }
        let cur = self
            .active_master_index(account, seq)
            .ok_or(CustodyError::NotMaster)?;
        let new_i = self
            .active_index_of(account, new_master, seq)
            .ok_or(CustodyError::UnknownWallet)?;
        let auth = rotate_master_authorization_message(account, nonce, new_master);
        self.verify_master_authorization(account, master_proof, &auth, seq)?;

        self.used_nonces.insert(nonce_key);
        self.bindings[cur].is_master = false;
        self.bindings[new_i].is_master = true;
        Ok(())
    }

    /// The active binding for a wallet, if any.
    pub fn binding(
        &self,
        account: AccountId,
        address: &WalletAddress,
        at: SequenceNumber,
    ) -> Option<&WalletBinding> {
        self.active_index_of(account, address, at)
            .map(|i| &self.bindings[i])
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
        self.active_master_index(account, at)
            .map(|i| &self.bindings[i])
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

    /// A deterministic commitment over the full binding history, order-independent.
    ///
    /// Every binding — active or revoked — contributes a leaf that commits its
    /// current privileges (`is_master`, `withdrawals_allowed`) and lifecycle
    /// (`bound_at`, `revoked_at`). Two registries that consumed the same command
    /// stream commit to the same root, so snapshot and replay agree.
    pub fn state_root(&self) -> Hash {
        let mut leaves: Vec<Hash> = self.bindings.iter().map(binding_leaf).collect();
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
    match b.revoked_at {
        None => w.u8(0),
        Some(s) => {
            w.u8(1);
            w.u64(s.get());
        }
    }
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

    fn evm_addr(seed: &[u8; 32]) -> WalletAddress {
        WalletAddress::Evm(evm_address_from_pubkey(&evm_uncompressed(seed)).unwrap())
    }

    /// Build a `BindWallet` whose `proof` is the new EVM wallet's own signature.
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

    /// A master proof (EVM) over an arbitrary authorization `message`.
    fn evm_master_proof(seed: &[u8; 32], message: &[u8]) -> WalletProof {
        let kp = EvmKeyPair::from_seed(seed).unwrap();
        WalletProof::Eip712 {
            public_key_sec1: evm_uncompressed(seed),
            signature: kp.sign_evm(message).unwrap().to_vec(),
        }
    }

    /// A registry with account `account`'s master established from `master_seed`.
    fn with_master(master_seed: &[u8; 32], account: u32, max: usize) -> WalletRegistry {
        let mut reg = WalletRegistry::new(max);
        let genesis = evm_bind(master_seed, account, true, false, 0);
        reg.establish_master(&genesis, SequenceNumber::new(1))
            .unwrap();
        reg
    }

    #[test]
    fn establish_master_accepts_genesis_and_tamper_rejects() {
        let mut reg = WalletRegistry::new(4);
        let cmd = evm_bind(&[1u8; 32], 1, true, true, 0);
        assert!(reg.establish_master(&cmd, SequenceNumber::new(1)).is_ok());

        // Tampered self-signature is rejected on a fresh account.
        let mut bad = evm_bind(&[2u8; 32], 2, true, true, 0);
        if let WalletProof::Eip712 { signature, .. } = &mut bad.proof {
            signature[0] ^= 1;
        }
        assert_eq!(
            reg.establish_master(&bad, SequenceNumber::new(2)),
            Err(CustodyError::InvalidSignature)
        );
    }

    #[test]
    fn establish_master_is_genesis_only() {
        let mut reg = with_master(&[1u8; 32], 1, 4);
        // A second establish on the same account is rejected: the first binding
        // cannot be separated from (repeated for) an already-created account.
        let again = evm_bind(&[9u8; 32], 1, true, false, 5);
        assert_eq!(
            reg.establish_master(&again, SequenceNumber::new(2)),
            Err(CustodyError::AccountAlreadyEstablished)
        );
        // The genesis binding must designate a master.
        let mut reg2 = WalletRegistry::new(4);
        let non_master = evm_bind(&[3u8; 32], 2, false, false, 0);
        assert_eq!(
            reg2.establish_master(&non_master, SequenceNumber::new(1)),
            Err(CustodyError::MasterRequired)
        );
    }

    #[test]
    fn wallet_cannot_attach_to_existing_account_with_only_its_own_signature() {
        // Account 1 is established with master seed [1].
        let mut reg = with_master(&[1u8; 32], 1, 4);
        // A different wallet attempts to bind itself to account 1 supplying only
        // its OWN proof as the "master" authorization. It is not the master, so
        // the authorization fails.
        let intruder = evm_bind(&[2u8; 32], 1, false, true, 2);
        let self_proof = intruder.proof.clone();
        assert_eq!(
            reg.bind(&intruder, &self_proof, SequenceNumber::new(3)),
            Err(CustodyError::NotMaster)
        );
        // It also cannot re-establish the account as its own master.
        let usurp = evm_bind(&[2u8; 32], 1, true, true, 7);
        assert_eq!(
            reg.establish_master(&usurp, SequenceNumber::new(3)),
            Err(CustodyError::AccountAlreadyEstablished)
        );
    }

    #[test]
    fn first_binding_requires_established_account() {
        // With no master established, binding a wallet is impossible: the first
        // wallet can only arrive through establish_master.
        let mut reg = WalletRegistry::new(4);
        let cmd = svm_bind(&[5u8; 32], 7, true, 0);
        let proof = cmd.proof.clone();
        assert_eq!(
            reg.bind(&cmd, &proof, SequenceNumber::new(1)),
            Err(CustodyError::NotMaster)
        );
    }

    #[test]
    fn bind_requires_current_master_authorization() {
        let mut reg = with_master(&[1u8; 32], 1, 4);
        let new_wallet = svm_bind(&[2u8; 32], 1, true, 2);

        // A correct master authorization over the exact command succeeds.
        let auth = bind_authorization_message(
            AccountId::new(1),
            new_wallet.nonce,
            &new_wallet.address,
            new_wallet.withdrawals_allowed,
        );
        let master_proof = evm_master_proof(&[1u8; 32], &auth);
        assert!(reg
            .bind(&new_wallet, &master_proof, SequenceNumber::new(2))
            .is_ok());

        // Replaying the same master nonce is rejected.
        let other = svm_bind(&[3u8; 32], 1, true, 2);
        let auth2 = bind_authorization_message(
            AccountId::new(1),
            other.nonce,
            &other.address,
            other.withdrawals_allowed,
        );
        let mp2 = evm_master_proof(&[1u8; 32], &auth2);
        assert_eq!(
            reg.bind(&other, &mp2, SequenceNumber::new(3)),
            Err(CustodyError::ReplayedBinding)
        );

        // A tampered master signature over a fresh nonce is rejected.
        let other3 = svm_bind(&[4u8; 32], 1, true, 3);
        let auth3 = bind_authorization_message(
            AccountId::new(1),
            other3.nonce,
            &other3.address,
            other3.withdrawals_allowed,
        );
        let mut bad_master = evm_master_proof(&[1u8; 32], &auth3);
        if let WalletProof::Eip712 { signature, .. } = &mut bad_master {
            signature[0] ^= 1;
        }
        assert_eq!(
            reg.bind(&other3, &bad_master, SequenceNumber::new(4)),
            Err(CustodyError::InvalidSignature)
        );
    }

    #[test]
    fn bind_rejects_authorization_for_a_different_wallet() {
        let mut reg = with_master(&[1u8; 32], 1, 4);
        // Master authorizes binding wallet A ...
        let wallet_a = svm_bind(&[2u8; 32], 1, true, 2);
        let auth_a = bind_authorization_message(
            AccountId::new(1),
            wallet_a.nonce,
            &wallet_a.address,
            wallet_a.withdrawals_allowed,
        );
        let proof_for_a = evm_master_proof(&[1u8; 32], &auth_a);
        // ... but the command actually names wallet B (same nonce). The proof does
        // not cover B's message, so it fails to verify.
        let wallet_b = svm_bind(&[3u8; 32], 1, true, 2);
        assert_eq!(
            reg.bind(&wallet_b, &proof_for_a, SequenceNumber::new(2)),
            Err(CustodyError::InvalidSignature)
        );
    }

    fn master_bind(reg: &mut WalletRegistry, master_seed: &[u8; 32], cmd: &BindWallet, seq: u64) {
        let auth = bind_authorization_message(
            cmd.account,
            cmd.nonce,
            &cmd.address,
            cmd.withdrawals_allowed,
        );
        let mp = evm_master_proof(master_seed, &auth);
        reg.bind(cmd, &mp, SequenceNumber::new(seq)).unwrap();
    }

    #[test]
    fn cross_account_reuse_rejected() {
        // Account 1 owns wallet W (seed [7]) as a bound wallet.
        let mut reg = with_master(&[1u8; 32], 1, 4);
        let wallet = svm_bind(&[7u8; 32], 1, false, 2);
        master_bind(&mut reg, &[1u8; 32], &wallet, 2);

        // Account 2 exists with its own master and tries to bind the same W.
        let genesis2 = evm_bind(&[2u8; 32], 2, true, false, 0);
        reg.establish_master(&genesis2, SequenceNumber::new(3))
            .unwrap();
        let reused = svm_bind(&[7u8; 32], 2, false, 1);
        let auth = bind_authorization_message(
            AccountId::new(2),
            reused.nonce,
            &reused.address,
            reused.withdrawals_allowed,
        );
        let mp2 = evm_master_proof(&[2u8; 32], &auth);
        assert_eq!(
            reg.bind(&reused, &mp2, SequenceNumber::new(4)),
            Err(CustodyError::CrossAccountReuse)
        );

        // Even establishing account 3's master from W's address is rejected.
        let mut genesis3 = svm_bind(&[7u8; 32], 3, false, 0);
        genesis3.is_master = true;
        // re-sign after flipping is_master
        let kp = KeyPair::from_seed(&[7u8; 32]);
        let g3_msg = genesis3.binding_message();
        if let WalletProof::Ed25519 { signature, .. } = &mut genesis3.proof {
            *signature = kp.sign(&g3_msg);
        }
        assert_eq!(
            reg.establish_master(&genesis3, SequenceNumber::new(5)),
            Err(CustodyError::CrossAccountReuse)
        );
    }

    #[test]
    fn cap_and_duplicate_enforced_under_master_authorization() {
        let mut reg = with_master(&[1u8; 32], 1, 2); // master + at most 2 active
        let w1 = svm_bind(&[2u8; 32], 1, false, 2);
        master_bind(&mut reg, &[1u8; 32], &w1, 2);

        // Duplicate active (account, address) rejected.
        let dup = svm_bind(&[2u8; 32], 1, false, 3);
        let auth = bind_authorization_message(
            AccountId::new(1),
            dup.nonce,
            &dup.address,
            dup.withdrawals_allowed,
        );
        let mp = evm_master_proof(&[1u8; 32], &auth);
        assert_eq!(
            reg.bind(&dup, &mp, SequenceNumber::new(3)),
            Err(CustodyError::DuplicateBinding)
        );

        // A second distinct wallet fills the cap of 2 (master + w1).
        let w2 = svm_bind(&[4u8; 32], 1, false, 4);
        let auth2 = bind_authorization_message(
            AccountId::new(1),
            w2.nonce,
            &w2.address,
            w2.withdrawals_allowed,
        );
        let mp2 = evm_master_proof(&[1u8; 32], &auth2);
        assert_eq!(
            reg.bind(&w2, &mp2, SequenceNumber::new(4)),
            Err(CustodyError::BindingCapExceeded)
        );
    }

    #[test]
    fn revoke_requires_master_and_protects_the_master() {
        let mut reg = with_master(&[1u8; 32], 1, 4);
        let w1 = svm_bind(&[2u8; 32], 1, true, 2);
        master_bind(&mut reg, &[1u8; 32], &w1, 2);
        let acc = AccountId::new(1);

        // Revoking without a valid master proof fails.
        let bogus = svm_bind(&[8u8; 32], 1, false, 99).proof;
        assert_eq!(
            reg.revoke(acc, &w1.address, &bogus, 3, SequenceNumber::new(3)),
            Err(CustodyError::NotMaster)
        );

        // The active master cannot be revoked directly.
        let master_addr = evm_addr(&[1u8; 32]);
        let auth_m = revoke_authorization_message(acc, 3, &master_addr);
        let mp_m = evm_master_proof(&[1u8; 32], &auth_m);
        assert_eq!(
            reg.revoke(acc, &master_addr, &mp_m, 3, SequenceNumber::new(3)),
            Err(CustodyError::MasterNotRevocable)
        );

        // A master-authorized revoke of w1 succeeds and takes effect after seq.
        let auth = revoke_authorization_message(acc, 4, &w1.address);
        let mp = evm_master_proof(&[1u8; 32], &auth);
        reg.revoke(acc, &w1.address, &mp, 4, SequenceNumber::new(5))
            .unwrap();
        assert!(reg
            .binding(acc, &w1.address, SequenceNumber::new(6))
            .is_none());

        // Replaying the revoke nonce is rejected even for another op.
        let auth2 = revoke_authorization_message(acc, 4, &w1.address);
        let mp2 = evm_master_proof(&[1u8; 32], &auth2);
        assert_eq!(
            reg.revoke(acc, &w1.address, &mp2, 4, SequenceNumber::new(7)),
            Err(CustodyError::ReplayedBinding)
        );
    }

    #[test]
    fn set_privileges_requires_master() {
        let mut reg = with_master(&[1u8; 32], 1, 4);
        let w1 = svm_bind(&[2u8; 32], 1, false, 2); // withdrawals off
        master_bind(&mut reg, &[1u8; 32], &w1, 2);
        let acc = AccountId::new(1);

        // Without withdrawals allowed, authorize_withdrawal is rejected.
        let wkp = KeyPair::from_seed(&[2u8; 32]);
        let msg = b"wd";
        let wproof = WalletProof::Ed25519 {
            public_key: wkp.public(),
            signature: wkp.sign(msg),
        };
        assert_eq!(
            reg.authorize_withdrawal(acc, &w1.address, &wproof, msg, SequenceNumber::new(3)),
            Err(CustodyError::WithdrawalNotAllowed)
        );

        // A non-master cannot flip the privilege.
        let bogus = svm_bind(&[8u8; 32], 1, false, 50).proof;
        assert_eq!(
            reg.set_privileges(acc, &w1.address, true, &bogus, 5, SequenceNumber::new(3)),
            Err(CustodyError::NotMaster)
        );

        // The master enables withdrawals; now the wallet authorizes.
        let auth = set_privileges_authorization_message(acc, 5, &w1.address, true);
        let mp = evm_master_proof(&[1u8; 32], &auth);
        reg.set_privileges(acc, &w1.address, true, &mp, 5, SequenceNumber::new(4))
            .unwrap();
        assert!(reg
            .authorize_withdrawal(acc, &w1.address, &wproof, msg, SequenceNumber::new(5))
            .is_ok());
    }

    #[test]
    fn rotate_master_moves_designation_under_current_master() {
        let mut reg = with_master(&[1u8; 32], 1, 4);
        let w1 = svm_bind(&[2u8; 32], 1, false, 2);
        master_bind(&mut reg, &[1u8; 32], &w1, 2);
        let acc = AccountId::new(1);

        // Rotating to an unbound wallet fails.
        let unbound = svm_bind(&[6u8; 32], 1, false, 9).address;
        let auth_bad = rotate_master_authorization_message(acc, 3, &unbound);
        let mp_bad = evm_master_proof(&[1u8; 32], &auth_bad);
        assert_eq!(
            reg.rotate_master(acc, &unbound, &mp_bad, 3, SequenceNumber::new(3)),
            Err(CustodyError::UnknownWallet)
        );

        // The current master rotates the designation onto w1.
        let auth = rotate_master_authorization_message(acc, 4, &w1.address);
        let mp = evm_master_proof(&[1u8; 32], &auth);
        reg.rotate_master(acc, &w1.address, &mp, 4, SequenceNumber::new(4))
            .unwrap();
        assert_eq!(
            reg.master(acc, SequenceNumber::new(5)).unwrap().address,
            w1.address
        );

        // The OLD master can no longer authorize (a bind now needs the new master).
        let extra = svm_bind(&[7u8; 32], 1, false, 5);
        let auth_extra =
            bind_authorization_message(acc, extra.nonce, &extra.address, extra.withdrawals_allowed);
        let old_proof = evm_master_proof(&[1u8; 32], &auth_extra);
        assert_eq!(
            reg.bind(&extra, &old_proof, SequenceNumber::new(6)),
            Err(CustodyError::NotMaster)
        );

        // The new master (w1) authorizes it.
        let new_master_proof = {
            let kp = KeyPair::from_seed(&[2u8; 32]);
            WalletProof::Ed25519 {
                public_key: kp.public(),
                signature: kp.sign(&auth_extra),
            }
        };
        assert!(reg
            .bind(&extra, &new_master_proof, SequenceNumber::new(6))
            .is_ok());
    }

    #[test]
    fn deterministic_replay_commits_history_and_privileges() {
        // A scripted command stream: establish, bind, revoke, set-privileges.
        let replay = || {
            let mut reg = with_master(&[1u8; 32], 1, 8);
            let acc = AccountId::new(1);
            let w1 = svm_bind(&[2u8; 32], 1, false, 2);
            master_bind(&mut reg, &[1u8; 32], &w1, 2);
            let w2 = svm_bind(&[3u8; 32], 1, false, 3);
            master_bind(&mut reg, &[1u8; 32], &w2, 3);
            // Enable withdrawals on w2 (privilege change committed to the root).
            let auth = set_privileges_authorization_message(acc, 4, &w2.address, true);
            let mp = evm_master_proof(&[1u8; 32], &auth);
            reg.set_privileges(acc, &w2.address, true, &mp, 4, SequenceNumber::new(4))
                .unwrap();
            // Revoke w1 (history committed to the root).
            let auth_r = revoke_authorization_message(acc, 5, &w1.address);
            let mp_r = evm_master_proof(&[1u8; 32], &auth_r);
            reg.revoke(acc, &w1.address, &mp_r, 5, SequenceNumber::new(5))
                .unwrap();
            reg
        };
        // Two independent replays commit to the same root.
        let a = replay();
        let b = replay();
        assert_eq!(a.state_root(), b.state_root());
        // A clone (snapshot) commits to the same root as its source.
        assert_eq!(a.clone().state_root(), a.state_root());

        // Revocation changes the committed root (history is not silently dropped).
        let mut reg = with_master(&[1u8; 32], 1, 8);
        let w1 = svm_bind(&[2u8; 32], 1, false, 2);
        master_bind(&mut reg, &[1u8; 32], &w1, 2);
        let before = reg.state_root();
        let auth_r = revoke_authorization_message(AccountId::new(1), 5, &w1.address);
        let mp_r = evm_master_proof(&[1u8; 32], &auth_r);
        reg.revoke(
            AccountId::new(1),
            &w1.address,
            &mp_r,
            5,
            SequenceNumber::new(6),
        )
        .unwrap();
        assert_ne!(before, reg.state_root());
    }

    #[test]
    fn solana_genesis_master_accepts_and_tamper_rejects() {
        let mut reg = WalletRegistry::new(4);
        let kp = KeyPair::from_seed(&[5u8; 32]);
        let pk = kp.public();
        let mut cmd = BindWallet {
            account: AccountId::new(7),
            address: WalletAddress::Svm(pk),
            is_master: true,
            withdrawals_allowed: true,
            nonce: 0,
            proof: WalletProof::Ed25519 {
                public_key: pk,
                signature: [0u8; 64],
            },
        };
        let sig = kp.sign(&cmd.binding_message());
        if let WalletProof::Ed25519 { signature, .. } = &mut cmd.proof {
            *signature = sig;
        }
        assert!(reg.establish_master(&cmd, SequenceNumber::new(1)).is_ok());

        let mut bad = cmd.clone();
        if let WalletProof::Ed25519 { signature, .. } = &mut bad.proof {
            signature[0] ^= 1;
        }
        bad.account = AccountId::new(8);
        assert!(reg.establish_master(&bad, SequenceNumber::new(2)).is_err());
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
            reg.establish_master(&cmd, SequenceNumber::new(1)),
            Err(CustodyError::AddressMismatch)
        );
    }

    #[test]
    fn multi_wallet_binding_and_only_flagged_wallet_authorizes_withdrawal() {
        let mut reg = with_master(&[1u8; 32], 1, 4); // master, NO withdrawals
        let acc = AccountId::new(1);
        let hot = svm_bind(&[2u8; 32], 1, true, 2); // withdrawals allowed
        master_bind(&mut reg, &[1u8; 32], &hot, 2);
        assert_eq!(reg.wallets_for(acc, SequenceNumber::new(3)).len(), 2);

        // A withdrawal message signed by the hot wallet is authorized.
        let msg = b"withdraw-1";
        let kp = KeyPair::from_seed(&[2u8; 32]);
        let proof = WalletProof::Ed25519 {
            public_key: kp.public(),
            signature: kp.sign(msg),
        };
        assert!(reg
            .authorize_withdrawal(acc, &hot.address, &proof, msg, SequenceNumber::new(3))
            .is_ok());

        // The master wallet is NOT flagged for withdrawals -> rejected.
        let master_addr = evm_addr(&[1u8; 32]);
        let mkp = EvmKeyPair::from_seed(&[1u8; 32]).unwrap();
        let mproof = WalletProof::Eip712 {
            public_key_sec1: evm_uncompressed(&[1u8; 32]),
            signature: mkp.sign_evm(msg).unwrap().to_vec(),
        };
        assert_eq!(
            reg.authorize_withdrawal(acc, &master_addr, &mproof, msg, SequenceNumber::new(3)),
            Err(CustodyError::WithdrawalNotAllowed)
        );
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
