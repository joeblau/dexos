//! The custody controller: the authoritative state machine over the threshold
//! signer set.
//!
//! It owns the current [`SignerSet`], the consensus [`ValidatorSet`] used to
//! independently verify certificates, per-chain policies, cumulative pending
//! accounting, the set of already-signed withdrawal ids (duplicate-sign
//! prevention), emergency-halt state, and a running audit root over every
//! control and signing event.
//!
//! Two controllers driven by the same command stream produce an identical audit
//! root and an identical signed-withdrawal set.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crypto::{hash_leaf, hash_node, QuorumCertificate, ValidatorSet};
use types::{Amount, Hash, SequenceNumber};

use crate::binding::{WalletProof, WalletRegistry};
use crate::chain::{ChainId, WalletAddress};
use crate::error::CustodyError;
use crate::policy::ChainPolicy;
use crate::session::SessionRegistry;
use crate::signer::{HsmBackend, HsmSigner, KeyHandle, KeyRef, SignerSet, MAX_SIGNERS};
use crate::wire::{Reader, Writer};
use crate::withdrawal::{verify_certificate, WithdrawalCertificate, WithdrawalId};

const AUDIT_SIGNED: u8 = 1;
const AUDIT_ROTATED: u8 = 2;
const AUDIT_HALTED: u8 = 3;
const AUDIT_RESUMED: u8 = 4;
const AUDIT_POLICY: u8 = 5;
const AUDIT_SETTLED: u8 = 6;

/// The output of a successful custody signing: the threshold certificate that
/// authorizes releasing the funds, tagged with the id and signing epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedWithdrawal {
    /// The withdrawal that was signed.
    pub withdrawal_id: WithdrawalId,
    /// The signer-set epoch that produced the certificate.
    pub epoch: u64,
    /// The threshold certificate over the withdrawal id.
    pub certificate: QuorumCertificate,
}

/// Wallet- or session-layer authorization that must precede threshold signing.
///
/// Binding and session registries are composed here so
/// [`CustodyController::authorize_withdrawal`] cannot be called with only a
/// consensus certificate — a live user proof is a hard precondition.
#[derive(Debug, Clone, Copy)]
pub enum UserWithdrawalAuth<'a> {
    /// A bound wallet flagged `withdrawals_allowed`, with a fresh proof over
    /// the withdrawal authorization message.
    Wallet {
        /// Registry holding the binding.
        registry: &'a WalletRegistry,
        /// Bound wallet address.
        address: &'a WalletAddress,
        /// Proof from the bound key.
        proof: &'a WalletProof,
    },
    /// A live session key with the withdrawal scope enabled.
    Session {
        /// Session registry.
        registry: &'a SessionRegistry,
        /// Session public key.
        session_pubkey: &'a [u8; 32],
    },
}

/// Chain-adapter-style finality attestation required to settle a withdrawal.
///
/// Produced by verified header-chain observation (see `chain-adapter::FinalityProof`).
/// Host-asserted settle without this proof is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettlementFinality {
    /// Including block / slot number.
    pub block_number: u64,
    /// Including block / slot hash.
    pub block_hash: Hash,
    /// Confirmation depth derived from a verified header chain.
    pub confirmations: u32,
}

/// Per-id pending authorization record (amount + chain) for settlement checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingAuth {
    chain: u64,
    amount: Amount,
}

/// A control-plane command against the custody controller.
///
/// Rotation carries **public keys and handles only** ([`KeyRef`]); raw seed or
/// private-key material is never accepted on the control plane. The new signers'
/// private keys are provisioned into the HSM / KMS out of band in an offline key
/// ceremony, and the controller reconstitutes live signers by binding each
/// handle through its [`HsmBackend`] and attesting the published public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlCommand {
    /// Rotate to a new signer set at a strictly newer epoch.
    Rotate {
        /// The new epoch (must exceed the current one).
        epoch: u64,
        /// The new threshold `t`.
        threshold: u32,
        /// The new signers' public identities (handle + published public key).
        /// Never seeds.
        keys: Vec<KeyRef>,
    },
    /// Engage emergency halt (blocks all signing).
    Halt,
    /// Clear emergency halt.
    Resume,
    /// Install or replace a per-chain policy.
    SetPolicy(ChainPolicy),
}

const CTRL_ROTATE: u8 = 1;
const CTRL_HALT: u8 = 2;
const CTRL_RESUME: u8 = 3;
const CTRL_POLICY: u8 = 4;

impl ControlCommand {
    /// Encode the command for transport / fuzzing.
    pub fn encode(&self) -> Result<Vec<u8>, CustodyError> {
        let mut w = Writer::new();
        match self {
            Self::Rotate {
                epoch,
                threshold,
                keys,
            } => {
                w.u8(CTRL_ROTATE);
                w.u64(*epoch);
                w.u32(*threshold);
                let n = u32::try_from(keys.len()).map_err(|_| CustodyError::Decode)?;
                w.u32(n);
                for k in keys {
                    w.var_bytes(k.handle.as_bytes())?;
                    w.raw(&k.public_key);
                }
            }
            Self::Halt => w.u8(CTRL_HALT),
            Self::Resume => w.u8(CTRL_RESUME),
            Self::SetPolicy(p) => {
                w.u8(CTRL_POLICY);
                w.raw(&p.encode());
            }
        }
        Ok(w.into_vec())
    }

    /// Decode a command from bytes. Total: arbitrary input yields `Err`, and no
    /// epoch/threshold field is ever narrowed with `as`.
    pub fn decode(bytes: &[u8]) -> Result<Self, CustodyError> {
        let mut r = Reader::new(bytes);
        let cmd = match r.u8()? {
            CTRL_ROTATE => {
                let epoch = r.u64()?;
                let threshold = r.u32()?;
                let n = usize::try_from(r.u32()?).map_err(|_| CustodyError::Decode)?;
                // Each key needs at least a 4-byte handle length prefix plus a
                // 32-byte public key, so bound the allocation against the input.
                if n > r.remaining() / 36 {
                    return Err(CustodyError::Decode);
                }
                let mut keys = Vec::with_capacity(n);
                for _ in 0..n {
                    let handle = KeyHandle::from_bytes(&r.var_bytes()?);
                    let public_key = r.array::<32>()?;
                    keys.push(KeyRef { handle, public_key });
                }
                Self::Rotate {
                    epoch,
                    threshold,
                    keys,
                }
            }
            CTRL_HALT => Self::Halt,
            CTRL_RESUME => Self::Resume,
            CTRL_POLICY => {
                let rest = r.tail();
                Self::SetPolicy(ChainPolicy::decode(rest)?)
            }
            _ => return Err(CustodyError::Decode),
        };
        Ok(cmd)
    }
}

/// The custody controller over an HSM-backed threshold signer set.
///
/// Every signing key lives behind the [`HsmBackend`] boundary ([`HsmSigner`]);
/// the controller holds only public keys and opaque handles. The same backend is
/// used to reconstitute signers on rotation, so a control-plane operator can
/// never inject a key they secretly control (rotation attests every published
/// public key against the HSM) nor ship raw seed material.
#[derive(Debug, Clone)]
pub struct CustodyController {
    backend: Arc<dyn HsmBackend>,
    signers: SignerSet<HsmSigner>,
    consensus: ValidatorSet,
    halted: bool,
    policies: BTreeMap<u64, ChainPolicy>,
    signed_ids: BTreeSet<[u8; 32]>,
    /// Per-withdrawal pending records so settle must match authorize exactly.
    pending_by_id: BTreeMap<[u8; 32], PendingAuth>,
    pending: BTreeMap<u64, Amount>,
    pending_count: BTreeMap<u64, u32>,
    audit_root: Hash,
    audit_len: u64,
}

impl CustodyController {
    /// Create a controller over `backend` with an HSM-bound signer set and the
    /// consensus verifier set.
    ///
    /// All signers in `signers` must be bound to `backend`; rotation binds new
    /// handles through this same backend.
    pub fn new(
        backend: Arc<dyn HsmBackend>,
        signers: SignerSet<HsmSigner>,
        consensus: ValidatorSet,
    ) -> Self {
        Self {
            backend,
            signers,
            consensus,
            halted: false,
            policies: BTreeMap::new(),
            signed_ids: BTreeSet::new(),
            pending_by_id: BTreeMap::new(),
            pending: BTreeMap::new(),
            pending_count: BTreeMap::new(),
            audit_root: Hash::ZERO,
            audit_len: 0,
        }
    }

    /// The current signer-set epoch.
    pub fn epoch(&self) -> u64 {
        self.signers.epoch()
    }

    /// Whether emergency halt is engaged.
    pub fn is_halted(&self) -> bool {
        self.halted
    }

    /// The running audit-log commitment.
    pub fn audit_root(&self) -> Hash {
        self.audit_root
    }

    /// The number of recorded audit events.
    pub fn audit_len(&self) -> u64 {
        self.audit_len
    }

    /// The current pending (authorized-but-unsettled) amount for a chain.
    pub fn pending(&self, chain: ChainId) -> Amount {
        self.policies_pending(chain.get())
    }

    fn policies_pending(&self, chain: u64) -> Amount {
        self.pending.get(&chain).copied().unwrap_or(Amount::ZERO)
    }

    /// Whether a withdrawal id has already been signed.
    pub fn is_signed(&self, id: &WithdrawalId) -> bool {
        self.signed_ids.contains(id.as_bytes())
    }

    /// Install or replace a per-chain policy.
    pub fn set_policy(&mut self, policy: ChainPolicy) {
        self.policies.insert(policy.chain.get(), policy);
        self.append_audit(AUDIT_POLICY, &policy.encode());
    }

    /// Engage emergency halt.
    pub fn halt(&mut self) {
        self.halted = true;
        self.append_audit(AUDIT_HALTED, &[]);
    }

    /// Clear emergency halt.
    pub fn resume(&mut self) {
        self.halted = false;
        self.append_audit(AUDIT_RESUMED, &[]);
    }

    /// Rotate to a new signer set. The new epoch must strictly exceed the
    /// current one; the old set is discarded and can no longer sign. The
    /// duplicate-sign ledger is preserved, so an id signed under the old set can
    /// never be re-signed under the new one.
    pub fn rotate(&mut self, new_signers: SignerSet<HsmSigner>) -> Result<(), CustodyError> {
        if new_signers.epoch() <= self.signers.epoch() {
            return Err(CustodyError::StaleEpoch);
        }
        let mut body = Writer::new();
        body.u64(new_signers.epoch());
        body.u64(new_signers.threshold());
        body.u32(u32::try_from(new_signers.n()).unwrap_or(u32::MAX));
        self.append_audit(AUDIT_ROTATED, &body.into_vec());
        self.signers = new_signers;
        Ok(())
    }

    /// Independently verify a finalized certificate **and** a user
    /// wallet/session authorization, then — if policy and duplicate checks pass
    /// — produce a threshold certificate over its id.
    ///
    /// Order of checks: halt, **user auth (hard precondition)**, certificate
    /// verification, chain policy, duplicate suppression, threshold signing.
    /// State is mutated only after every check succeeds.
    pub fn authorize_withdrawal(
        &mut self,
        cert: &WithdrawalCertificate,
        user_auth: UserWithdrawalAuth<'_>,
        signer_indices: &[usize],
        now: SequenceNumber,
    ) -> Result<SignedWithdrawal, CustodyError> {
        if self.halted {
            return Err(CustodyError::EmergencyHalt);
        }

        // Hard precondition: wallet or session must authorize this withdrawal.
        self.verify_user_auth(cert, user_auth, now)?;

        // Independent verification of the consensus-authorized certificate.
        verify_certificate(cert, &self.consensus, now)?;

        let chain = cert.request.chain.get();
        let policy = *self
            .policies
            .get(&chain)
            .ok_or(CustodyError::UnknownChain)?;
        let pending = self.policies_pending(chain);
        let count = self.pending_count.get(&chain).copied().unwrap_or(0);
        policy.check(cert.request.amount, cert.confirmations, pending, count)?;

        let id = cert.withdrawal_id;
        if self.signed_ids.contains(id.as_bytes()) {
            return Err(CustodyError::DuplicateSign);
        }

        // Threshold-sign the withdrawal id and confirm the quorum is reached
        // BEFORE mutating any state.
        let qc = self.signers.sign(id.to_hash(), signer_indices)?;
        self.signers
            .validator_set()
            .verify(&qc)
            .map_err(|_| CustodyError::ThresholdNotMet)?;

        // Commit.
        let new_pending = pending.checked_add(cert.request.amount)?;
        let new_count = count.checked_add(1).ok_or(CustodyError::Overflow)?;
        self.pending.insert(chain, new_pending);
        self.pending_count.insert(chain, new_count);
        self.signed_ids.insert(*id.as_bytes());
        self.pending_by_id.insert(
            *id.as_bytes(),
            PendingAuth {
                chain,
                amount: cert.request.amount,
            },
        );

        let mut body = Writer::new();
        body.raw(id.as_bytes());
        body.u64(self.signers.epoch());
        self.append_audit(AUDIT_SIGNED, &body.into_vec());

        Ok(SignedWithdrawal {
            withdrawal_id: id,
            epoch: self.signers.epoch(),
            certificate: qc,
        })
    }

    fn verify_user_auth(
        &self,
        cert: &WithdrawalCertificate,
        user_auth: UserWithdrawalAuth<'_>,
        now: SequenceNumber,
    ) -> Result<(), CustodyError> {
        // Message binds the withdrawal id so a proof cannot be reused across
        // different withdrawals.
        let mut msg = Writer::new();
        msg.raw(b"dexos:custody:user-withdraw-auth:v1");
        msg.raw(cert.withdrawal_id.as_bytes());
        msg.u32(cert.request.account.get());
        let message = msg.into_vec();

        match user_auth {
            UserWithdrawalAuth::Wallet {
                registry,
                address,
                proof,
            } => registry
                .authorize_withdrawal(cert.request.account, address, proof, &message, now)
                .map_err(|e| {
                    // Surface missing-auth distinctly from other wallet errors
                    // when the wallet is unknown / not permitted.
                    match e {
                        CustodyError::UnknownWallet
                        | CustodyError::WithdrawalNotAllowed
                        | CustodyError::NotMaster => CustodyError::MissingUserAuthorization,
                        other => other,
                    }
                }),
            UserWithdrawalAuth::Session {
                registry,
                session_pubkey,
            } => registry
                .authorize_withdrawal(cert.request.account, session_pubkey, now)
                .map_err(|e| match e {
                    CustodyError::UnknownSession
                    | CustodyError::SessionExpired
                    | CustodyError::SessionRevoked
                    | CustodyError::OutOfScope => CustodyError::MissingUserAuthorization,
                    other => other,
                }),
        }
    }

    /// Settle a previously authorized withdrawal against a verified finality
    /// attestation. Releases the pending amount and rate-limit slot only when:
    ///
    /// 1. `id` was authorized (present in the signed / pending-by-id ledger),
    /// 2. `chain` and `amount` match the authorized record exactly, and
    /// 3. `finality.confirmations` meets the chain policy minimum.
    ///
    /// Unauthenticated or mismatched settle attempts error without mutating
    /// pending accounting. The id remains permanently in the signed ledger.
    pub fn settle(
        &mut self,
        chain: ChainId,
        id: &WithdrawalId,
        amount: Amount,
        finality: &SettlementFinality,
    ) -> Result<(), CustodyError> {
        let key = chain.get();
        let auth = self
            .pending_by_id
            .get(id.as_bytes())
            .copied()
            .ok_or(CustodyError::UnauthenticatedSettle)?;
        if auth.chain != key || auth.amount != amount {
            return Err(CustodyError::UnauthenticatedSettle);
        }
        let policy = self.policies.get(&key).ok_or(CustodyError::UnknownChain)?;
        if finality.confirmations < policy.min_confirmations {
            return Err(CustodyError::UnverifiedFinality);
        }
        // Non-zero block hash required so a zeroed host stub cannot settle.
        if finality.block_hash == Hash::ZERO {
            return Err(CustodyError::UnverifiedFinality);
        }

        self.pending_by_id.remove(id.as_bytes());
        let cur = self.policies_pending(key);
        self.pending.insert(key, cur.saturating_sub(amount));
        let cnt = self.pending_count.get(&key).copied().unwrap_or(0);
        self.pending_count.insert(key, cnt.saturating_sub(1));

        let mut body = Writer::new();
        body.u64(key);
        body.raw(id.as_bytes());
        body.i128(amount.raw());
        body.u64(finality.block_number);
        body.raw(finality.block_hash.as_bytes());
        body.u32(finality.confirmations);
        self.append_audit(AUDIT_SETTLED, &body.into_vec());
        Ok(())
    }

    fn append_audit(&mut self, tag: u8, body: &[u8]) {
        let mut w = Writer::new();
        w.u8(tag);
        w.raw(body);
        let leaf = hash_leaf(&w.into_vec());
        self.audit_root = hash_node(self.audit_root, leaf);
        self.audit_len = self.audit_len.saturating_add(1);
    }
}

impl CustodyController {
    /// Apply a decoded [`ControlCommand`].
    ///
    /// A [`Rotate`](ControlCommand::Rotate) installs **public keys only**: each
    /// published [`KeyRef`] is bound through the controller's [`HsmBackend`] and
    /// its public key is attested against the HSM-reported key
    /// ([`CustodyError::KeyAttestationFailed`] on mismatch), so the private key
    /// stays inside the token and an operator cannot substitute a key they
    /// control. This also drives the deterministic replay harness: the same
    /// command stream over the same backend yields an identical audit root and
    /// signer set on every node.
    pub fn apply_control(&mut self, cmd: &ControlCommand) -> Result<(), CustodyError> {
        match cmd {
            ControlCommand::Rotate {
                epoch,
                threshold,
                keys,
            } => {
                if keys.is_empty() || keys.len() > MAX_SIGNERS {
                    return Err(CustodyError::InvalidThreshold);
                }
                let mut signers = Vec::with_capacity(keys.len());
                for key in keys {
                    signers.push(HsmSigner::bind_attested(
                        self.backend.clone(),
                        key.handle.clone(),
                        key.public_key,
                    )?);
                }
                let set = SignerSet::new(signers, u64::from(*threshold), *epoch)?;
                self.rotate(set)
            }
            ControlCommand::Halt => {
                self.halt();
                Ok(())
            }
            ControlCommand::Resume => {
                self.resume();
                Ok(())
            }
            ControlCommand::SetPolicy(p) => {
                self.set_policy(*p);
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::{BindWallet, WalletProof, WalletRegistry};
    use crate::chain::{evm_address_from_pubkey, WalletAddress};
    use crate::signer::MockHsm;
    use crate::withdrawal::{withdrawal_authorization_digest, ReservationProof, WithdrawalRequest};
    use crypto::{EvmKeyPair, MerkleTree, ThresholdSigners};
    use k256::ecdsa::SigningKey;
    use types::AccountId;

    const MASTER_SEED: [u8; 32] = [0x42; 32];

    fn seeds(n: usize) -> Vec<[u8; 32]> {
        (0..n).map(|i| [u8::try_from(i).unwrap() + 1; 32]).collect()
    }

    fn seeds_offset(n: usize, off: u8) -> Vec<[u8; 32]> {
        (0..n)
            .map(|i| [u8::try_from(i).unwrap() + off; 32])
            .collect()
    }

    // A consensus threshold set (for certificate quorums).
    fn consensus() -> ThresholdSigners {
        ThresholdSigners::from_seeds(&[[10u8; 32], [11u8; 32], [12u8; 32], [13u8; 32]], 3)
    }

    // Provision `seeds` into `hsm` (deterministic label per key) and return the
    // published key references (handle + public key) a rotation ships.
    fn refs_for(hsm: &mut MockHsm, seeds: &[[u8; 32]]) -> Vec<KeyRef> {
        seeds
            .iter()
            .map(|s| {
                let handle = KeyHandle::from_label(&format!("seed-{}", s[0]));
                let public_key = hsm.provision(&handle, s);
                KeyRef::new(handle, public_key)
            })
            .collect()
    }

    // Bind already-provisioned `refs` from `backend` into a threshold signer set.
    fn bind_set(
        backend: &Arc<dyn HsmBackend>,
        refs: &[KeyRef],
        threshold: u64,
        epoch: u64,
    ) -> SignerSet<HsmSigner> {
        let signers = refs
            .iter()
            .map(|r| {
                HsmSigner::bind_attested(backend.clone(), r.handle.clone(), r.public_key).unwrap()
            })
            .collect();
        SignerSet::new(signers, threshold, epoch).unwrap()
    }

    fn controller() -> CustodyController {
        let mut hsm = MockHsm::new();
        let refs = refs_for(&mut hsm, &seeds(4));
        let backend: Arc<dyn HsmBackend> = Arc::new(hsm);
        let custody = bind_set(&backend, &refs, 3, 1);
        let mut c = CustodyController::new(backend, custody, consensus().validator_set());
        c.set_policy(ChainPolicy {
            chain: ChainId(1),
            max_per_tx: Amount::from_raw(1_000),
            max_pending: Amount::from_raw(2_000),
            min_confirmations: 6,
            rate_limit: 5,
        });
        c
    }

    fn evm_uncompressed(seed: &[u8; 32]) -> Vec<u8> {
        let sk = SigningKey::from_slice(seed).unwrap();
        sk.verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    /// Wallet registry with account 1's master established and withdrawals allowed.
    fn wallets() -> (WalletRegistry, WalletAddress) {
        let mut reg = WalletRegistry::new(4);
        let uncompressed = evm_uncompressed(&MASTER_SEED);
        let addr = evm_address_from_pubkey(&uncompressed).unwrap();
        let mut cmd = BindWallet {
            account: AccountId::new(1),
            address: WalletAddress::Evm(addr),
            is_master: true,
            withdrawals_allowed: true,
            nonce: 0,
            proof: WalletProof::Eip712 {
                public_key_sec1: uncompressed,
                signature: vec![0u8; 64],
            },
        };
        let kp = EvmKeyPair::from_seed(&MASTER_SEED).unwrap();
        let sig = kp.sign_evm(&cmd.binding_message()).unwrap();
        if let WalletProof::Eip712 { signature, .. } = &mut cmd.proof {
            *signature = sig.to_vec();
        }
        reg.establish_master(&cmd, SequenceNumber::new(1)).unwrap();
        (reg, WalletAddress::Evm(addr))
    }

    fn user_message(cert: &WithdrawalCertificate) -> Vec<u8> {
        let mut msg = Writer::new();
        msg.raw(b"dexos:custody:user-withdraw-auth:v1");
        msg.raw(cert.withdrawal_id.as_bytes());
        msg.u32(cert.request.account.get());
        msg.into_vec()
    }

    fn wallet_proof_for(cert: &WithdrawalCertificate) -> WalletProof {
        let kp = EvmKeyPair::from_seed(&MASTER_SEED).unwrap();
        WalletProof::Eip712 {
            public_key_sec1: evm_uncompressed(&MASTER_SEED),
            signature: kp.sign_evm(&user_message(cert)).unwrap().to_vec(),
        }
    }

    fn auth<'a>(
        reg: &'a WalletRegistry,
        addr: &'a WalletAddress,
        proof: &'a WalletProof,
    ) -> UserWithdrawalAuth<'a> {
        UserWithdrawalAuth::Wallet {
            registry: reg,
            address: addr,
            proof,
        }
    }

    fn good_finality() -> SettlementFinality {
        SettlementFinality {
            block_number: 100,
            block_hash: Hash::from_bytes([0x77; 32]),
            confirmations: 12,
        }
    }

    // Build a certificate whose finalizing checkpoint genuinely commits to the
    // request's authorization digest via a Merkle inclusion proof, and whose
    // consensus quorum signs that checkpoint. This mirrors what a correct
    // sequencer would emit, so `verify_certificate` passes and the controller's
    // policy/duplicate/signing logic is what the assertions exercise.
    fn cert_for(req: WithdrawalRequest, confirmations: u32) -> WithdrawalCertificate {
        let cons = consensus();
        let reserved_amount = req.amount;
        let reservation_seq = SequenceNumber::new(42);
        let leaf_index = 3usize;
        let digest = withdrawal_authorization_digest(
            &req,
            req.id(),
            confirmations,
            reserved_amount,
            reservation_seq,
        );
        let mut tree = MerkleTree::new(8);
        for i in 0..8usize {
            tree.set(i, Hash::from_bytes([u8::try_from(i).unwrap() + 0x40; 32]))
                .unwrap();
        }
        tree.set(leaf_index, digest).unwrap();
        let checkpoint = tree.root();
        let quorum = cons.sign(checkpoint, vec![0, 1, 2]);
        WithdrawalCertificate {
            withdrawal_id: req.id(),
            request: req,
            checkpoint,
            quorum,
            confirmations,
            reservation: ReservationProof {
                reserved_amount,
                reservation_seq,
                leaf_index: leaf_index as u64,
                branch: tree.proof(leaf_index).unwrap(),
            },
            expiry: SequenceNumber::new(1000),
        }
    }

    fn cert(nonce: u64, amount: i128, confirmations: u32) -> WithdrawalCertificate {
        cert_for(
            WithdrawalRequest {
                account: AccountId::new(1),
                chain: ChainId(1),
                to: WalletAddress::Evm([0xAB; 20]),
                amount: Amount::from_raw(amount),
                nonce,
            },
            confirmations,
        )
    }

    #[test]
    fn k_of_n_signs_and_k_minus_1_does_not() {
        let mut c = controller();
        let (reg, addr) = wallets();
        let crt = cert(1, 100, 6);
        let proof = wallet_proof_for(&crt);
        // 3-of-4 succeeds.
        let signed = c
            .authorize_withdrawal(
                &crt,
                auth(&reg, &addr, &proof),
                &[0, 1, 2],
                SequenceNumber::new(1),
            )
            .unwrap();
        assert!(c
            .signers
            .validator_set()
            .verify(&signed.certificate)
            .is_ok());

        // 2-of-4 (below threshold) on a fresh id fails with ThresholdNotMet.
        let crt2 = cert(2, 100, 6);
        let proof2 = wallet_proof_for(&crt2);
        assert_eq!(
            c.authorize_withdrawal(
                &crt2,
                auth(&reg, &addr, &proof2),
                &[0, 1],
                SequenceNumber::new(2)
            ),
            Err(CustodyError::ThresholdNotMet)
        );
    }

    #[test]
    fn authorize_without_wallet_proof_fails() {
        let mut c = controller();
        let reg = WalletRegistry::new(4); // empty — no bindings
        let addr = WalletAddress::Evm([0xAB; 20]);
        let crt = cert(1, 100, 6);
        let proof = wallet_proof_for(&crt);
        assert_eq!(
            c.authorize_withdrawal(
                &crt,
                auth(&reg, &addr, &proof),
                &[0, 1, 2],
                SequenceNumber::new(1)
            ),
            Err(CustodyError::MissingUserAuthorization)
        );
    }

    #[test]
    fn duplicate_sign_prevented() {
        let mut c = controller();
        let (reg, addr) = wallets();
        let crt = cert(1, 100, 6);
        let proof = wallet_proof_for(&crt);
        c.authorize_withdrawal(
            &crt,
            auth(&reg, &addr, &proof),
            &[0, 1, 2],
            SequenceNumber::new(1),
        )
        .unwrap();
        assert_eq!(
            c.authorize_withdrawal(
                &crt,
                auth(&reg, &addr, &proof),
                &[0, 1, 2],
                SequenceNumber::new(2)
            ),
            Err(CustodyError::DuplicateSign)
        );
    }

    #[test]
    fn emergency_halt_blocks_then_resume() {
        let mut c = controller();
        let (reg, addr) = wallets();
        c.halt();
        let crt = cert(1, 100, 6);
        let proof = wallet_proof_for(&crt);
        assert_eq!(
            c.authorize_withdrawal(
                &crt,
                auth(&reg, &addr, &proof),
                &[0, 1, 2],
                SequenceNumber::new(1)
            ),
            Err(CustodyError::EmergencyHalt)
        );
        c.resume();
        assert!(c
            .authorize_withdrawal(
                &crt,
                auth(&reg, &addr, &proof),
                &[0, 1, 2],
                SequenceNumber::new(2)
            )
            .is_ok());
    }

    #[test]
    fn per_chain_limits_and_unknown_chain() {
        let mut c = controller();
        let (reg, addr) = wallets();
        let crt_over = cert(1, 5_000, 6);
        let p_over = wallet_proof_for(&crt_over);
        // Over per-tx cap.
        assert_eq!(
            c.authorize_withdrawal(
                &crt_over,
                auth(&reg, &addr, &p_over),
                &[0, 1, 2],
                SequenceNumber::new(1)
            ),
            Err(CustodyError::PolicyViolation)
        );
        // Under confirmations.
        let crt_conf = cert(2, 100, 3);
        let p_conf = wallet_proof_for(&crt_conf);
        assert_eq!(
            c.authorize_withdrawal(
                &crt_conf,
                auth(&reg, &addr, &p_conf),
                &[0, 1, 2],
                SequenceNumber::new(2)
            ),
            Err(CustodyError::PolicyViolation)
        );
        // Unknown chain id. Build the certificate for chain 999 directly so its
        // inclusion proof is valid and the controller reaches the policy lookup.
        let bad = cert_for(
            WithdrawalRequest {
                account: AccountId::new(1),
                chain: ChainId(999),
                to: WalletAddress::Evm([0xAB; 20]),
                amount: Amount::from_raw(100),
                nonce: 3,
            },
            6,
        );
        let p_bad = wallet_proof_for(&bad);
        assert_eq!(
            c.authorize_withdrawal(
                &bad,
                auth(&reg, &addr, &p_bad),
                &[0, 1, 2],
                SequenceNumber::new(3)
            ),
            Err(CustodyError::UnknownChain)
        );
    }

    #[test]
    fn cumulative_pending_cap_enforced_and_settle_frees() {
        let mut c = controller();
        let (reg, addr) = wallets();
        // max_pending = 2000; three 1000-withdrawals: 2 fit, 3rd exceeds.
        let c1 = cert(1, 1_000, 6);
        let p1 = wallet_proof_for(&c1);
        c.authorize_withdrawal(
            &c1,
            auth(&reg, &addr, &p1),
            &[0, 1, 2],
            SequenceNumber::new(1),
        )
        .unwrap();
        let c2 = cert(2, 1_000, 6);
        let p2 = wallet_proof_for(&c2);
        c.authorize_withdrawal(
            &c2,
            auth(&reg, &addr, &p2),
            &[0, 1, 2],
            SequenceNumber::new(2),
        )
        .unwrap();
        assert_eq!(c.pending(ChainId(1)), Amount::from_raw(2_000));
        let c3 = cert(3, 1_000, 6);
        let p3 = wallet_proof_for(&c3);
        assert_eq!(
            c.authorize_withdrawal(
                &c3,
                auth(&reg, &addr, &p3),
                &[0, 1, 2],
                SequenceNumber::new(3)
            ),
            Err(CustodyError::PolicyViolation)
        );
        // Unauthenticated settle is ignored / errors and conserves pending.
        let id = c1.withdrawal_id;
        assert_eq!(
            c.settle(
                ChainId(1),
                &id,
                Amount::from_raw(1_000),
                &SettlementFinality {
                    block_number: 1,
                    block_hash: Hash::ZERO,
                    confirmations: 100,
                }
            ),
            Err(CustodyError::UnverifiedFinality)
        );
        assert_eq!(c.pending(ChainId(1)), Amount::from_raw(2_000));
        // Wrong amount does not free slots.
        assert_eq!(
            c.settle(ChainId(1), &id, Amount::from_raw(999), &good_finality()),
            Err(CustodyError::UnauthenticatedSettle)
        );
        assert_eq!(c.pending(ChainId(1)), Amount::from_raw(2_000));
        // Verified finality settle frees headroom.
        c.settle(ChainId(1), &id, Amount::from_raw(1_000), &good_finality())
            .unwrap();
        assert_eq!(c.pending(ChainId(1)), Amount::from_raw(1_000));
        assert!(c
            .authorize_withdrawal(
                &c3,
                auth(&reg, &addr, &p3),
                &[0, 1, 2],
                SequenceNumber::new(4)
            )
            .is_ok());
    }

    #[test]
    fn rotation_invalidates_old_set_and_preserves_dup_ledger() {
        let mut c = controller();
        let (reg, addr) = wallets();
        let old_vs = c.signers.validator_set();
        let crt = cert(1, 100, 6);
        let proof = wallet_proof_for(&crt);
        let signed = c
            .authorize_withdrawal(
                &crt,
                auth(&reg, &addr, &proof),
                &[0, 1, 2],
                SequenceNumber::new(1),
            )
            .unwrap();
        assert!(old_vs.verify(&signed.certificate).is_ok());

        // Rotate to a disjoint set at a newer epoch, provisioned in its own HSM.
        let mut hsm_new = MockHsm::new();
        let refs_new = refs_for(&mut hsm_new, &seeds_offset(4, 100));
        let backend_new: Arc<dyn HsmBackend> = Arc::new(hsm_new);
        let new_set = bind_set(&backend_new, &refs_new, 3, 2);
        let new_vs = new_set.validator_set();
        c.rotate(new_set).unwrap();
        assert_eq!(c.epoch(), 2);

        // Stale rotation rejected.
        let mut hsm_stale = MockHsm::new();
        let refs_stale = refs_for(&mut hsm_stale, &seeds(4));
        let backend_stale: Arc<dyn HsmBackend> = Arc::new(hsm_stale);
        let stale = bind_set(&backend_stale, &refs_stale, 3, 1);
        assert_eq!(c.rotate(stale), Err(CustodyError::StaleEpoch));

        // New signatures verify under the NEW set, not the old one.
        let crt2 = cert(2, 100, 6);
        let proof2 = wallet_proof_for(&crt2);
        let signed2 = c
            .authorize_withdrawal(
                &crt2,
                auth(&reg, &addr, &proof2),
                &[0, 1, 2],
                SequenceNumber::new(2),
            )
            .unwrap();
        assert!(new_vs.verify(&signed2.certificate).is_ok());
        assert!(old_vs.verify(&signed2.certificate).is_err());

        // The already-signed id cannot be re-signed after rotation.
        assert_eq!(
            c.authorize_withdrawal(
                &crt,
                auth(&reg, &addr, &proof),
                &[0, 1, 2],
                SequenceNumber::new(3)
            ),
            Err(CustodyError::DuplicateSign)
        );
    }

    #[test]
    fn control_plane_rotation_installs_public_keys_only() {
        // A rotation control command carries public keys + handles, never seeds,
        // and the controller attests each key against its HSM before installing.
        let mut hsm = MockHsm::new();
        let base = refs_for(&mut hsm, &seeds(4));
        let rotated = refs_for(&mut hsm, &seeds_offset(4, 100));
        let backend: Arc<dyn HsmBackend> = Arc::new(hsm);
        let custody = bind_set(&backend, &base, 3, 1);
        let mut c = CustodyController::new(backend, custody, consensus().validator_set());

        let expected_vs = {
            let mut probe = MockHsm::new();
            let refs = refs_for(&mut probe, &seeds_offset(4, 100));
            let b: Arc<dyn HsmBackend> = Arc::new(probe);
            bind_set(&b, &refs, 3, 2).validator_set()
        };

        c.apply_control(&ControlCommand::Rotate {
            epoch: 2,
            threshold: 3,
            keys: rotated.clone(),
        })
        .unwrap();
        assert_eq!(c.epoch(), 2);
        assert_eq!(
            c.signers.validator_set().total_weight(),
            expected_vs.total_weight()
        );

        // Attestation failure: a published public key the HSM does not hold for
        // the handle is rejected (key-substitution attempt).
        let forged = vec![KeyRef::new(rotated[0].handle.clone(), [0xEE; 32])];
        assert_eq!(
            c.apply_control(&ControlCommand::Rotate {
                epoch: 3,
                threshold: 1,
                keys: forged,
            }),
            Err(CustodyError::KeyAttestationFailed)
        );

        // A handle the HSM never provisioned is rejected, not silently trusted.
        let unknown = vec![KeyRef::new(KeyHandle::from_label("ghost"), [1u8; 32])];
        assert_eq!(
            c.apply_control(&ControlCommand::Rotate {
                epoch: 3,
                threshold: 1,
                keys: unknown,
            }),
            Err(CustodyError::UnknownKeyHandle)
        );
    }

    #[test]
    fn deterministic_replay_yields_identical_audit_root_and_signed_set() {
        let run = || {
            // Base and rotation keys are provisioned into one HSM up front (the
            // offline ceremony), so the public-key-only rotate command can bind
            // the new handles when replayed.
            let mut hsm = MockHsm::new();
            let base = refs_for(&mut hsm, &seeds(4));
            let rotated = refs_for(&mut hsm, &seeds_offset(4, 50));
            let backend: Arc<dyn HsmBackend> = Arc::new(hsm);
            let custody = bind_set(&backend, &base, 3, 1);
            let mut c = CustodyController::new(backend, custody, consensus().validator_set());
            c.set_policy(ChainPolicy {
                chain: ChainId(1),
                max_per_tx: Amount::from_raw(1_000),
                max_pending: Amount::from_raw(2_000),
                min_confirmations: 6,
                rate_limit: 5,
            });
            let stream = [
                ControlCommand::Halt,
                ControlCommand::Resume,
                ControlCommand::Rotate {
                    epoch: 2,
                    threshold: 3,
                    keys: rotated.clone(),
                },
                ControlCommand::SetPolicy(ChainPolicy {
                    chain: ChainId(2),
                    max_per_tx: Amount::from_raw(500),
                    max_pending: Amount::from_raw(500),
                    min_confirmations: 1,
                    rate_limit: 2,
                }),
            ];
            for cmd in &stream {
                c.apply_control(cmd).unwrap();
            }
            let (reg, addr) = wallets();
            let c1 = cert(1, 100, 6);
            let p1 = wallet_proof_for(&c1);
            c.authorize_withdrawal(
                &c1,
                auth(&reg, &addr, &p1),
                &[0, 1, 2],
                SequenceNumber::new(1),
            )
            .unwrap();
            let c2 = cert(2, 200, 6);
            let p2 = wallet_proof_for(&c2);
            c.authorize_withdrawal(
                &c2,
                auth(&reg, &addr, &p2),
                &[0, 1, 2],
                SequenceNumber::new(2),
            )
            .unwrap();
            (c.audit_root(), c.signed_ids.clone())
        };
        let (root_a, set_a) = run();
        let (root_b, set_b) = run();
        assert_eq!(root_a, root_b);
        assert_eq!(set_a, set_b);
        assert_eq!(set_a.len(), 2);
    }

    #[test]
    fn control_command_decode_never_panics_and_round_trips() {
        let mut state = 0x99u64;
        for _ in 0..20_000 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let len = usize::try_from(state % 200).unwrap();
            let bytes: Vec<u8> = (0..len)
                .map(|_| {
                    state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                    state.to_le_bytes()[0]
                })
                .collect();
            let _ = ControlCommand::decode(&bytes);
        }
        for cmd in [
            ControlCommand::Halt,
            ControlCommand::Resume,
            ControlCommand::Rotate {
                epoch: 9,
                threshold: 2,
                // Handles of varying length, including an empty one, to exercise
                // the length-prefixed decode bound.
                keys: vec![
                    KeyRef::new(KeyHandle::from_label("arn:aws:kms:key/a"), [1u8; 32]),
                    KeyRef::new(KeyHandle::from_bytes(&[]), [2u8; 32]),
                    KeyRef::new(KeyHandle::from_label("slot-3"), [3u8; 32]),
                ],
            },
            ControlCommand::SetPolicy(ChainPolicy {
                chain: ChainId(7),
                max_per_tx: Amount::from_raw(10),
                max_pending: Amount::from_raw(20),
                min_confirmations: 1,
                rate_limit: 4,
            }),
        ] {
            let bytes = cmd.encode().unwrap();
            assert_eq!(ControlCommand::decode(&bytes).unwrap(), cmd);
        }
    }
}
