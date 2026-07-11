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

use crypto::{hash_leaf, hash_node, QuorumCertificate, ValidatorSet};
use types::{Amount, Hash, SequenceNumber};

use crate::chain::ChainId;
use crate::error::CustodyError;
use crate::policy::ChainPolicy;
use crate::signer::{Signer, SignerSet, SoftSigner, MAX_SIGNERS};
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

/// A control-plane command against the custody controller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlCommand {
    /// Rotate to a new signer set at a strictly newer epoch.
    Rotate {
        /// The new epoch (must exceed the current one).
        epoch: u64,
        /// The new threshold `t`.
        threshold: u32,
        /// The new signers' seeds (software simulator).
        seeds: Vec<[u8; 32]>,
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
                seeds,
            } => {
                w.u8(CTRL_ROTATE);
                w.u64(*epoch);
                w.u32(*threshold);
                let n = u32::try_from(seeds.len()).map_err(|_| CustodyError::Decode)?;
                w.u32(n);
                for s in seeds {
                    w.raw(s);
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
                if n > r.remaining() / 32 {
                    return Err(CustodyError::Decode);
                }
                let mut seeds = Vec::with_capacity(n);
                for _ in 0..n {
                    seeds.push(r.array::<32>()?);
                }
                Self::Rotate {
                    epoch,
                    threshold,
                    seeds,
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

/// The custody controller, generic over the [`Signer`] implementation so the
/// software simulator and a real HSM are interchangeable.
#[derive(Debug, Clone)]
pub struct CustodyController<S: Signer> {
    signers: SignerSet<S>,
    consensus: ValidatorSet,
    halted: bool,
    policies: BTreeMap<u64, ChainPolicy>,
    signed_ids: BTreeSet<[u8; 32]>,
    pending: BTreeMap<u64, Amount>,
    pending_count: BTreeMap<u64, u32>,
    audit_root: Hash,
    audit_len: u64,
}

impl<S: Signer> CustodyController<S> {
    /// Create a controller with a signer set and the consensus verifier set.
    pub fn new(signers: SignerSet<S>, consensus: ValidatorSet) -> Self {
        Self {
            signers,
            consensus,
            halted: false,
            policies: BTreeMap::new(),
            signed_ids: BTreeSet::new(),
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
    pub fn rotate(&mut self, new_signers: SignerSet<S>) -> Result<(), CustodyError> {
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

    /// Independently verify a finalized certificate and, if it passes policy and
    /// has not been signed before, produce a threshold certificate over its id.
    ///
    /// Order of checks: halt, certificate verification, chain policy, duplicate
    /// suppression, threshold signing. State is mutated only after every check
    /// (including that the produced certificate meets threshold) succeeds.
    pub fn authorize_withdrawal(
        &mut self,
        cert: &WithdrawalCertificate,
        signer_indices: &[usize],
        now: SequenceNumber,
    ) -> Result<SignedWithdrawal, CustodyError> {
        if self.halted {
            return Err(CustodyError::EmergencyHalt);
        }

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

    /// Settle a previously authorized withdrawal, releasing its pending amount
    /// and rate-limit slot. The id remains permanently in the signed ledger.
    pub fn settle(&mut self, chain: ChainId, id: &WithdrawalId, amount: Amount) {
        let key = chain.get();
        let cur = self.policies_pending(key);
        self.pending.insert(key, cur.saturating_sub(amount));
        let cnt = self.pending_count.get(&key).copied().unwrap_or(0);
        self.pending_count.insert(key, cnt.saturating_sub(1));

        let mut body = Writer::new();
        body.u64(key);
        body.raw(id.as_bytes());
        body.i128(amount.raw());
        self.append_audit(AUDIT_SETTLED, &body.into_vec());
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

impl CustodyController<SoftSigner> {
    /// Apply a decoded [`ControlCommand`] to a software-simulator controller.
    ///
    /// This drives the deterministic replay harness: the same command stream
    /// yields an identical audit root and signer set on every node.
    pub fn apply_control(&mut self, cmd: &ControlCommand) -> Result<(), CustodyError> {
        match cmd {
            ControlCommand::Rotate {
                epoch,
                threshold,
                seeds,
            } => {
                if seeds.len() > MAX_SIGNERS {
                    return Err(CustodyError::InvalidThreshold);
                }
                let set = SignerSet::from_seeds(seeds, u64::from(*threshold), *epoch)?;
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
    use crate::chain::WalletAddress;
    use crate::withdrawal::WithdrawalRequest;
    use crypto::ThresholdSigners;
    use types::AccountId;

    fn seeds(n: usize) -> Vec<[u8; 32]> {
        (0..n).map(|i| [u8::try_from(i).unwrap() + 1; 32]).collect()
    }

    // A consensus threshold set (for certificate quorums).
    fn consensus() -> ThresholdSigners {
        ThresholdSigners::from_seeds(&[[10u8; 32], [11u8; 32], [12u8; 32], [13u8; 32]], 3)
    }

    fn controller() -> CustodyController<SoftSigner> {
        let custody = SignerSet::from_seeds(&seeds(4), 3, 1).unwrap();
        let mut c = CustodyController::new(custody, consensus().validator_set());
        c.set_policy(ChainPolicy {
            chain: ChainId(1),
            max_per_tx: Amount::from_raw(1_000),
            max_pending: Amount::from_raw(2_000),
            min_confirmations: 6,
            rate_limit: 5,
        });
        c
    }

    fn cert(nonce: u64, amount: i128, confirmations: u32) -> WithdrawalCertificate {
        let cons = consensus();
        let req = WithdrawalRequest {
            account: AccountId::new(1),
            chain: ChainId(1),
            to: WalletAddress::Evm([0xAB; 20]),
            amount: Amount::from_raw(amount),
            nonce,
        };
        let checkpoint = Hash::from_bytes([9u8; 32]);
        let quorum = cons.sign(checkpoint, vec![0, 1, 2]);
        WithdrawalCertificate {
            withdrawal_id: req.id(),
            request: req,
            checkpoint,
            quorum,
            finalized: true,
            confirmations,
            ledger_reserved: true,
            expiry: SequenceNumber::new(1000),
        }
    }

    #[test]
    fn k_of_n_signs_and_k_minus_1_does_not() {
        let mut c = controller();
        let crt = cert(1, 100, 6);
        // 3-of-4 succeeds.
        let signed = c
            .authorize_withdrawal(&crt, &[0, 1, 2], SequenceNumber::new(1))
            .unwrap();
        assert!(c
            .signers
            .validator_set()
            .verify(&signed.certificate)
            .is_ok());

        // 2-of-4 (below threshold) on a fresh id fails with ThresholdNotMet.
        let crt2 = cert(2, 100, 6);
        assert_eq!(
            c.authorize_withdrawal(&crt2, &[0, 1], SequenceNumber::new(2)),
            Err(CustodyError::ThresholdNotMet)
        );
    }

    #[test]
    fn duplicate_sign_prevented() {
        let mut c = controller();
        let crt = cert(1, 100, 6);
        c.authorize_withdrawal(&crt, &[0, 1, 2], SequenceNumber::new(1))
            .unwrap();
        assert_eq!(
            c.authorize_withdrawal(&crt, &[0, 1, 2], SequenceNumber::new(2)),
            Err(CustodyError::DuplicateSign)
        );
    }

    #[test]
    fn emergency_halt_blocks_then_resume() {
        let mut c = controller();
        c.halt();
        let crt = cert(1, 100, 6);
        assert_eq!(
            c.authorize_withdrawal(&crt, &[0, 1, 2], SequenceNumber::new(1)),
            Err(CustodyError::EmergencyHalt)
        );
        c.resume();
        assert!(c
            .authorize_withdrawal(&crt, &[0, 1, 2], SequenceNumber::new(2))
            .is_ok());
    }

    #[test]
    fn per_chain_limits_and_unknown_chain() {
        let mut c = controller();
        // Over per-tx cap.
        assert_eq!(
            c.authorize_withdrawal(&cert(1, 5_000, 6), &[0, 1, 2], SequenceNumber::new(1)),
            Err(CustodyError::PolicyViolation)
        );
        // Under confirmations.
        assert_eq!(
            c.authorize_withdrawal(&cert(2, 100, 3), &[0, 1, 2], SequenceNumber::new(2)),
            Err(CustodyError::PolicyViolation)
        );
        // Unknown chain id.
        let mut bad = cert(3, 100, 6);
        bad.request.chain = ChainId(999);
        bad.withdrawal_id = bad.request.id();
        assert_eq!(
            c.authorize_withdrawal(&bad, &[0, 1, 2], SequenceNumber::new(3)),
            Err(CustodyError::UnknownChain)
        );
    }

    #[test]
    fn cumulative_pending_cap_enforced_and_settle_frees() {
        let mut c = controller();
        // max_pending = 2000; three 1000-withdrawals: 2 fit, 3rd exceeds.
        c.authorize_withdrawal(&cert(1, 1_000, 6), &[0, 1, 2], SequenceNumber::new(1))
            .unwrap();
        c.authorize_withdrawal(&cert(2, 1_000, 6), &[0, 1, 2], SequenceNumber::new(2))
            .unwrap();
        assert_eq!(c.pending(ChainId(1)), Amount::from_raw(2_000));
        assert_eq!(
            c.authorize_withdrawal(&cert(3, 1_000, 6), &[0, 1, 2], SequenceNumber::new(3)),
            Err(CustodyError::PolicyViolation)
        );
        // Settle one, freeing headroom.
        let id = cert(1, 1_000, 6).withdrawal_id;
        c.settle(ChainId(1), &id, Amount::from_raw(1_000));
        assert_eq!(c.pending(ChainId(1)), Amount::from_raw(1_000));
        assert!(c
            .authorize_withdrawal(&cert(3, 1_000, 6), &[0, 1, 2], SequenceNumber::new(4))
            .is_ok());
    }

    #[test]
    fn rotation_invalidates_old_set_and_preserves_dup_ledger() {
        let mut c = controller();
        let old_vs = c.signers.validator_set();
        let crt = cert(1, 100, 6);
        let signed = c
            .authorize_withdrawal(&crt, &[0, 1, 2], SequenceNumber::new(1))
            .unwrap();
        assert!(old_vs.verify(&signed.certificate).is_ok());

        // Rotate to a disjoint set at a newer epoch.
        let new_set = SignerSet::from_seeds(&seeds_offset(4, 100), 3, 2).unwrap();
        let new_vs = new_set.validator_set();
        c.rotate(new_set).unwrap();
        assert_eq!(c.epoch(), 2);

        // Stale rotation rejected.
        let stale = SignerSet::from_seeds(&seeds(4), 3, 1).unwrap();
        assert_eq!(c.rotate(stale), Err(CustodyError::StaleEpoch));

        // New signatures verify under the NEW set, not the old one.
        let crt2 = cert(2, 100, 6);
        let signed2 = c
            .authorize_withdrawal(&crt2, &[0, 1, 2], SequenceNumber::new(2))
            .unwrap();
        assert!(new_vs.verify(&signed2.certificate).is_ok());
        assert!(old_vs.verify(&signed2.certificate).is_err());

        // The already-signed id cannot be re-signed after rotation.
        assert_eq!(
            c.authorize_withdrawal(&crt, &[0, 1, 2], SequenceNumber::new(3)),
            Err(CustodyError::DuplicateSign)
        );
    }

    fn seeds_offset(n: usize, off: u8) -> Vec<[u8; 32]> {
        (0..n)
            .map(|i| [u8::try_from(i).unwrap() + off; 32])
            .collect()
    }

    #[test]
    fn deterministic_replay_yields_identical_audit_root_and_signed_set() {
        let run = || {
            let mut c = controller();
            let stream = [
                ControlCommand::Halt,
                ControlCommand::Resume,
                ControlCommand::Rotate {
                    epoch: 2,
                    threshold: 3,
                    seeds: seeds_offset(4, 50),
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
            c.authorize_withdrawal(&cert(1, 100, 6), &[0, 1, 2], SequenceNumber::new(1))
                .unwrap();
            c.authorize_withdrawal(&cert(2, 200, 6), &[0, 1, 2], SequenceNumber::new(2))
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
                seeds: seeds(3),
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
