//! Scoped, master-authorized trading session keys.
//!
//! An account's master wallet authorizes an ephemeral session key with a bounded
//! scope: an allow-list of markets, a maximum notional per order, a maximum
//! leverage, whether withdrawals are permitted, and an expiry sequence. Every
//! scope dimension is enforced on use, and a session revoked at sequence `N` is
//! rejected for all commands at sequence `> N`.

use std::collections::BTreeMap;

use types::{AccountId, Amount, MarketId, Ratio, SequenceNumber};

use crate::binding::{WalletProof, WalletRegistry};
use crate::error::CustodyError;
use crate::wire::Writer;

/// Domain tag separating session-authorization messages from other payloads.
pub const SESSION_DOMAIN: &[u8] = b"DEXOS/AUTHORIZE-SESSION/v1";

/// The bounded authority granted to a session key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionScope {
    /// Allow-list of markets the session may trade. Empty denies all markets.
    pub markets: Vec<MarketId>,
    /// Maximum notional per order.
    pub max_notional: Amount,
    /// Maximum leverage (as a [`Ratio`]).
    pub max_leverage: Ratio,
    /// Whether the session may authorize withdrawals.
    pub allow_withdrawals: bool,
    /// Last sequence at which the session is valid (inclusive).
    pub expiry: SequenceNumber,
}

impl SessionScope {
    fn encode_into(&self, w: &mut Writer) -> Result<(), CustodyError> {
        let len = u32::try_from(self.markets.len()).map_err(|_| CustodyError::Decode)?;
        w.u32(len);
        for m in &self.markets {
            w.u32(m.get());
        }
        w.i128(self.max_notional.raw());
        w.u64(u64::try_from(self.max_leverage.raw()).unwrap_or(0));
        w.u8(u8::from(self.allow_withdrawals));
        w.u64(self.expiry.get());
        Ok(())
    }
}

/// A command, signed by the account's master wallet, authorizing a session key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizeSession {
    /// The account granting authority.
    pub account: AccountId,
    /// The ed25519 session public key being authorized.
    pub session_pubkey: [u8; 32],
    /// The granted scope.
    pub scope: SessionScope,
    /// A per-account nonce guarding against authorization replay.
    pub nonce: u64,
    /// Proof from the account's master wallet.
    pub master_proof: WalletProof,
}

impl AuthorizeSession {
    /// The canonical message the master wallet must sign.
    pub fn authorization_message(&self) -> Result<Vec<u8>, CustodyError> {
        let mut w = Writer::new();
        w.raw(SESSION_DOMAIN);
        w.u32(self.account.get());
        w.raw(&self.session_pubkey);
        self.scope.encode_into(&mut w)?;
        w.u64(self.nonce);
        Ok(w.into_vec())
    }
}

/// A live session key with its scope and lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionKey {
    /// The owning account.
    pub account: AccountId,
    /// The ed25519 session public key.
    pub session_pubkey: [u8; 32],
    /// The granted scope.
    pub scope: SessionScope,
    /// Sequence at which the session was authorized.
    pub authorized_at: SequenceNumber,
    /// Sequence at which the session was revoked, if any.
    pub revoked_at: Option<SequenceNumber>,
}

impl SessionKey {
    /// Whether the session is usable at `seq` (authorized, not revoked, not expired).
    pub fn is_live(&self, seq: SequenceNumber) -> bool {
        if seq > self.scope.expiry {
            return false;
        }
        match self.revoked_at {
            Some(r) => seq <= r,
            None => true,
        }
    }
}

/// A registry of scoped session keys.
#[derive(Debug, Clone, Default)]
pub struct SessionRegistry {
    sessions: BTreeMap<(u32, [u8; 32]), SessionKey>,
    used_nonces: std::collections::BTreeSet<(u32, u64)>,
}

impl SessionRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify a master-signed [`AuthorizeSession`] and record the session.
    ///
    /// The master proof must carry the key of the account's active master wallet
    /// and verify over the canonical authorization message.
    pub fn authorize(
        &mut self,
        cmd: &AuthorizeSession,
        wallets: &WalletRegistry,
        seq: SequenceNumber,
    ) -> Result<(), CustodyError> {
        let nonce_key = (cmd.account.get(), cmd.nonce);
        if self.used_nonces.contains(&nonce_key) {
            return Err(CustodyError::ReplayedBinding);
        }
        let master = wallets
            .master(cmd.account, seq)
            .ok_or(CustodyError::NotMaster)?;
        if cmd.master_proof.key() != master.key {
            return Err(CustodyError::NotMaster);
        }
        let message = cmd.authorization_message()?;
        cmd.master_proof.verify(&message)?;

        self.used_nonces.insert(nonce_key);
        self.sessions.insert(
            (cmd.account.get(), cmd.session_pubkey),
            SessionKey {
                account: cmd.account,
                session_pubkey: cmd.session_pubkey,
                scope: cmd.scope.clone(),
                authorized_at: seq,
                revoked_at: None,
            },
        );
        Ok(())
    }

    /// Revoke a session at `seq`.
    pub fn revoke(
        &mut self,
        account: AccountId,
        session_pubkey: &[u8; 32],
        seq: SequenceNumber,
    ) -> Result<(), CustodyError> {
        let s = self
            .sessions
            .get_mut(&(account.get(), *session_pubkey))
            .ok_or(CustodyError::UnknownSession)?;
        s.revoked_at = Some(seq);
        Ok(())
    }

    fn live(
        &self,
        account: AccountId,
        session_pubkey: &[u8; 32],
        seq: SequenceNumber,
    ) -> Result<&SessionKey, CustodyError> {
        let s = self
            .sessions
            .get(&(account.get(), *session_pubkey))
            .ok_or(CustodyError::UnknownSession)?;
        if let Some(r) = s.revoked_at {
            if seq > r {
                return Err(CustodyError::SessionRevoked);
            }
        }
        if seq > s.scope.expiry {
            return Err(CustodyError::SessionExpired);
        }
        Ok(s)
    }

    /// Authorize an order under a session, enforcing every scope dimension.
    pub fn authorize_order(
        &self,
        account: AccountId,
        session_pubkey: &[u8; 32],
        market: MarketId,
        notional: Amount,
        leverage: Ratio,
        seq: SequenceNumber,
    ) -> Result<(), CustodyError> {
        let s = self.live(account, session_pubkey, seq)?;
        if !s.scope.markets.contains(&market) {
            return Err(CustodyError::OutOfScope);
        }
        if notional > s.scope.max_notional {
            return Err(CustodyError::OutOfScope);
        }
        if leverage > s.scope.max_leverage {
            return Err(CustodyError::OutOfScope);
        }
        Ok(())
    }

    /// Authorize a withdrawal under a session (requires the withdrawal scope).
    pub fn authorize_withdrawal(
        &self,
        account: AccountId,
        session_pubkey: &[u8; 32],
        seq: SequenceNumber,
    ) -> Result<(), CustodyError> {
        let s = self.live(account, session_pubkey, seq)?;
        if !s.scope.allow_withdrawals {
            return Err(CustodyError::OutOfScope);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::BindWallet;
    use crate::chain::WalletAddress;
    use crypto::KeyPair;

    fn master_bound(seed: &[u8; 32], account: u32) -> (WalletRegistry, KeyPair) {
        let kp = KeyPair::from_seed(seed);
        let pk = kp.public();
        let mut cmd = BindWallet {
            account: AccountId::new(account),
            address: WalletAddress::Svm(pk),
            is_master: true,
            withdrawals_allowed: false,
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
        let mut reg = WalletRegistry::new(4);
        reg.bind(&cmd, SequenceNumber::new(1)).unwrap();
        (reg, kp)
    }

    fn authorize_cmd(master: &KeyPair, account: u32, scope: SessionScope) -> AuthorizeSession {
        let session_pubkey = [77u8; 32];
        let mut cmd = AuthorizeSession {
            account: AccountId::new(account),
            session_pubkey,
            scope,
            nonce: 1,
            master_proof: WalletProof::Ed25519 {
                public_key: master.public(),
                signature: [0u8; 64],
            },
        };
        let sig = master.sign(&cmd.authorization_message().unwrap());
        if let WalletProof::Ed25519 { signature, .. } = &mut cmd.master_proof {
            *signature = sig;
        }
        cmd
    }

    fn scope(expiry: u64, wd: bool) -> SessionScope {
        SessionScope {
            markets: vec![MarketId::new(10)],
            max_notional: Amount::from_raw(1_000_000_000),
            max_leverage: Ratio::from_raw(5_000_000),
            allow_withdrawals: wd,
            expiry: SequenceNumber::new(expiry),
        }
    }

    #[test]
    fn authorizes_only_with_valid_master_signature() {
        let (wallets, master) = master_bound(&[1u8; 32], 1);
        let mut sessions = SessionRegistry::new();
        let cmd = authorize_cmd(&master, 1, scope(100, false));
        assert!(sessions
            .authorize(&cmd, &wallets, SequenceNumber::new(2))
            .is_ok());

        // Tampered master signature is rejected.
        let mut bad = authorize_cmd(&master, 1, scope(100, false));
        bad.nonce = 2;
        if let WalletProof::Ed25519 { signature, .. } = &mut bad.master_proof {
            signature[0] ^= 1;
        }
        assert!(sessions
            .authorize(&bad, &wallets, SequenceNumber::new(3))
            .is_err());
    }

    #[test]
    fn enforces_every_scope_dimension() {
        let (wallets, master) = master_bound(&[1u8; 32], 1);
        let mut sessions = SessionRegistry::new();
        let cmd = authorize_cmd(&master, 1, scope(100, false));
        sessions
            .authorize(&cmd, &wallets, SequenceNumber::new(2))
            .unwrap();
        let sk = [77u8; 32];
        let acc = AccountId::new(1);
        let n = SequenceNumber::new(5);

        // In-scope order succeeds.
        assert!(sessions
            .authorize_order(
                acc,
                &sk,
                MarketId::new(10),
                Amount::from_raw(1),
                Ratio::from_raw(1),
                n
            )
            .is_ok());
        // Out-of-scope market.
        assert_eq!(
            sessions.authorize_order(
                acc,
                &sk,
                MarketId::new(11),
                Amount::from_raw(1),
                Ratio::from_raw(1),
                n
            ),
            Err(CustodyError::OutOfScope)
        );
        // Over-notional.
        assert_eq!(
            sessions.authorize_order(
                acc,
                &sk,
                MarketId::new(10),
                Amount::from_raw(2_000_000_000),
                Ratio::from_raw(1),
                n
            ),
            Err(CustodyError::OutOfScope)
        );
        // Over-leverage.
        assert_eq!(
            sessions.authorize_order(
                acc,
                &sk,
                MarketId::new(10),
                Amount::from_raw(1),
                Ratio::from_raw(9_000_000),
                n
            ),
            Err(CustodyError::OutOfScope)
        );
        // Withdrawal not in scope.
        assert_eq!(
            sessions.authorize_withdrawal(acc, &sk, n),
            Err(CustodyError::OutOfScope)
        );
    }

    #[test]
    fn revocation_rejects_after_sequence_and_expiry() {
        let (wallets, master) = master_bound(&[1u8; 32], 1);
        let mut sessions = SessionRegistry::new();
        let cmd = authorize_cmd(&master, 1, scope(100, true));
        sessions
            .authorize(&cmd, &wallets, SequenceNumber::new(2))
            .unwrap();
        let sk = [77u8; 32];
        let acc = AccountId::new(1);

        sessions.revoke(acc, &sk, SequenceNumber::new(10)).unwrap();
        // At/below N still allowed; above N rejected.
        assert!(sessions
            .authorize_withdrawal(acc, &sk, SequenceNumber::new(10))
            .is_ok());
        assert_eq!(
            sessions.authorize_withdrawal(acc, &sk, SequenceNumber::new(11)),
            Err(CustodyError::SessionRevoked)
        );
        // Past expiry rejected.
        assert_eq!(
            sessions.authorize_withdrawal(acc, &sk, SequenceNumber::new(101)),
            Err(CustodyError::SessionRevoked)
        );
    }
}
