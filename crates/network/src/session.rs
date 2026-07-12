//! Authenticated transport encryption for the TCP peer link.
//!
//! After the ed25519 mutual-authentication handshake (see [`crate::tcp`]), the
//! two peers additionally perform an **ephemeral X25519 ECDH** whose public keys
//! are bound into the signed handshake transcript. This gives the link:
//!
//! * **Confidentiality + integrity** — every application frame is sealed with
//!   ChaCha20-Poly1305 AEAD, so a passive observer or on-path middlebox sees
//!   only ciphertext and a length prefix.
//! * **Forward secrecy** — the ECDH secret is ephemeral, so compromising a
//!   node's long-term ed25519 key later does not decrypt recorded sessions.
//! * **Authentication** — the ephemeral public keys are covered by the ed25519
//!   handshake signature, so a man-in-the-middle cannot substitute its own
//!   ephemeral key without failing authentication.
//!
//! Keys are derived per-direction (initiator→responder and responder→initiator)
//! via HKDF-SHA256 over the ECDH secret, salted with both handshake nonces and
//! bound to both static identities. Each direction owns an independent
//! monotonic nonce counter, so nonces never repeat under a fixed key.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::TransportError;

/// Domain separation for the transport-encryption key schedule. Distinct from
/// the handshake-signature domain so the two never collide.
const SESSION_DOMAIN: &[u8] = b"dexos-network-session-v1";

/// Size of an X25519 public key on the wire.
pub(crate) const EPH_PUBLIC_LEN: usize = 32;

/// ChaCha20-Poly1305 authentication tag length (bytes).
const TAG_LEN: usize = 16;

/// A freshly generated ephemeral X25519 keypair for one handshake.
pub(crate) struct Ephemeral {
    secret: StaticSecret,
    public: [u8; EPH_PUBLIC_LEN],
}

impl Ephemeral {
    /// Generate an ephemeral keypair from the OS CSPRNG.
    ///
    /// Uses `getrandom` (the platform secure RNG) rather than the non-secret
    /// handshake nonce source, because this secret guards session confidentiality.
    pub(crate) fn generate() -> Result<Self, TransportError> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|_| TransportError::HandshakeFailed)?;
        let secret = StaticSecret::from(seed);
        let public = PublicKey::from(&secret).to_bytes();
        Ok(Self { secret, public })
    }

    /// This ephemeral public key, to be sent to the peer and signed into the
    /// handshake transcript.
    pub(crate) fn public(&self) -> [u8; EPH_PUBLIC_LEN] {
        self.public
    }

    /// Complete the ECDH against the peer's ephemeral public key and derive the
    /// directional session ciphers.
    ///
    /// `is_initiator` is the unambiguous handshake role — the dialer
    /// ([`crate::Transport::connect`]) is the initiator, the accepter
    /// ([`crate::Transport::accept`]) the responder. The key schedule is ordered
    /// by that role (initiator material first) and each side takes the *opposite*
    /// send/recv key, so the two peers can NEVER pick the same send key — even if
    /// their static identities or handshake nonces collide (misconfiguration or a
    /// reflection attempt). This eliminates any keystream/nonce reuse across the
    /// two senders. `local_static` / `remote_static` are the ed25519 identity
    /// public keys and `local_nonce` / `remote_nonce` the handshake nonces; all
    /// are already authenticated by the ed25519 handshake, so binding them here
    /// ties the session keys to both peer identities and both nonces.
    pub(crate) fn into_session(
        self,
        is_initiator: bool,
        remote_eph: &[u8; EPH_PUBLIC_LEN],
        local_static: &[u8; 32],
        remote_static: &[u8; 32],
        local_nonce: &[u8; 32],
        remote_nonce: &[u8; 32],
    ) -> Session {
        let shared = self.secret.diffie_hellman(&PublicKey::from(*remote_eph));

        // Order the key-schedule inputs by ROLE (initiator first) so both peers
        // derive identical directional keys regardless of who dialed.
        let (init_id, resp_id, init_nonce, resp_nonce) = if is_initiator {
            (local_static, remote_static, local_nonce, remote_nonce)
        } else {
            (remote_static, local_static, remote_nonce, local_nonce)
        };

        let mut salt = [0u8; 64];
        salt[..32].copy_from_slice(init_nonce);
        salt[32..].copy_from_slice(resp_nonce);
        let hk = Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes());

        let key_init_to_resp = expand_key(&hk, SESSION_DOMAIN, b"init->resp", init_id, resp_id);
        let key_resp_to_init = expand_key(&hk, SESSION_DOMAIN, b"resp->init", init_id, resp_id);

        // The initiator sends on init->resp; the responder takes the mirror. The
        // two directional keys always differ (distinct HKDF `info` labels), so
        // the peers' send keys are guaranteed distinct.
        let (send_key, recv_key) = if is_initiator {
            (key_init_to_resp, key_resp_to_init)
        } else {
            (key_resp_to_init, key_init_to_resp)
        };

        Session {
            send: DirectionCipher::new(&send_key),
            recv: DirectionCipher::new(&recv_key),
        }
    }
}

/// Expand one directional 32-byte key from the shared HKDF context.
fn expand_key(
    hk: &Hkdf<Sha256>,
    domain: &[u8],
    dir: &[u8],
    lo_id: &[u8; 32],
    hi_id: &[u8; 32],
) -> [u8; 32] {
    let mut info = Vec::with_capacity(domain.len() + dir.len() + 64);
    info.extend_from_slice(domain);
    info.extend_from_slice(dir);
    info.extend_from_slice(lo_id);
    info.extend_from_slice(hi_id);
    let mut okm = [0u8; 32];
    // HKDF-expand of 32 bytes never exceeds 255*HashLen, so this cannot fail.
    hk.expand(&info, &mut okm)
        .expect("hkdf expand of 32 bytes is infallible");
    okm
}

/// One direction's AEAD state: a fixed key plus a monotonic nonce counter.
struct DirectionCipher {
    cipher: ChaCha20Poly1305,
    counter: u64,
}

impl DirectionCipher {
    fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(&Key::from(*key)),
            counter: 0,
        }
    }

    /// Build the 96-bit nonce for record `counter` (first 4 bytes zero, last 8
    /// the little-endian counter). Distinct keys per direction mean the counter
    /// never has to encode direction.
    fn nonce(counter: u64) -> Nonce {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&counter.to_le_bytes());
        Nonce::from(n)
    }

    fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, TransportError> {
        let nonce = Self::nonce(self.counter);
        let ct = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &self.counter.to_le_bytes(),
                },
            )
            .map_err(|_| TransportError::HandshakeFailed)?;
        self.counter = self.counter.wrapping_add(1);
        Ok(ct)
    }

    fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, TransportError> {
        let nonce = Self::nonce(self.counter);
        let pt = self
            .cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: &self.counter.to_le_bytes(),
                },
            )
            .map_err(|_| TransportError::Decrypt)?;
        self.counter = self.counter.wrapping_add(1);
        Ok(pt)
    }
}

/// An established encrypted session: an AEAD sealer for outbound records and an
/// opener for inbound records. Held one-per-direction inside the split
/// reader/writer tasks.
pub(crate) struct Session {
    send: DirectionCipher,
    recv: DirectionCipher,
}

impl Session {
    /// Split the session into its send and receive halves so the writer and
    /// reader tasks can each own one without sharing a lock. Records must arrive
    /// in order (TCP guarantees this); a gap, reorder, or tamper fails
    /// decryption and drops the link.
    pub(crate) fn split(self) -> (Sealer, Opener) {
        (Sealer(self.send), Opener(self.recv))
    }
}

/// Outbound half of a [`Session`], owned by the writer task.
pub(crate) struct Sealer(DirectionCipher);

impl Sealer {
    pub(crate) fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, TransportError> {
        self.0.seal(plaintext)
    }
}

/// Inbound half of a [`Session`], owned by the reader task.
pub(crate) struct Opener(DirectionCipher);

impl Opener {
    pub(crate) fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, TransportError> {
        self.0.open(ciphertext)
    }
}

/// Maximum plaintext expansion added by the AEAD layer (the Poly1305 tag).
pub(crate) const AEAD_OVERHEAD: usize = TAG_LEN;

#[cfg(test)]
mod tests {
    use super::*;

    /// Derive both peers' A→B sealer/opener halves from a simulated handshake.
    /// Returns `(a_send, b_recv, b_send, a_recv)` so tests can drive both
    /// directions.
    fn halves() -> (Sealer, Opener, Sealer, Opener) {
        let a_static = [0x11u8; 32];
        let b_static = [0x22u8; 32];
        let a_nonce = [0xA1u8; 32];
        let b_nonce = [0xB2u8; 32];
        let a_eph = Ephemeral::generate().unwrap();
        let b_eph = Ephemeral::generate().unwrap();
        let a_pub = a_eph.public();
        let b_pub = b_eph.public();
        let a_sess = a_eph.into_session(true, &b_pub, &a_static, &b_static, &a_nonce, &b_nonce);
        let b_sess = b_eph.into_session(false, &a_pub, &b_static, &a_static, &b_nonce, &a_nonce);
        let (a_send, a_recv) = a_sess.split();
        let (b_send, b_recv) = b_sess.split();
        (a_send, b_recv, b_send, a_recv)
    }

    #[test]
    fn round_trips_both_directions() {
        let (mut a_send, mut b_recv, mut b_send, mut a_recv) = halves();
        for i in 0..64u8 {
            let msg = vec![i; 100 + i as usize];
            let ct = a_send.seal(&msg).unwrap();
            assert_ne!(ct, msg, "ciphertext must differ from plaintext");
            assert_eq!(b_recv.open(&ct).unwrap(), msg);

            let reply = vec![i ^ 0xFF; 40];
            let ct2 = b_send.seal(&reply).unwrap();
            assert_eq!(a_recv.open(&ct2).unwrap(), reply);
        }
    }

    #[test]
    fn bit_flip_is_rejected() {
        let (mut a_send, mut b_recv, _, _) = halves();
        let mut ct = a_send.seal(b"consensus-vote").unwrap();
        ct[0] ^= 0x01;
        assert!(matches!(b_recv.open(&ct), Err(TransportError::Decrypt)));
    }

    #[test]
    fn key_mismatch_cannot_decrypt() {
        let (mut a_send, _, _, _) = halves();
        let (_, mut d_recv, _, _) = halves();
        let ct = a_send.seal(b"secret-order").unwrap();
        // `d_recv` derived a different ECDH secret; opening a's record must fail.
        assert!(matches!(d_recv.open(&ct), Err(TransportError::Decrypt)));
    }

    #[test]
    fn nonce_advances_so_identical_plaintext_differs() {
        let (mut a_send, mut b_recv, _, _) = halves();
        let ct1 = a_send.seal(b"same").unwrap();
        let ct2 = a_send.seal(b"same").unwrap();
        assert_ne!(ct1, ct2, "counter must make repeated plaintext distinct");
        assert_eq!(b_recv.open(&ct1).unwrap(), b"same");
        assert_eq!(b_recv.open(&ct2).unwrap(), b"same");
    }

    #[test]
    fn reordered_records_fail() {
        let (mut a_send, mut b_recv, _, _) = halves();
        let _ct1 = a_send.seal(b"first").unwrap();
        let ct2 = a_send.seal(b"second").unwrap();
        // Deliver out of order: b expects record 0 first.
        assert!(matches!(b_recv.open(&ct2), Err(TransportError::Decrypt)));
    }
}

#[cfg(test)]
mod adversarial_probe {
    use super::*;

    /// Regression test for keystream reuse under colliding static identities.
    ///
    /// If two endpoints share the SAME identity keypair (misconfiguration or a
    /// reflection attempt), a naive "order by identity" role assignment ties and
    /// both peers would send under the same key + nonce, reusing the ChaCha20
    /// keystream — catastrophic for a stream cipher. Role-based key assignment
    /// (initiator vs responder) guarantees distinct send keys regardless, so the
    /// keystreams MUST differ.
    #[test]
    fn equal_identity_senders_do_not_reuse_keystream() {
        let same_static = [0x33u8; 32];
        let x_nonce = [0xC1u8; 32];
        let y_nonce = [0xD2u8; 32];
        let x_eph = Ephemeral::generate().unwrap();
        let y_eph = Ephemeral::generate().unwrap();
        let x_pub = x_eph.public();
        let y_pub = y_eph.public();
        // X dials (initiator), Y accepts (responder) — the unambiguous roles the
        // TCP transport passes through from connect()/accept().
        let x_sess =
            x_eph.into_session(true, &y_pub, &same_static, &same_static, &x_nonce, &y_nonce);
        let y_sess = y_eph.into_session(
            false,
            &x_pub,
            &same_static,
            &same_static,
            &y_nonce,
            &x_nonce,
        );
        let (mut x_send, mut x_recv) = x_sess.split();
        let (mut y_send, mut y_recv) = y_sess.split();

        // Both seal DIFFERENT plaintexts as their first record (counter 0). The
        // ChaCha20-Poly1305 ciphertext body is plaintext XOR keystream, so
        // recovering keystream = ciphertext XOR plaintext reveals reuse if any.
        let p_x = b"XXXX-plaintext-from-x";
        let p_y = b"YYYY-plaintext-from-y";
        let ct_x = x_send.seal(p_x).unwrap();
        let ct_y = y_send.seal(p_y).unwrap();
        let n = p_x.len();
        let ks_x: Vec<u8> = ct_x[..n].iter().zip(p_x).map(|(c, p)| c ^ p).collect();
        let ks_y: Vec<u8> = ct_y[..n].iter().zip(p_y).map(|(c, p)| c ^ p).collect();
        assert_ne!(ks_x, ks_y, "keystreams must differ — no key/nonce reuse");

        // The sessions are still a correct pair: each opens the other's record.
        assert_eq!(y_recv.open(&ct_x).unwrap(), p_x);
        assert_eq!(x_recv.open(&ct_y).unwrap(), p_y);
    }
}
