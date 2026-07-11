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
    /// `initiator` orders the two static identities so both peers agree on which
    /// direction is which regardless of who dialed. `local_static` /
    /// `remote_static` are the ed25519 identity public keys; `local_nonce` /
    /// `remote_nonce` are the handshake nonces. All four are already
    /// authenticated by the ed25519 handshake, so binding them here ties the
    /// session keys to both peer identities and both nonces.
    pub(crate) fn into_session(
        self,
        remote_eph: &[u8; EPH_PUBLIC_LEN],
        local_static: &[u8; 32],
        remote_static: &[u8; 32],
        local_nonce: &[u8; 32],
        remote_nonce: &[u8; 32],
    ) -> Session {
        let shared = self.secret.diffie_hellman(&PublicKey::from(*remote_eph));

        // Canonically order the two identities so both sides compute an identical
        // salt/info independent of dial direction.
        let (lo_id, hi_id, lo_nonce, hi_nonce) = if local_static <= remote_static {
            (local_static, remote_static, local_nonce, remote_nonce)
        } else {
            (remote_static, local_static, remote_nonce, local_nonce)
        };

        let mut salt = [0u8; 64];
        salt[..32].copy_from_slice(lo_nonce);
        salt[32..].copy_from_slice(hi_nonce);
        let hk = Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes());

        let key_lo_to_hi = expand_key(&hk, SESSION_DOMAIN, b"lo->hi", lo_id, hi_id);
        let key_hi_to_lo = expand_key(&hk, SESSION_DOMAIN, b"hi->lo", lo_id, hi_id);

        // The lexicographically-smaller identity always sends on lo->hi.
        let local_is_lo = local_static <= remote_static;
        let (send_key, recv_key) = if local_is_lo {
            (key_lo_to_hi, key_hi_to_lo)
        } else {
            (key_hi_to_lo, key_lo_to_hi)
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
        let a_sess = a_eph.into_session(&b_pub, &a_static, &b_static, &a_nonce, &b_nonce);
        let b_sess = b_eph.into_session(&a_pub, &b_static, &a_static, &b_nonce, &a_nonce);
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

    #[test]
    fn equal_identity_both_send_same_key_nonce_reuse() {
        // Two endpoints sharing the SAME identity keypair (misconfig / reflection).
        let same_static = [0x33u8; 32];
        let x_nonce = [0xC1u8; 32];
        let y_nonce = [0xD2u8; 32];
        let x_eph = Ephemeral::generate().unwrap();
        let y_eph = Ephemeral::generate().unwrap();
        let x_pub = x_eph.public();
        let y_pub = y_eph.public();
        // X views itself as local=same_static, remote=same_static.
        let x_sess = x_eph.into_session(&y_pub, &same_static, &same_static, &x_nonce, &y_nonce);
        let y_sess = y_eph.into_session(&x_pub, &same_static, &same_static, &y_nonce, &x_nonce);
        let (mut x_send, _x_recv) = x_sess.split();
        let (mut y_send, _y_recv) = y_sess.split();

        // Both seal DIFFERENT plaintexts as their first record (counter 0).
        let p_x = b"XXXX-plaintext-from-x";
        let p_y = b"YYYY-plaintext-from-y";
        let ct_x = x_send.seal(p_x).unwrap();
        let ct_y = y_send.seal(p_y).unwrap();

        // If they share (key, nonce), the ChaCha20 keystream is identical, so the
        // ciphertext bodies XOR to the plaintext XOR. Demonstrate keystream reuse.
        let n = p_x.len();
        let ks_x: Vec<u8> = ct_x[..n].iter().zip(p_x.iter()).map(|(c, p)| c ^ p).collect();
        let ks_y: Vec<u8> = ct_y[..n].iter().zip(p_y.iter()).map(|(c, p)| c ^ p).collect();
        assert_eq!(ks_x, ks_y, "KEYSTREAM REUSE: same key+nonce across two senders");

        // And XOR of the two ciphertext bodies == XOR of the two plaintexts.
        let ct_xor: Vec<u8> = ct_x[..n].iter().zip(ct_y[..n].iter()).map(|(a, b)| a ^ b).collect();
        let pt_xor: Vec<u8> = p_x.iter().zip(p_y.iter()).map(|(a, b)| a ^ b).collect();
        assert_eq!(ct_xor, pt_xor, "passive observer recovers P_x XOR P_y");
    }
}
