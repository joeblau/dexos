//! Encrypted, length-prefixed [`codec::Frame`] framing over an async byte stream.
//!
//! Every application frame crosses the wire as an AEAD record:
//! `u32 ciphertext_len (LE) || ChaCha20Poly1305(encode(frame))`. The plaintext
//! is the self-delimiting 19-byte-header [`codec::Frame`] byte string, so one
//! record carries exactly one frame. The declared ciphertext length is bounded
//! against the payload cap *before* allocating, so a hostile length header
//! cannot force a large allocation, and AEAD authentication (tamper, truncation,
//! reorder, wrong key) surfaces as a typed [`TransportError`] — never a panic,
//! over-read, or silent truncation.

use codec::{Frame, FRAME_HEADER_LEN, MAX_FRAME_PAYLOAD};
use tokio::io::{AsyncRead, AsyncReadExt};
#[cfg(test)]
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::error::TransportError;
use crate::session::{Opener, Sealer, AEAD_OVERHEAD};
use crate::util::as_usize;

/// Seal and write one frame as an encrypted, length-prefixed AEAD record.
///
/// Wire layout: `u32 ciphertext_len (LE) || ChaCha20Poly1305(encode(frame))`.
/// The plaintext is the self-delimiting [`Frame`] byte string, so decryption
/// yields exactly one frame. Only the 4-byte length prefix and opaque
/// ciphertext appear on the wire.
#[cfg(test)]
pub(crate) async fn write_encrypted_frame<W>(
    writer: &mut W,
    sealer: &mut Sealer,
    frame: &Frame,
) -> Result<(), TransportError>
where
    W: AsyncWrite + Unpin,
{
    let mut record = Vec::new();
    append_encrypted_record(&mut record, sealer, frame)?;
    writer.write_all(&record).await?;
    writer.flush().await?;
    Ok(())
}

/// Append one complete encrypted record to a reusable output buffer.
///
/// Keeping record construction separate from I/O lets the TCP writer coalesce
/// a bounded queue burst into one `write_all`/`flush` pair. Record boundaries
/// remain self-describing, so readers and cryptographic sequence handling are
/// unchanged.
pub(crate) fn append_encrypted_record(
    output: &mut Vec<u8>,
    sealer: &mut Sealer,
    frame: &Frame,
) -> Result<(), TransportError> {
    let plaintext = frame.encode()?;
    let ciphertext = sealer.seal(&plaintext)?;
    let len = u32::try_from(ciphertext.len()).map_err(|_| TransportError::MessageTooLarge)?;
    output.extend_from_slice(&len.to_le_bytes());
    output.extend_from_slice(&ciphertext);
    Ok(())
}

/// Read, open, and decode one encrypted AEAD record into a [`Frame`].
///
/// The declared ciphertext length is bounded before allocation against the
/// plaintext payload cap plus fixed framing and AEAD-tag overhead, so a hostile
/// length header cannot force a large allocation. AEAD failure (tamper,
/// truncation, reorder, or wrong key) surfaces as [`TransportError::Decrypt`].
pub(crate) async fn read_encrypted_frame<R>(
    reader: &mut R,
    opener: &mut Opener,
    max_payload: usize,
) -> Result<Frame, TransportError>
where
    R: AsyncRead + Unpin,
{
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes).await?;
    let declared = as_usize(u64::from(u32::from_le_bytes(len_bytes)));

    // A record's plaintext is one frame (header + payload); ciphertext adds the
    // AEAD tag. Cap the ciphertext accordingly before allocating.
    let cap = max_payload.min(MAX_FRAME_PAYLOAD) + FRAME_HEADER_LEN + AEAD_OVERHEAD;
    if declared < AEAD_OVERHEAD || declared > cap {
        return Err(TransportError::MessageTooLarge);
    }

    let mut ciphertext = vec![0u8; declared];
    reader.read_exact(&mut ciphertext).await?;

    let plaintext = opener.open(&ciphertext)?;
    let (frame, _consumed) = Frame::decode(&plaintext)?;
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::Ephemeral;
    use codec::TrafficClass;

    /// Build a matched sealer/opener pair via a simulated handshake.
    fn cipher_pair() -> (Sealer, Opener) {
        let a_static = [0x01u8; 32];
        let b_static = [0x02u8; 32];
        let a_nonce = [0x0Au8; 32];
        let b_nonce = [0x0Bu8; 32];
        let a_eph = Ephemeral::generate().unwrap();
        let b_eph = Ephemeral::generate().unwrap();
        let a_pub = a_eph.public();
        let b_pub = b_eph.public();
        let a_sess = a_eph.into_session(true, &b_pub, &a_static, &b_static, &a_nonce, &b_nonce);
        let b_sess = b_eph.into_session(false, &a_pub, &b_static, &a_static, &b_nonce, &a_nonce);
        let (sealer, _) = a_sess.split();
        let (_, opener) = b_sess.split();
        (sealer, opener)
    }

    #[tokio::test]
    async fn wire_shows_only_ciphertext() {
        let frame = Frame {
            class: TrafficClass::Consensus,
            msg_type: 7,
            sequence: 3,
            payload: b"top-secret-vote".to_vec(),
        };
        let (mut sealer, _opener) = cipher_pair();
        let (mut client, mut server) = tokio::io::duplex(4096);
        write_encrypted_frame(&mut client, &mut sealer, &frame)
            .await
            .unwrap();
        drop(client);

        let mut wire = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut server, &mut wire)
            .await
            .unwrap();
        assert!(
            !wire
                .windows(b"top-secret-vote".len())
                .any(|w| w == b"top-secret-vote"),
            "plaintext payload leaked onto the wire"
        );
    }

    #[tokio::test]
    async fn encrypted_frame_decodes_to_original() {
        let frame = Frame {
            class: TrafficClass::NewOrder,
            msg_type: 9,
            sequence: 11,
            payload: vec![0xABu8; 512],
        };
        let (mut sealer, mut opener) = cipher_pair();
        let (mut client, mut server) = tokio::io::duplex(8192);
        write_encrypted_frame(&mut client, &mut sealer, &frame)
            .await
            .unwrap();
        let got = read_encrypted_frame(&mut server, &mut opener, MAX_FRAME_PAYLOAD)
            .await
            .unwrap();
        assert_eq!(got, frame);
    }

    #[tokio::test]
    async fn tampered_ciphertext_is_rejected() {
        let frame = Frame {
            class: TrafficClass::MarketData,
            msg_type: 1,
            sequence: 1,
            payload: vec![1u8; 32],
        };
        let (mut sealer, mut opener) = cipher_pair();
        // Seal by hand so we can flip a byte before delivery.
        let plaintext = frame.encode().unwrap();
        let mut ct = sealer.seal(&plaintext).unwrap();
        let flip = ct.len() / 2;
        ct[flip] ^= 0x80;
        let len = u32::try_from(ct.len()).unwrap();
        let (mut client, mut server) = tokio::io::duplex(8192);
        client.write_all(&len.to_le_bytes()).await.unwrap();
        client.write_all(&ct).await.unwrap();
        client.flush().await.unwrap();
        let res = read_encrypted_frame(&mut server, &mut opener, MAX_FRAME_PAYLOAD).await;
        assert!(matches!(res, Err(TransportError::Decrypt)));
    }

    #[tokio::test]
    async fn multiple_encrypted_frames_stream_in_order() {
        let (mut sealer, mut opener) = cipher_pair();
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        let frames: Vec<Frame> = (0..16)
            .map(|i| Frame {
                class: TrafficClass::MarketData,
                msg_type: 1,
                sequence: i,
                payload: vec![u8::try_from(i).unwrap(); 10],
            })
            .collect();
        for f in &frames {
            write_encrypted_frame(&mut client, &mut sealer, f)
                .await
                .unwrap();
        }
        for expected in &frames {
            let got = read_encrypted_frame(&mut server, &mut opener, MAX_FRAME_PAYLOAD)
                .await
                .unwrap();
            assert_eq!(&got, expected);
        }
    }

    #[tokio::test]
    async fn never_panics_on_arbitrary_inbound_bytes() {
        // Feed a deterministic pseudo-random byte stream; the encrypted reader
        // must only ever produce a typed error, never panic or over-allocate.
        let (_sealer, mut opener) = cipher_pair();
        let mut state: u64 = 0x0102_0304_0506_0708;
        let mut bytes = Vec::new();
        for _ in 0..8192 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            bytes.push(state.to_le_bytes()[0]);
        }
        let (mut client, mut server) = tokio::io::duplex(16 * 1024);
        let writer = tokio::spawn(async move {
            let _ = client.write_all(&bytes).await;
            drop(client);
        });
        // A tight payload cap ensures a hostile length header cannot make us
        // allocate megabytes from a few random bytes.
        for _ in 0..8192 {
            match read_encrypted_frame(&mut server, &mut opener, 1024).await {
                Ok(_) => {}
                Err(_) => break,
            }
        }
        let _ = writer.await;
    }
}
