//! Length-prefixed [`codec::Frame`] framing over an async byte stream.
//!
//! A DexOS frame is self-delimiting: its 19-byte header carries a `u32` payload
//! length. We read the header, bound the declared length against
//! [`codec::MAX_FRAME_PAYLOAD`] (and the per-transport cap) *before* allocating,
//! then read exactly the payload and hand the whole buffer to
//! [`codec::Frame::decode`], which is total on adversarial bytes. No decode path
//! panics, over-reads, or silently truncates.

use codec::{Frame, FRAME_HEADER_LEN, MAX_FRAME_PAYLOAD};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::TransportError;
use crate::util::as_usize;

/// Serialize and write a single frame, flushing it to the stream.
pub(crate) async fn write_frame<W>(writer: &mut W, frame: &Frame) -> Result<(), TransportError>
where
    W: AsyncWrite + Unpin,
{
    let bytes = frame.encode()?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

/// Read exactly one frame from the stream.
///
/// `max_payload` is the transport's own payload cap (never larger than
/// [`MAX_FRAME_PAYLOAD`]); a frame declaring more is rejected before any
/// payload-sized allocation, bounding memory against a hostile length header.
pub(crate) async fn read_frame<R>(
    reader: &mut R,
    max_payload: usize,
) -> Result<Frame, TransportError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; FRAME_HEADER_LEN];
    reader.read_exact(&mut header).await?;

    // Declared payload length lives in the last 4 header bytes (LE u32).
    let declared = u32::from_le_bytes([header[15], header[16], header[17], header[18]]);
    let payload_len = as_usize(u64::from(declared));
    let cap = max_payload.min(MAX_FRAME_PAYLOAD);
    if payload_len > cap {
        return Err(TransportError::MessageTooLarge);
    }

    let total = FRAME_HEADER_LEN
        .checked_add(payload_len)
        .ok_or(TransportError::MessageTooLarge)?;
    let mut buf = vec![0u8; total];
    buf[..FRAME_HEADER_LEN].copy_from_slice(&header);
    reader.read_exact(&mut buf[FRAME_HEADER_LEN..]).await?;

    let (frame, consumed) = Frame::decode(&buf)?;
    debug_assert_eq!(consumed, total);
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::TrafficClass;

    #[tokio::test]
    async fn frame_round_trips_over_a_stream() {
        let frame = Frame {
            class: TrafficClass::NewOrder,
            msg_type: 42,
            sequence: 7,
            payload: vec![9u8; 300],
        };
        let (mut client, mut server) = tokio::io::duplex(4096);
        write_frame(&mut client, &frame).await.unwrap();
        let got = read_frame(&mut server, MAX_FRAME_PAYLOAD).await.unwrap();
        assert_eq!(got, frame);
    }

    #[tokio::test]
    async fn multiple_frames_stream_in_order() {
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
            write_frame(&mut client, f).await.unwrap();
        }
        for expected in &frames {
            let got = read_frame(&mut server, MAX_FRAME_PAYLOAD).await.unwrap();
            assert_eq!(&got, expected);
        }
    }

    #[tokio::test]
    async fn never_panics_on_arbitrary_inbound_bytes() {
        // Feed a deterministic pseudo-random byte stream; the reader must only
        // ever produce frames or typed errors, never panic or over-allocate.
        let mut state: u64 = 0x0102_0304_0506_0708;
        let mut bytes = Vec::new();
        for _ in 0..8192 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            bytes.push(state.to_le_bytes()[0]);
        }
        let (mut client, mut server) = tokio::io::duplex(16 * 1024);
        let writer = tokio::spawn(async move {
            // Ignore errors: the reader may give up (and drop) before we finish.
            let _ = client.write_all(&bytes).await;
            drop(client);
        });
        // A tight payload cap ensures a hostile length header cannot make us
        // allocate megabytes from a few random bytes.
        for _ in 0..8192 {
            match read_frame(&mut server, 1024).await {
                Ok(_) => {}
                Err(_) => break,
            }
        }
        let _ = writer.await;
    }
}
