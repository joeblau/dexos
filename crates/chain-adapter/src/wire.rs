//! [`Codec`] implementations for foreign `types`/`crypto` values used on the wire.

use crate::codec::{Codec, CodecError, Reader, Writer};
use crypto::{QuorumCertificate, QuorumSignatures};
use types::{AccountId, Amount, Hash};

/// A `u16` bitmap has at most 16 set bits, so a quorum never carries more.
pub const MAX_QUORUM_SIGNATURES: usize = 16;

impl Codec for Hash {
    fn write(&self, w: &mut Writer) {
        w.array32(self.as_bytes());
    }
    fn read(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Hash::from_bytes(r.array32()?))
    }
}

impl Codec for Amount {
    fn write(&self, w: &mut Writer) {
        w.i128(self.raw());
    }
    fn read(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Amount::from_raw(r.i128()?))
    }
}

impl Codec for AccountId {
    fn write(&self, w: &mut Writer) {
        w.u32(self.get());
    }
    fn read(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(AccountId::new(r.u32()?))
    }
}

impl Codec for QuorumCertificate {
    fn write(&self, w: &mut Writer) {
        self.message.write(w);
        w.u16(self.signer_bitmap);
        w.len(self.signatures.len());
        for sig in &self.signatures {
            w.array64(sig);
        }
    }
    fn read(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let message = Hash::read(r)?;
        let signer_bitmap = r.u16()?;
        let count = r.len()?;
        if count > MAX_QUORUM_SIGNATURES {
            return Err(CodecError::LengthOutOfRange);
        }
        let mut signatures = QuorumSignatures::new();
        for _ in 0..count {
            signatures
                .try_push(r.array64()?)
                .map_err(|_| CodecError::LengthOutOfRange)?;
        }
        Ok(QuorumCertificate {
            message,
            signer_bitmap,
            signatures,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foreign_types_round_trip() {
        let h = Hash::from_bytes([7u8; 32]);
        assert_eq!(Hash::decode(&h.encode()).unwrap(), h);

        let a = Amount::from_raw(i128::MIN);
        assert_eq!(Amount::decode(&a.encode()).unwrap(), a);

        let acct = AccountId::new(9);
        assert_eq!(AccountId::decode(&acct.encode()).unwrap(), acct);

        let qc = QuorumCertificate {
            message: h,
            signer_bitmap: 0b101,
            signatures: [[1u8; 64], [2u8; 64]].into_iter().collect(),
        };
        assert_eq!(QuorumCertificate::decode(&qc.encode()).unwrap(), qc);
    }

    #[test]
    fn oversized_signature_vec_rejected() {
        let mut w = Writer::new();
        Hash::ZERO.write(&mut w);
        w.u16(0);
        w.len(MAX_QUORUM_SIGNATURES + 1);
        // No signatures follow; length guard trips first.
        assert!(matches!(
            QuorumCertificate::decode(&w.into_bytes()),
            Err(CodecError::LengthOutOfRange)
        ));
    }
}
