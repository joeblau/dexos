//! Chain identifiers, external wallet addresses, and EVM address derivation.

use serde::{Deserialize, Serialize};

use crypto::keccak256;

use crate::error::CustodyError;
use crate::wire::{Reader, Writer};

/// A numeric chain identifier (EVM chain id, or an internal id for an SVM
/// cluster). Per-chain withdrawal policies are keyed on this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ChainId(pub u64);

impl ChainId {
    /// The raw identifier.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// The virtual-machine family a wallet belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChainKind {
    /// EVM chains (secp256k1 / keccak addresses, 20 bytes).
    Evm,
    /// Solana / SVM (ed25519 pubkey addresses, 32 bytes).
    Svm,
}

/// An external wallet address. The variant fixes both the length and the chain
/// family, so a malformed length or unknown tag is unrepresentable once decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WalletAddress {
    /// A 20-byte EVM address.
    Evm([u8; 20]),
    /// A 32-byte SVM (ed25519 public key) address.
    Svm([u8; 32]),
}

const TAG_EVM: u8 = 1;
const TAG_SVM: u8 = 2;

impl WalletAddress {
    /// The chain family of this address.
    pub const fn kind(&self) -> ChainKind {
        match self {
            Self::Evm(_) => ChainKind::Evm,
            Self::Svm(_) => ChainKind::Svm,
        }
    }

    /// Canonical bytes (tag + raw address), appended to `w`.
    pub(crate) fn encode_into(&self, w: &mut Writer) {
        match self {
            Self::Evm(a) => {
                w.u8(TAG_EVM);
                w.raw(a);
            }
            Self::Svm(a) => {
                w.u8(TAG_SVM);
                w.raw(a);
            }
        }
    }

    /// Decode a tagged address. Unknown tags become [`CustodyError::MalformedAddress`].
    pub(crate) fn decode_from(r: &mut Reader<'_>) -> Result<Self, CustodyError> {
        match r.u8()? {
            TAG_EVM => Ok(Self::Evm(r.array::<20>()?)),
            TAG_SVM => Ok(Self::Svm(r.array::<32>()?)),
            _ => Err(CustodyError::MalformedAddress),
        }
    }
}

/// Derive the 20-byte EVM address from an secp256k1 public key.
///
/// The address is the last 20 bytes of `keccak256` of the 64-byte uncompressed
/// public key (the `X || Y` coordinates). A 65-byte SEC1 key (`0x04 || X || Y`)
/// has its prefix stripped; a bare 64-byte `X || Y` key is accepted directly.
/// Any other length, or a bad SEC1 prefix, is [`CustodyError::MalformedKey`].
///
/// Compressed (33-byte) keys are rejected: they cannot be expanded without a
/// curve implementation, which this crate deliberately does not depend on.
pub fn evm_address_from_pubkey(pubkey: &[u8]) -> Result<[u8; 20], CustodyError> {
    let xy: &[u8] = match pubkey.len() {
        65 => {
            if pubkey[0] != 0x04 {
                return Err(CustodyError::MalformedKey);
            }
            &pubkey[1..]
        }
        64 => pubkey,
        _ => return Err(CustodyError::MalformedKey),
    };
    let digest = keccak256(xy);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&digest[12..]);
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evm_address_known_answer_generator_point() {
        // secp256k1 private key = 1 => public key is the generator G, and the
        // Ethereum address is the widely published 0x7E5F...395Bdf.
        let gx = hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .unwrap();
        let gy = hex::decode("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
            .unwrap();
        let mut uncompressed = vec![0x04u8];
        uncompressed.extend_from_slice(&gx);
        uncompressed.extend_from_slice(&gy);

        let addr = evm_address_from_pubkey(&uncompressed).unwrap();
        assert_eq!(
            hex::encode(addr),
            "7e5f4552091a69125d5dfcb7b8c2659029395bdf"
        );

        // The 64-byte (prefix-stripped) form derives the same address.
        let addr64 = evm_address_from_pubkey(&uncompressed[1..]).unwrap();
        assert_eq!(addr64, addr);
    }

    #[test]
    fn evm_address_rejects_bad_lengths_and_prefix() {
        assert_eq!(
            evm_address_from_pubkey(&[0u8; 33]),
            Err(CustodyError::MalformedKey)
        );
        let mut bad = vec![0x05u8];
        bad.extend_from_slice(&[0u8; 64]);
        assert_eq!(
            evm_address_from_pubkey(&bad),
            Err(CustodyError::MalformedKey)
        );
    }

    #[test]
    fn address_codec_round_trips_and_rejects_unknown_tag() {
        for addr in [WalletAddress::Evm([9u8; 20]), WalletAddress::Svm([3u8; 32])] {
            let mut w = Writer::new();
            addr.encode_into(&mut w);
            let bytes = w.into_vec();
            let mut r = Reader::new(&bytes);
            assert_eq!(WalletAddress::decode_from(&mut r).unwrap(), addr);
        }
        let mut r = Reader::new(&[7u8, 0, 0]);
        assert_eq!(
            WalletAddress::decode_from(&mut r),
            Err(CustodyError::MalformedAddress)
        );
    }
}
