//! A small, dependency-free CRC-32 (IEEE 802.3, reflected) implementation used
//! to frame log records and snapshots with an integrity checksum.
//!
//! The table is generated at compile time via a `const fn`, so there is no
//! runtime initialization cost and no external dependency. The algorithm is the
//! standard reflected CRC-32 with polynomial `0xEDB88320`, matching `zlib` /
//! `crc32` output, which keeps checksums reproducible across platforms.

/// Reflected generator polynomial for CRC-32 (IEEE 802.3).
const POLY: u32 = 0xEDB8_8320;

/// Precomputed lookup table, one entry per possible input byte.
const TABLE: [u32; 256] = make_table();

/// Build the 256-entry CRC-32 lookup table at compile time.
const fn make_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    // `i` is a `u32` so `i as usize` below is a widening (lossless) conversion,
    // avoiding any narrowing cast that the lint gate would reject.
    let mut i: u32 = 0;
    while i < 256 {
        let mut crc = i;
        let mut bit = 0;
        while bit < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ POLY;
            } else {
                crc >>= 1;
            }
            bit += 1;
        }
        table[i as usize] = crc;
        i += 1;
    }
    table
}

/// Compute the CRC-32 checksum of `data`.
///
/// This is a pure function: identical input always yields identical output on
/// every platform, which is required for deterministic replay and verification.
#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        // `crc ^ byte` masked to a byte is in `0..=255`, so the `as usize`
        // index is a widening conversion.
        let index = ((crc ^ u32::from(byte)) & 0xFF) as usize;
        crc = (crc >> 8) ^ TABLE[index];
    }
    crc ^ 0xFFFF_FFFF
}

#[cfg(test)]
mod tests {
    use super::crc32;

    #[test]
    fn known_vectors() {
        // Canonical CRC-32 test vectors.
        assert_eq!(crc32(b""), 0x0000_0000);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(
            crc32(b"The quick brown fox jumps over the lazy dog"),
            0x414F_A339
        );
    }

    #[test]
    fn detects_single_bit_flip() {
        let data = b"deterministic-exchange-kernel";
        let base = crc32(data);
        let mut flipped = data.to_vec();
        flipped[3] ^= 0x01;
        assert_ne!(base, crc32(&flipped));
    }

    #[test]
    fn empty_and_nonempty_differ() {
        assert_ne!(crc32(b""), crc32(b"\0"));
    }
}
