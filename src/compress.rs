//! Optional per-record compression, applied before encryption.
//!
//! Compressing then encrypting is the only workable order - ciphertext does not compress -
//! and it is cheap here because a record is already the unit of I/O: an AEAD authenticates a
//! payload as a whole, so a read of any byte already fetches and processes the entire record.
//! Compression rides along inside that existing work rather than adding a new read cost.
//!
//! The trade is a side channel. An observer of a volume can already see record boundaries and
//! sizes; with compression they additionally learn how *compressible* each record was, which
//! distinguishes text from already-compressed media. Records hold one inode's bytes, so there
//! is no cross-file mixing of the kind CRIME exploits, but an attacker who can write chosen
//! bytes into the same file as a secret and watch record sizes learns something about it.

use serde::{Deserialize, Serialize};
use std::io;

/// Upper bound on a decompressed record, guarding against a corrupt or forged length.
///
/// On an encrypted volume the length lives inside the AEAD, so it cannot be forged without
/// the key; this bound is what protects an unencrypted volume, where nothing authenticates it.
pub const MAX_DECOMPRESSED_RECORD: usize = 256 * 1024 * 1024;

/// zstd level. Measured across source text, logs, sparse binary and incompressible data,
/// level 3 sits at near-peak ratio while compressing at 170-690 MB/s; level 6 buys a few
/// percent more for a collapse to 55 MB/s, which would throttle flushing.
const ZSTD_LEVEL: i32 = 3;

/// Minimum saving for a compressed record to be kept, as a fraction of the original.
///
/// Below this the space win does not justify decompressing on every future read, so the
/// record is stored as-is. Matches the ratio ZFS uses for the same decision.
const MIN_SAVING_NUMERATOR: usize = 1;
const MIN_SAVING_DENOMINATOR: usize = 8;

/// How a volume compresses newly written records.
///
/// This governs writes only. What a *reader* does is decided by the record's opcode
/// (`OpCode::Data` vs `OpCode::DataZstd`), which is authenticated via AAD.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum Compression {
    #[default]
    None = 0,
    Zstd = 1,
}

impl Compression {
    pub fn is_enabled(self) -> bool {
        self != Compression::None
    }
}

impl std::fmt::Display for Compression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(match self {
            Compression::None => "None",
            Compression::Zstd => "zstd",
        })
    }
}

/// Compresses `payload` using zstd if compression is beneficial.
pub fn compress_zstd(payload: &[u8]) -> Option<Vec<u8>> {
    if let Ok(compressed) = zstd::bulk::compress(payload, ZSTD_LEVEL) {
        let saved = payload.len().saturating_sub(compressed.len());
        if saved >= payload.len() / MIN_SAVING_DENOMINATOR * MIN_SAVING_NUMERATOR && !compressed.is_empty() {
            return Some(compressed);
        }
    }
    None
}

/// Decompresses a raw zstd frame.
pub fn decompress_zstd(compressed: &[u8]) -> io::Result<Vec<u8>> {
    let original_len = zstd::zstd_safe::get_frame_content_size(compressed)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("zstd frame error: {}", e)))?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "compressed frame missing content size"))?
        as usize;

    if original_len > MAX_DECOMPRESSED_RECORD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "compressed record claims to expand to {} bytes, beyond the {} byte limit",
                original_len, MAX_DECOMPRESSED_RECORD
            ),
        ));
    }

    zstd::bulk::decompress(compressed, original_len).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("record decompression failed: {}", e),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trip_compressible_and_not() {
        let text = "the quick brown fox jumps over the lazy dog. ".repeat(500).into_bytes();
        let compressed = compress_zstd(&text).expect("repetitive text should compress");
        assert!(compressed.len() < text.len() / 2);
        assert_eq!(decompress_zstd(&compressed).unwrap(), text);

        // Incompressible input must not be kept.
        let mut rnd = vec![0u8; 64 * 1024];
        let mut x: u64 = 0x9E3779B97F4A7C15;
        for b in rnd.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = x as u8;
        }
        assert!(compress_zstd(&rnd).is_none(), "random data must not be kept compressed");
    }

    #[test]
    fn test_corrupt_frames_are_rejected() {
        assert!(decompress_zstd(&[]).is_err(), "empty payload");
        assert!(
            decompress_zstd(&[0x28, 0xb5, 0x2f, 0xfd, 0x00]).is_err(),
            "truncated frame"
        );
    }
}
