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
pub const ZSTD_LEVEL: i32 = 3;

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

use std::cell::RefCell;

thread_local! {
    static COMPRESSOR: RefCell<Option<zstd::bulk::Compressor<'static>>> = const { RefCell::new(None) };
    static DECOMPRESSOR: RefCell<Option<zstd::bulk::Decompressor<'static>>> = const { RefCell::new(None) };
}

fn with_compressor<R>(f: impl FnOnce(&mut zstd::bulk::Compressor<'static>) -> io::Result<R>) -> io::Result<R> {
    COMPRESSOR.with_borrow_mut(|slot| {
        let val = match slot {
            Some(v) => v,
            None => {
                *slot = Some(zstd::bulk::Compressor::new(ZSTD_LEVEL)?);
                slot.as_mut().unwrap()
            }
        };
        f(val)
    })
}

fn with_decompressor<R>(f: impl FnOnce(&mut zstd::bulk::Decompressor<'static>) -> io::Result<R>) -> io::Result<R> {
    DECOMPRESSOR.with_borrow_mut(|slot| {
        let val = match slot {
            Some(v) => v,
            None => {
                *slot = Some(zstd::bulk::Decompressor::new()?);
                slot.as_mut().unwrap()
            }
        };
        f(val)
    })
}

fn decompress_zstd_buffered(compressed: &[u8], capacity: usize) -> io::Result<Vec<u8>> {
    with_decompressor(|d| d.decompress(compressed, capacity))
}

/// Compresses `payload` unconditionally using zstd.
pub fn compress_zstd_unconditional(payload: &[u8]) -> io::Result<Vec<u8>> {
    with_compressor(|c| c.compress(payload))
}

/// Returns true if compression achieves at least the required space saving threshold.
pub fn is_compression_beneficial(original_len: usize, compressed_len: usize) -> bool {
    let saved = original_len.saturating_sub(compressed_len);
    saved >= original_len / MIN_SAVING_DENOMINATOR * MIN_SAVING_NUMERATOR && compressed_len > 0
}

/// Compresses `payload` directly into `dst` using the thread-local compressor.
pub fn compress_zstd_into(payload: &[u8], dst: &mut [u8]) -> io::Result<usize> {
    with_compressor(|c| c.compress_to_buffer(payload, dst))
}

/// Compresses `payload` using zstd if compression is beneficial.
pub fn compress_zstd(payload: &[u8]) -> Option<Vec<u8>> {
    if let Ok(compressed) = compress_zstd_unconditional(payload)
        && is_compression_beneficial(payload.len(), compressed.len())
    {
        return Some(compressed);
    }
    None
}

/// Inspects the zstd frame header to determine the uncompressed content size
/// without decompressing the payload.
pub fn zstd_frame_content_size(compressed: &[u8]) -> io::Result<usize> {
    let frame_size = zstd::zstd_safe::get_frame_content_size(compressed)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("zstd frame error: {}", e)))?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "compressed frame missing content size"))?
        as usize;

    if frame_size > MAX_DECOMPRESSED_RECORD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "compressed payload claims to expand to {} bytes, beyond the {} byte limit",
                frame_size, MAX_DECOMPRESSED_RECORD
            ),
        ));
    }

    Ok(frame_size)
}

/// Decompresses a raw zstd frame verifying that its decompressed size matches `expected_len`.
pub fn decompress_zstd_exact(compressed: &[u8], expected_len: usize) -> io::Result<Vec<u8>> {
    if expected_len > MAX_DECOMPRESSED_RECORD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "compressed payload claims to expand to {} bytes, beyond the {} byte limit",
                expected_len, MAX_DECOMPRESSED_RECORD
            ),
        ));
    }

    let frame_size = zstd_frame_content_size(compressed)?;

    if frame_size != expected_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "zstd frame content size mismatch: expected {} bytes, frame declares {}",
                expected_len, frame_size
            ),
        ));
    }

    let decompressed = decompress_zstd_buffered(compressed, expected_len)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("decompression failed: {}", e)))?;

    if decompressed.len() != expected_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "decompressed size mismatch: expected {} bytes, got {}",
                expected_len,
                decompressed.len()
            ),
        ));
    }

    Ok(decompressed)
}

/// Decompresses a raw zstd frame with a maximum decompressed size limit.
pub fn decompress_zstd_with_limit(compressed: &[u8], max_len: usize) -> io::Result<Vec<u8>> {
    let original_len = zstd_frame_content_size(compressed)?;

    if original_len > max_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "compressed payload claims to expand to {} bytes, beyond the {} byte limit",
                original_len, max_len
            ),
        ));
    }

    decompress_zstd_buffered(compressed, original_len)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("decompression failed: {}", e)))
}

/// Decompresses a raw zstd frame.
pub fn decompress_zstd(compressed: &[u8]) -> io::Result<Vec<u8>> {
    decompress_zstd_with_limit(compressed, MAX_DECOMPRESSED_RECORD)
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

    #[test]
    fn test_unconditional_compression_and_limits() {
        // Incompressible data is compressed anyway when using unconditional compression
        let mut rnd = vec![0u8; 4096];
        let mut x: u64 = 0x123456789ABCDEF;
        for b in rnd.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = x as u8;
        }
        let compressed = compress_zstd_unconditional(&rnd).expect("unconditional compress should succeed");
        assert_eq!(decompress_zstd_with_limit(&compressed, 4096).unwrap(), rnd);

        // Limit rejection
        let err = decompress_zstd_with_limit(&compressed, 4095).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("beyond the 4095 byte limit"));

        // Empty payload
        let compressed_empty = compress_zstd_unconditional(&[]).expect("empty payload compresses");
        assert_eq!(decompress_zstd(&compressed_empty).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_decompress_zstd_exact() {
        let text = b"test payload for exact decompression";
        let compressed = compress_zstd_unconditional(text).unwrap();

        // Exact match
        assert_eq!(decompress_zstd_exact(&compressed, text.len()).unwrap(), text);

        // Mismatched expected length (smaller)
        let err = decompress_zstd_exact(&compressed, text.len() - 1).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("size mismatch"));

        // Mismatched expected length (larger)
        let err = decompress_zstd_exact(&compressed, text.len() + 1).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("size mismatch"));

        // Exceeding MAX_DECOMPRESSED_RECORD
        let err = decompress_zstd_exact(&compressed, MAX_DECOMPRESSED_RECORD + 1).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("beyond the"));
    }

    #[test]
    fn test_zstd_frame_content_size() {
        let text = b"test payload for frame content size inspection";
        let compressed = compress_zstd_unconditional(text).unwrap();
        assert_eq!(zstd_frame_content_size(&compressed).unwrap(), text.len());

        // Corrupt / empty / truncated frame
        assert!(zstd_frame_content_size(&[]).is_err());
        assert!(zstd_frame_content_size(&[0x28, 0xb5, 0x2f, 0xfd, 0x00]).is_err());
    }
}
