use crate::crypto::cipher::CryptoError;
use rand::RngCore;

/// Largest generation number encodable in a record nonce.
pub const MAX_NONCE_GENERATION: u64 = u32::MAX as u64;
/// Largest compaction revision encodable in a record nonce.
pub const MAX_NONCE_REVISION: u32 = u16::MAX as u32;
/// Exclusive upper bound on a record offset encodable in a record nonce (256 TiB).
pub const MAX_NONCE_RECORD_OFFSET: u64 = 1 << 48;

/// Derives a deterministic 96-bit (12-byte) nonce for a log record.
///
/// ```text
/// byte  0    1    2    3  |  4    5  |  6    7  |  8    9   10   11
///      [ generation: 32 ] [ rev: 16 ] [ off_hi ] [   off_lo: 32   ]
/// ```
///
/// Uniqueness rests on `(generation, revision, record_offset)`. Within a single generation file
/// revision, records are strictly append-only, so every record starts at a unique, monotonically
/// increasing byte offset. Across generation rolls, `generation` increases monotonically.
/// When a generation is rewritten, compacted, or purged into a new revision, `revision` advances,
/// ensuring nonces never repeat across the volume's lifetime even if records reside at identical
/// byte offsets under the same generation.
///
/// ChaCha20-Poly1305 fixes the nonce at 96 bits, so the three fields have to share that budget.
/// The offset gets 48 of them, split either side of the revision: `record_offset` is the field
/// that actually grows, and the split is what keeps this encoding byte-identical to the one it
/// replaces. That earlier layout spent a full 32 bits on `revision` and truncated both other
/// fields to 32 - so a generation file larger than 4 GiB silently reused a nonce, which under
/// ChaCha20-Poly1305 leaks the XOR of two plaintexts and the Poly1305 one-time key with it.
/// Since every record written so far has `revision == 0` and an offset below 4 GiB, bytes 4..8
/// are zero under both layouts and existing volumes decrypt unchanged.
///
/// Out-of-range coordinates are an error rather than a wrap. Exceeding these bounds is
/// unreachable in practice - 256 TiB in one generation, or 4.29 billion generations - and if
/// one ever were reached, refusing the write costs a failed flush while encoding it anyway
/// would quietly destroy the confidentiality of two records.
#[inline]
pub fn derive_record_nonce(generation: u64, revision: u32, record_offset: u64) -> Result<[u8; 12], CryptoError> {
    if generation > MAX_NONCE_GENERATION {
        return Err(CryptoError::NonceOverflow(format!(
            "generation {} exceeds the maximum of {} encodable in a record nonce",
            generation, MAX_NONCE_GENERATION
        )));
    }
    if revision > MAX_NONCE_REVISION {
        return Err(CryptoError::NonceOverflow(format!(
            "revision {} exceeds the maximum of {} encodable in a record nonce",
            revision, MAX_NONCE_REVISION
        )));
    }
    if record_offset >= MAX_NONCE_RECORD_OFFSET {
        return Err(CryptoError::NonceOverflow(format!(
            "record offset {} reaches the {}-byte limit encodable in a record nonce",
            record_offset, MAX_NONCE_RECORD_OFFSET
        )));
    }

    let mut nonce = [0u8; 12];
    nonce[0..4].copy_from_slice(&(generation as u32).to_be_bytes());
    nonce[4..6].copy_from_slice(&(revision as u16).to_be_bytes());
    nonce[6..8].copy_from_slice(&((record_offset >> 32) as u16).to_be_bytes());
    nonce[8..12].copy_from_slice(&(record_offset as u32).to_be_bytes());
    Ok(nonce)
}

/// Generates a cryptographically random 12-byte IV (used for summaries and key wrapping).
pub fn generate_random_iv() -> [u8; 12] {
    let mut iv = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut iv);
    iv
}

/// Generates a cryptographically random 16-byte salt / volume ID.
pub fn generate_random_16() -> [u8; 16] {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nonce(generation: u64, revision: u32, record_offset: u64) -> [u8; 12] {
        derive_record_nonce(generation, revision, record_offset).unwrap()
    }

    #[test]
    fn test_record_nonce_derivation() {
        let n1 = nonce(1, 0, 32);
        let n2 = nonce(1, 0, 100);
        let n3 = nonce(2, 0, 32);
        let n4 = nonce(1, 1, 32);

        assert_ne!(n1, n2);
        assert_ne!(n1, n3);
        assert_ne!(n2, n3);
        assert_ne!(n1, n4);
        assert_ne!(n3, n4);

        assert_eq!(&n1[0..4], &1u32.to_be_bytes());
        assert_eq!(&n1[4..6], &0u16.to_be_bytes());
        assert_eq!(&n1[6..8], &0u16.to_be_bytes());
        assert_eq!(&n1[8..12], &32u32.to_be_bytes());

        assert_eq!(&n4[0..4], &1u32.to_be_bytes());
        assert_eq!(&n4[4..6], &1u16.to_be_bytes());
        assert_eq!(&n4[6..8], &0u16.to_be_bytes());
        assert_eq!(&n4[8..12], &32u32.to_be_bytes());

        // The high half of a 48-bit offset lands in bytes 6..8, immediately left of the low
        // half, so the offset reads as one contiguous big-endian field.
        let big = nonce(1, 0, (3u64 << 32) | 77);
        assert_eq!(&big[6..8], &3u16.to_be_bytes());
        assert_eq!(&big[8..12], &77u32.to_be_bytes());
    }

    /// The layout this replaced was `[generation:32][revision:32][record_offset:32]`. Every
    /// record ever written has `revision == 0` and an offset below 4 GiB, so both layouts
    /// must agree on that entire range - otherwise existing encrypted volumes stop decrypting.
    #[test]
    fn test_nonce_is_unchanged_for_every_record_written_so_far() {
        fn previous_layout(generation: u64, revision: u32, record_offset: u64) -> [u8; 12] {
            let mut nonce = [0u8; 12];
            nonce[0..4].copy_from_slice(&(generation as u32).to_be_bytes());
            nonce[4..8].copy_from_slice(&revision.to_be_bytes());
            nonce[8..12].copy_from_slice(&(record_offset as u32).to_be_bytes());
            nonce
        }

        for generation in [0u64, 1, 7, 4096, u32::MAX as u64] {
            for offset in [0u64, 32, 4096, 2 * 1024 * 1024 * 1024, u32::MAX as u64] {
                assert_eq!(
                    nonce(generation, 0, offset),
                    previous_layout(generation, 0, offset),
                    "generation {} offset {}",
                    generation,
                    offset
                );
            }
        }
    }

    /// The bug this layout exists to fix: two records 4 GiB apart in one generation used to
    /// derive the same nonce, which under ChaCha20-Poly1305 is fatal rather than cosmetic.
    #[test]
    fn test_offsets_four_gib_apart_no_longer_collide() {
        assert_ne!(nonce(7, 0, 1024), nonce(7, 0, 1024 + (1 << 32)));
        assert_ne!(nonce(7, 0, 0), nonce(7, 0, 1 << 32));

        // And a revision no longer collides with the offset bits it used to share a word with.
        assert_ne!(nonce(7, 1, 0), nonce(7, 0, 1 << 32));
    }

    #[test]
    fn test_out_of_range_coordinates_fail_closed() {
        // Each of these would have silently wrapped onto a nonce already in use.
        for (generation, revision, offset) in [
            (MAX_NONCE_GENERATION + 1, 0, 32),
            (1, MAX_NONCE_REVISION + 1, 32),
            (1, 0, MAX_NONCE_RECORD_OFFSET),
            (1, 0, u64::MAX),
        ] {
            let err = derive_record_nonce(generation, revision, offset)
                .expect_err(&format!("({}, {}, {}) must be refused", generation, revision, offset));
            assert!(
                matches!(err, CryptoError::NonceOverflow(_)),
                "unexpected error for ({}, {}, {}): {}",
                generation,
                revision,
                offset,
                err
            );
        }

        // The boundary values themselves remain usable.
        assert!(derive_record_nonce(MAX_NONCE_GENERATION, MAX_NONCE_REVISION, MAX_NONCE_RECORD_OFFSET - 1).is_ok());
    }

    #[test]
    fn test_random_generators_produce_unique_outputs() {
        let iv1 = generate_random_iv();
        let iv2 = generate_random_iv();
        assert_ne!(iv1, iv2);

        let s1 = generate_random_16();
        let s2 = generate_random_16();
        assert_ne!(s1, s2);
    }
}
