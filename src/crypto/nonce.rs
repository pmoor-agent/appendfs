use crate::crypto::cipher::CryptoError;
use rand::RngCore;

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
/// `record_offset` takes 48 of them because it is the field that actually grows; an earlier
/// layout spent a full 32 bits on `revision` and truncated the offset to 32, so a generation
/// file larger than 4 GiB silently reused a nonce - which under ChaCha20-Poly1305 leaks the
/// XOR of two plaintexts and the Poly1305 one-time key with it.
///
/// Two of the three coordinates need no bound check at all: `generation` is a `u32` and
/// `revision` a `u16` everywhere they exist, on disk and in memory alike, so neither can
/// overflow its field. Only `record_offset` is checked, because a file offset is naturally a
/// `u64` and 48 bits is a real limit rather than a type. Reaching it needs 256 TiB in one
/// generation, and if it ever were reached, refusing the write costs a failed flush while
/// encoding it anyway would quietly destroy the confidentiality of two records.
#[inline]
pub fn derive_record_nonce(generation: u32, revision: u16, record_offset: u64) -> Result<[u8; 12], CryptoError> {
    if record_offset >= MAX_NONCE_RECORD_OFFSET {
        return Err(CryptoError::NonceOverflow(format!(
            "record offset {} reaches the {}-byte limit encodable in a record nonce",
            record_offset, MAX_NONCE_RECORD_OFFSET
        )));
    }

    let mut nonce = [0u8; 12];
    nonce[0..4].copy_from_slice(&generation.to_be_bytes());
    nonce[4..6].copy_from_slice(&revision.to_be_bytes());
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

    fn nonce(generation: u32, revision: u16, record_offset: u64) -> [u8; 12] {
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

    /// Pins the byte layout against accidental change.
    ///
    /// A nonce is part of the on-disk format in every sense that matters - shift a field by
    /// one byte and every existing encrypted record stops authenticating - but unlike the
    /// headers it is never written down, so nothing else in the tree would catch a change to
    /// it. Hence explicit expected bytes rather than a second implementation to compare
    /// against, which would only restate the code.
    #[test]
    fn test_nonce_layout_is_pinned() {
        let cases: [(u32, u16, u64, [u8; 12]); 4] = [
            (0, 0, 0, [0; 12]),
            (1, 0, 32, [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 32]),
            (
                7,
                2,
                0x0000_1234_5678_9abc,
                [0, 0, 0, 7, 0, 2, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc],
            ),
            (u32::MAX, u16::MAX, (1 << 48) - 1, [0xFF; 12]),
        ];

        for (generation, revision, offset, expected) in cases {
            assert_eq!(
                nonce(generation, revision, offset),
                expected,
                "({}, {}, {})",
                generation,
                revision,
                offset
            );
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

    /// Only `record_offset` appears here: `generation` is a `u32` and `revision` a `u16` end
    /// to end, so neither has an out-of-range value to pass. For those two the type is the
    /// check; this is what is left over.
    #[test]
    fn test_out_of_range_offset_fails_closed() {
        // Each of these would have silently wrapped onto a nonce already in use.
        for (generation, revision, offset) in [
            (1, 0, MAX_NONCE_RECORD_OFFSET),
            (1, 0, u64::MAX),
            (u32::MAX, u16::MAX, MAX_NONCE_RECORD_OFFSET),
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
        assert!(derive_record_nonce(u32::MAX, u16::MAX, MAX_NONCE_RECORD_OFFSET - 1).is_ok());
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
