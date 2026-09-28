use rand::RngCore;

/// Builds the 96-bit (12-byte) nonce for a log record.
///
/// ```text
/// byte  0    1    2    3  |  4    5    6    7    8    9   10   11
///      [ generation: 32 ] [              sequence: 64              ]
/// ```
///
/// Uniqueness rests on `(generation, sequence)`. A generation number is never written twice:
/// each log file is created with `CreateNew`, and every mount starts at a generation past the
/// newest one on disk, so a crashed mount's generation is never reused. Within a generation,
/// `sequence` is a counter the writer only ever advances - a rolled-back write gives its
/// sequence numbers up rather than reusing them - so no two records in one file share one.
///
/// The sequence is stored in the record header rather than derived from where the record
/// lands, so encrypting a record needs to know only its destination generation, not its byte
/// offset. The generation is not stored: it is the generation of the file the record is in.
#[inline]
pub fn record_nonce(generation: u32, sequence: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..4].copy_from_slice(&generation.to_be_bytes());
    nonce[4..12].copy_from_slice(&sequence.to_be_bytes());
    nonce
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

    #[test]
    fn test_record_nonce_distinguishes_generation_and_sequence() {
        assert_ne!(record_nonce(1, 0), record_nonce(1, 1));
        assert_ne!(record_nonce(1, 0), record_nonce(2, 0));
        // The sequence has the low eight bytes to itself, so a large sequence can never
        // spill into the generation bits and collide with a record of the next generation.
        assert_ne!(record_nonce(1, u64::MAX), record_nonce(2, 0));
    }

    /// Pins the byte layout against accidental change.
    ///
    /// Only the sequence is written down in the record header; the arrangement of the two
    /// fields inside the nonce is not, so nothing else in the tree would catch a change to it.
    /// Yet shifting a field by one byte makes every existing encrypted record stop
    /// authenticating. Hence explicit expected bytes rather than a second implementation to
    /// compare against, which would only restate the code.
    #[test]
    fn test_nonce_layout_is_pinned() {
        let cases: [(u32, u64, [u8; 12]); 4] = [
            (0, 0, [0; 12]),
            (1, 32, [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 32]),
            (7, 0x0102_0304_0506_0708, [0, 0, 0, 7, 1, 2, 3, 4, 5, 6, 7, 8]),
            (u32::MAX, u64::MAX, [0xFF; 12]),
        ];

        for (generation, sequence, expected) in cases {
            assert_eq!(
                record_nonce(generation, sequence),
                expected,
                "({}, {})",
                generation,
                sequence
            );
        }
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
