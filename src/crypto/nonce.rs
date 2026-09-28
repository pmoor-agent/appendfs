use rand::RngCore;

/// Builds the 96-bit (12-byte) nonce for a log record.
///
/// ```text
/// byte  0    1    2    3  |  4    5    6    7    8    9   10   11
///      [    zero: 32     ] [              sequence: 64              ]
/// ```
///
/// Every log file is encrypted under its own key (see [`crate::crypto::LogFileKey`]), so the
/// nonce only has to be unique within one file. `sequence` is a counter the writer starts at 0
/// for each file and only ever advances - a rolled-back write gives its sequence numbers up
/// rather than reusing them - so no two records in one file share one. It is stored in the
/// record header rather than derived from where the record lands, so encrypting a record
/// needs to know only which file it goes to, not its byte offset.
#[inline]
pub fn record_nonce(sequence: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
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

    /// Pins the byte layout against accidental change.
    ///
    /// Only the sequence is written down in the record header; where it sits inside the nonce
    /// is not, so nothing else in the tree would catch a change to it. Yet shifting it by one
    /// byte makes every existing encrypted record stop authenticating. Hence explicit expected
    /// bytes rather than a second implementation to compare against, which would only restate
    /// the code.
    #[test]
    fn test_nonce_layout_is_pinned() {
        let cases: [(u64, [u8; 12]); 4] = [
            (0, [0; 12]),
            (32, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32]),
            (0x0102_0304_0506_0708, [0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]),
            (u64::MAX, [0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
        ];

        for (sequence, expected) in cases {
            assert_eq!(record_nonce(sequence), expected, "{}", sequence);
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
