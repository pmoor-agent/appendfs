use rand::RngCore;

/// Derives a deterministic 96-bit (12-byte) nonce for a log record.
/// Format: `[generation (4 bytes BE) || revision (4 bytes BE) || record_offset (4 bytes BE)]`
///
/// Uniqueness rests on `(generation, revision, record_offset)`. Within a single generation file
/// revision, records are strictly append-only, so every record starts at a unique, monotonically
/// increasing byte offset. Across generation rolls, `generation` increases monotonically.
/// When a generation is rewritten, compacted, or purged into a new revision, `revision` advances,
/// ensuring nonces never repeat across the volume's lifetime even if records reside at identical
/// byte offsets under the same generation.
#[inline]
pub fn derive_record_nonce(generation: u64, revision: u32, record_offset: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..4].copy_from_slice(&(generation as u32).to_be_bytes());
    nonce[4..8].copy_from_slice(&revision.to_be_bytes());
    nonce[8..12].copy_from_slice(&(record_offset as u32).to_be_bytes());
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
    fn test_record_nonce_derivation() {
        let n1 = derive_record_nonce(1, 0, 32);
        let n2 = derive_record_nonce(1, 0, 100);
        let n3 = derive_record_nonce(2, 0, 32);
        let n4 = derive_record_nonce(1, 1, 32);

        assert_ne!(n1, n2);
        assert_ne!(n1, n3);
        assert_ne!(n2, n3);
        assert_ne!(n1, n4);
        assert_ne!(n3, n4);

        assert_eq!(&n1[0..4], &1u32.to_be_bytes());
        assert_eq!(&n1[4..8], &0u32.to_be_bytes());
        assert_eq!(&n1[8..12], &32u32.to_be_bytes());

        assert_eq!(&n4[0..4], &1u32.to_be_bytes());
        assert_eq!(&n4[4..8], &1u32.to_be_bytes());
        assert_eq!(&n4[8..12], &32u32.to_be_bytes());
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
