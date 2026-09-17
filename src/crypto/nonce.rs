use rand::RngCore;

/// Derives a deterministic 96-bit (12-byte) nonce for a log record.
/// Format: `[generation (4 bytes BE) || record_offset (8 bytes BE)]`
///
/// Uniqueness rests on `(generation, record_offset)`. Within a single generation file,
/// records are strictly append-only, so every record starts at a unique, monotonically
/// increasing byte offset. Across generation rolls, `generation` increases monotonically,
/// ensuring nonces never repeat across the volume's lifetime.
#[inline]
pub fn derive_record_nonce(generation: u64, record_offset: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    let gen_u32 = (generation & 0xFFFF_FFFF) as u32;
    nonce[0..4].copy_from_slice(&gen_u32.to_be_bytes());
    nonce[4..12].copy_from_slice(&record_offset.to_be_bytes());
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
        let n1 = derive_record_nonce(1, 32);
        let n2 = derive_record_nonce(1, 100);
        let n3 = derive_record_nonce(2, 32);

        assert_ne!(n1, n2);
        assert_ne!(n1, n3);
        assert_ne!(n2, n3);

        assert_eq!(&n1[0..4], &1u32.to_be_bytes());
        assert_eq!(&n1[4..12], &32u64.to_be_bytes());
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
