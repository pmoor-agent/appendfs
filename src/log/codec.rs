//! The single path between a record payload in memory and the bytes stored for it.
//!
//! Compression and encryption are always applied together and in one order - compress, then
//! encrypt - so they are exposed as one operation rather than two steps a caller composes.
//! When they were separate, three read paths each had to remember to unwrap the compression
//! envelope after decrypting, and one of them (the keyless branch of `dump`) did not, quietly
//! reporting every payload shifted by a byte. Pairing them here removes the chance to perform
//! half of the transformation.

use crate::compress::Compression;
use crate::crypto::LogFileKey;
use crate::log::record::OpCode;
use std::io;

/// The fields that identify a record for authentication.
///
/// `sequence` forms the nonce; `op_code` and `inode` are bound into the AEAD's associated
/// data, so a payload cannot be relabelled as a different record type or reattributed to
/// another inode. Which file the record belongs to is carried by the [`LogFileKey`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordId {
    pub sequence: u64,
    pub op_code: u8,
    pub inode: u64,
}

/// Turns a payload into the bytes written to the log, returning `(actual_op, ciphertext, auth_tag)`.
pub fn encode(
    key: &LogFileKey,
    compression: Compression,
    id: RecordId,
    payload: &[u8],
) -> io::Result<(OpCode, Vec<u8>, [u8; 16])> {
    let (actual_op, data_to_encrypt) = if id.op_code == OpCode::Data as u8 && compression == Compression::Zstd {
        match crate::compress::compress_zstd(payload) {
            Some(compressed) => (OpCode::DataZstd, compressed),
            None => (OpCode::Data, payload.to_vec()),
        }
    } else {
        let op = OpCode::try_from(id.op_code).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        (op, payload.to_vec())
    };

    let (ciphertext, auth_tag) = key
        .encrypt_record(id.sequence, actual_op as u8, id.inode, &data_to_encrypt)
        .map_err(io::Error::from)?;
    Ok((actual_op, ciphertext, auth_tag))
}

/// Recovers the original payload from bytes read out of the log.
pub fn decode(key: &LogFileKey, id: RecordId, stored: &[u8], auth_tag: &[u8; 16]) -> io::Result<Vec<u8>> {
    let plain = key
        .decrypt_record(id.sequence, id.op_code, id.inode, stored, auth_tag)
        .map_err(io::Error::from)?;
    if id.op_code == OpCode::DataZstd as u8 {
        crate::compress::decompress_zstd(&plain)
    } else {
        Ok(plain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{KeySource, MasterKey, VolumeHeader, VolumeKey};

    const SALT: [u8; 16] = [0x5A; 16];

    const ID: RecordId = RecordId {
        sequence: 17,
        op_code: 1,
        inode: 42,
    };

    fn payload() -> Vec<u8> {
        "log line that repeats and repeats and repeats. "
            .repeat(200)
            .into_bytes()
    }

    #[test]
    fn test_round_trip_across_every_volume_shape() {
        let master = MasterKey::new([0x21u8; 32]);
        let data = payload();

        for compression in [Compression::None, Compression::Zstd] {
            // Unencrypted volume.
            let plain_key = VolumeKey::plaintext().log_file_key(&SALT);
            let (op, stored, tag) = encode(&plain_key, compression, ID, &data).unwrap();
            let rec_id = RecordId {
                op_code: op as u8,
                ..ID
            };
            assert_eq!(
                decode(&plain_key, rec_id, &stored, &tag).unwrap(),
                data,
                "plaintext/{}",
                compression
            );

            // Encrypted volume.
            let (_h, key) = VolumeHeader::new_encrypted(&master, [0u8; 16], KeySource::KeyFile, compression).unwrap();
            let key = key.log_file_key(&SALT);
            let (op, stored, tag) = encode(&key, compression, ID, &data).unwrap();
            assert_ne!(stored, data, "encrypted/{} left the payload readable", compression);
            let rec_id = RecordId {
                op_code: op as u8,
                ..ID
            };
            assert_eq!(
                decode(&key, rec_id, &stored, &tag).unwrap(),
                data,
                "encrypted/{}",
                compression
            );
        }
    }

    #[test]
    fn test_compression_shrinks_the_stored_bytes() {
        let key = VolumeKey::plaintext().log_file_key(&SALT);
        let data = payload();
        let (op_plain, plain, _) = encode(&key, Compression::None, ID, &data).unwrap();
        assert_eq!(op_plain, OpCode::Data);
        let (op_squeezed, squeezed, _) = encode(&key, Compression::Zstd, ID, &data).unwrap();
        assert_eq!(op_squeezed, OpCode::DataZstd);
        assert!(
            squeezed.len() * 4 < plain.len(),
            "expected a large saving on repetitive data: {} -> {}",
            plain.len(),
            squeezed.len()
        );
    }

    #[test]
    fn test_decode_rejects_a_reattributed_record() {
        let master = MasterKey::new([0x21u8; 32]);
        let (_h, volume_key) =
            VolumeHeader::new_encrypted(&master, [0u8; 16], KeySource::KeyFile, Compression::Zstd).unwrap();
        let key = volume_key.log_file_key(&SALT);
        let (op, stored, tag) = encode(&key, Compression::Zstd, ID, &payload()).unwrap();
        let actual_id = RecordId {
            op_code: op as u8,
            ..ID
        };

        // The identity is bound into the nonce and AAD, so an intact record cannot be moved
        // onto another inode, relabelled as another record type, or read under another nonce.
        let other_inode = RecordId {
            inode: ID.inode + 1,
            ..actual_id
        };
        assert!(decode(&key, other_inode, &stored, &tag).is_err());
        let other_op = RecordId {
            op_code: if op == OpCode::DataZstd {
                OpCode::Data as u8
            } else {
                OpCode::DataZstd as u8
            },
            ..actual_id
        };
        assert!(decode(&key, other_op, &stored, &tag).is_err());
        let other_sequence = RecordId {
            sequence: ID.sequence + 1,
            ..actual_id
        };
        assert!(decode(&key, other_sequence, &stored, &tag).is_err());
        let other_file = volume_key.log_file_key(&[0xA5; 16]);
        assert!(decode(&other_file, actual_id, &stored, &tag).is_err());
    }
}
