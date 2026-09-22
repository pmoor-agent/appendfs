use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum CipherSuite {
    #[default]
    None = 0,
    ChaCha20Poly1305 = 1,
}

impl CipherSuite {
    pub fn is_encrypted(self) -> bool {
        self != CipherSuite::None
    }
}

impl fmt::Display for CipherSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CipherSuite::None => write!(f, "Plaintext (None)"),
            CipherSuite::ChaCha20Poly1305 => write!(f, "ChaCha20-Poly1305"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    AuthFailed,
    /// The supplied passphrase or key file does not match this volume.
    ///
    /// Kept distinct from [`CryptoError::AuthFailed`] so a wrong key is never reported as
    /// data corruption - the two are otherwise indistinguishable to a caller.
    WrongKey,
    /// Encrypted data was reached with no key supplied at all.
    ///
    /// Distinct from [`CryptoError::WrongKey`]: "you did not provide a key" and "the key
    /// you provided is wrong" call for different things from the user.
    KeyRequired,
    InvalidKeyLength,
    /// A record's coordinates do not fit the 96-bit record nonce.
    ///
    /// Fails the write rather than wrapping: two records sharing a nonce under
    /// ChaCha20-Poly1305 leak the XOR of their plaintexts and the Poly1305 one-time key,
    /// so a refused flush is by far the cheaper outcome.
    NonceOverflow(String),
    IoError(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::AuthFailed => write!(f, "Cryptographic authentication failed (corrupted or tampered data)"),
            CryptoError::WrongKey => write!(
                f,
                "Wrong passphrase or key file for this volume (the volume itself is intact)"
            ),
            CryptoError::KeyRequired => write!(
                f,
                "This volume is encrypted - a passphrase or key file is required to read it"
            ),
            CryptoError::InvalidKeyLength => write!(f, "Invalid cryptographic key length"),
            CryptoError::NonceOverflow(s) => write!(f, "Record nonce space exhausted: {}", s),
            CryptoError::IoError(s) => write!(f, "Crypto I/O error: {}", s),
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<CryptoError> for std::io::Error {
    fn from(err: CryptoError) -> Self {
        match err {
            CryptoError::AuthFailed => std::io::Error::new(std::io::ErrorKind::InvalidData, err),
            CryptoError::WrongKey | CryptoError::KeyRequired => {
                std::io::Error::new(std::io::ErrorKind::PermissionDenied, err)
            }
            CryptoError::NonceOverflow(_) => std::io::Error::new(std::io::ErrorKind::InvalidInput, err),
            _ => std::io::Error::other(err),
        }
    }
}

/// Encrypts `plaintext` producing ciphertext and a detached 16-byte authentication tag.
/// For plaintext volumes (`CipherSuite::None`), produces a 16-byte BLAKE3 tag over `(aad || plaintext)`.
pub fn encrypt_payload(
    cipher: CipherSuite,
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 16]), CryptoError> {
    match cipher {
        CipherSuite::None => {
            let mut hasher = blake3::Hasher::new();
            hasher.update(aad);
            hasher.update(plaintext);
            let mut tag = [0u8; 16];
            tag.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
            Ok((plaintext.to_vec(), tag))
        }
        CipherSuite::ChaCha20Poly1305 => {
            let key = Key::from_slice(key);
            let cipher = ChaCha20Poly1305::new(key);
            let nonce = Nonce::from_slice(nonce);
            let mut buffer = plaintext.to_vec();
            let tag = cipher
                .encrypt_in_place_detached(nonce, aad, &mut buffer)
                .map_err(|_| CryptoError::AuthFailed)?;
            let mut tag_bytes = [0u8; 16];
            tag_bytes.copy_from_slice(&tag);
            Ok((buffer, tag_bytes))
        }
    }
}

/// Decrypts and verifies `ciphertext` using a detached 16-byte authentication tag.
/// For plaintext volumes (`CipherSuite::None`), verifies the 16-byte BLAKE3 tag over `(aad || ciphertext)`.
pub fn decrypt_payload(
    cipher: CipherSuite,
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    expected_tag: &[u8; 16],
) -> Result<Vec<u8>, CryptoError> {
    match cipher {
        CipherSuite::None => {
            let mut hasher = blake3::Hasher::new();
            hasher.update(aad);
            hasher.update(ciphertext);
            if &hasher.finalize().as_bytes()[..16] != expected_tag {
                return Err(CryptoError::AuthFailed);
            }
            Ok(ciphertext.to_vec())
        }
        CipherSuite::ChaCha20Poly1305 => {
            let key = Key::from_slice(key);
            let cipher = ChaCha20Poly1305::new(key);
            let nonce = Nonce::from_slice(nonce);
            let mut buffer = ciphertext.to_vec();
            let tag = Tag::from_slice(expected_tag);
            cipher
                .decrypt_in_place_detached(nonce, aad, &mut buffer, tag)
                .map_err(|_| CryptoError::AuthFailed)?;
            Ok(buffer)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20poly1305_round_trip() {
        let key = [0x42u8; 32];
        let nonce = [0x07u8; 12];
        let aad = b"record_header_bytes";
        let plaintext = b"Hello AppendFS Encrypted World!";

        let (ciphertext, tag) = encrypt_payload(CipherSuite::ChaCha20Poly1305, &key, &nonce, aad, plaintext).unwrap();
        assert_ne!(&ciphertext, plaintext);
        assert_eq!(ciphertext.len(), plaintext.len());

        let decrypted = decrypt_payload(CipherSuite::ChaCha20Poly1305, &key, &nonce, aad, &ciphertext, &tag).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = [0x42u8; 32];
        let nonce = [0x07u8; 12];
        let aad = b"record_header_bytes";
        let plaintext = b"Sensitive filesystem metadata";

        let (mut ciphertext, tag) =
            encrypt_payload(CipherSuite::ChaCha20Poly1305, &key, &nonce, aad, plaintext).unwrap();
        // Tamper with one byte
        ciphertext[0] ^= 0xFF;

        let err = decrypt_payload(CipherSuite::ChaCha20Poly1305, &key, &nonce, aad, &ciphertext, &tag).unwrap_err();
        assert_eq!(err, CryptoError::AuthFailed);
    }

    #[test]
    fn test_tampered_tag_fails() {
        let key = [0x42u8; 32];
        let nonce = [0x07u8; 12];
        let aad = b"record_header_bytes";
        let plaintext = b"Sensitive filesystem metadata";

        let (ciphertext, mut tag) =
            encrypt_payload(CipherSuite::ChaCha20Poly1305, &key, &nonce, aad, plaintext).unwrap();
        tag[0] ^= 0xFF;

        let err = decrypt_payload(CipherSuite::ChaCha20Poly1305, &key, &nonce, aad, &ciphertext, &tag).unwrap_err();
        assert_eq!(err, CryptoError::AuthFailed);
    }

    #[test]
    fn test_tampered_aad_fails() {
        let key = [0x42u8; 32];
        let nonce = [0x07u8; 12];
        let aad = b"record_header_bytes";
        let plaintext = b"Sensitive filesystem metadata";

        let (ciphertext, tag) = encrypt_payload(CipherSuite::ChaCha20Poly1305, &key, &nonce, aad, plaintext).unwrap();
        let wrong_aad = b"different_header_bytes";

        let err = decrypt_payload(
            CipherSuite::ChaCha20Poly1305,
            &key,
            &nonce,
            wrong_aad,
            &ciphertext,
            &tag,
        )
        .unwrap_err();
        assert_eq!(err, CryptoError::AuthFailed);
    }

    #[test]
    fn test_none_cipher_authenticated() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let aad = b"header_data";
        let plaintext = b"Plaintext bytes";

        let (encrypted, tag) = encrypt_payload(CipherSuite::None, &key, &nonce, aad, plaintext).unwrap();
        assert_eq!(&encrypted, plaintext);

        let decrypted = decrypt_payload(CipherSuite::None, &key, &nonce, aad, &encrypted, &tag).unwrap();
        assert_eq!(&decrypted, plaintext);

        // Tampering with payload fails authentication
        let mut tampered = encrypted.clone();
        tampered[0] ^= 0xFF;
        assert_eq!(
            decrypt_payload(CipherSuite::None, &key, &nonce, aad, &tampered, &tag).unwrap_err(),
            CryptoError::AuthFailed
        );

        // Tampering with AAD fails authentication
        assert_eq!(
            decrypt_payload(CipherSuite::None, &key, &nonce, b"corrupted", &encrypted, &tag).unwrap_err(),
            CryptoError::AuthFailed
        );
    }
}
