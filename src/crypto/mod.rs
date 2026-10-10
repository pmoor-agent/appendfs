pub mod cipher;
pub mod kdf;
pub mod key_file;
pub mod nonce;
pub mod volume;

#[cfg(any(test, feature = "testing"))]
pub use cipher::encrypt_payload;
pub use cipher::{CipherSuite, CryptoError, decrypt_payload, encrypt_payload_in_place};
pub use kdf::{KEY_HEX_LEN, MasterKey, load_key_from_file_with_passphrase, parse_hex_key, prompt_passphrase};
pub use key_file::{
    EncryptedKeyFile, decrypt_pem_key, encrypt_key_to_pem, format_unencrypted_pem_key, is_pem_encrypted_key,
    is_pem_unencrypted_key, parse_pem_encrypted_key, parse_pem_unencrypted_key, write_key_file_atomic,
};
pub use nonce::{generate_random_16, generate_random_iv, record_nonce};
pub use volume::{KeySource, LogFileKey, VolumeHeader, VolumeKey};
