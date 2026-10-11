pub mod cipher;
pub mod key_file;
pub mod nonce;
pub mod volume;

#[cfg(any(test, feature = "testing"))]
pub use cipher::encrypt_payload;
pub use cipher::{CipherSuite, CryptoError, decrypt_payload, encrypt_payload_in_place};
pub use key_file::{
    KeyFile, MasterKey, format_encrypted_key_file, format_plain_key_file, prompt_passphrase, write_new_key_file,
};
pub use nonce::{generate_random_16, generate_random_iv, record_nonce};
pub use volume::{LogFileKey, VolumeHeader, VolumeKey};
