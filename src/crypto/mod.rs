pub mod cipher;
pub mod kdf;
pub mod nonce;
pub mod volume;

#[cfg(any(test, feature = "testing"))]
pub use cipher::encrypt_payload;
pub use cipher::{CipherSuite, CryptoError, decrypt_payload, encrypt_payload_in_place};
pub use kdf::{MasterKey, prompt_passphrase};
pub use nonce::{generate_random_16, generate_random_iv, record_nonce};
pub use volume::{KeySource, LogFileKey, VolumeHeader, VolumeKey};
