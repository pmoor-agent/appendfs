#[cfg(any(test, feature = "testing"))]
use crate::crypto::cipher::encrypt_payload;
use crate::crypto::cipher::{CipherSuite, CryptoError, decrypt_payload, encrypt_payload_in_place};
use crate::crypto::key_file::MasterKey;
use crate::crypto::nonce::{generate_random_16, generate_random_iv, record_nonce};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use zeroize::Zeroize;

/// Domain-separation contexts for the two subkeys derived from the master key.
///
/// The master key is never used to encrypt anything directly. Deriving separate subkeys
/// keeps the key-check value and the data path in disjoint key spaces, so the KCV's random
/// IV can never collide with a derived record nonce under the same key.
const DATA_KEY_CONTEXT: &str = "appendfs volume data key v1";
const KCV_KEY_CONTEXT: &str = "appendfs key check value v1";
/// Context for the per-file keys records are encrypted under, derived from the data key and
/// the salt in each log file's header.
const LOG_FILE_KEY_CONTEXT: &str = "appendfs log file key v1";

fn derive_subkey(context: &str, master: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key(context, master)
}

/// Computes the key check value: the bare Poly1305 tag over an empty message, with the
/// volume ID as associated data. Encrypting nothing means the KCV reveals no plaintext and
/// costs exactly one tag; binding `volume_id` stops a KCV from being transplanted between
/// volumes to make a wrong key look right.
fn compute_kcv(master: &[u8; 32], volume_id: &[u8; 16], iv: &[u8; 12]) -> Result<[u8; 16], CryptoError> {
    let kcv_key = derive_subkey(KCV_KEY_CONTEXT, master);
    let mut empty = [];
    encrypt_payload_in_place(CipherSuite::ChaCha20Poly1305, &kcv_key, iv, volume_id, &mut empty)
}

/// Which credentials a volume's key was derived from, back when that was a choice.
///
/// Volumes used to pick between a passphrase, a key file, or both, and recorded the pick
/// here. Only key files remain: a passphrase now protects the key file rather than feeding
/// the volume key, so every encrypted volume unlocks the same way and `cipher` alone says
/// whether a key file is needed. Volumes created under the retired modes keep working,
/// because their key file now holds the key those modes derived.
///
/// The field survives only because the header layout is positional - bincode writes this as
/// its variant index, so the order of the variants is part of the on-disk format. Headers
/// keep whatever they were created with; new ones record `KeyFile` or `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum LegacyKeySource {
    None,
    Passphrase,
    KeyFile,
    KeyFileAndPassphrase,
}

/// Volume identity and key-verification material. Always stored in plaintext.
///
/// This is the part of a volume that must be readable *before* the key is known, so a mount
/// can tell "you supplied the wrong key" apart from "this volume is corrupt". Without it a
/// wrong key surfaces as an authentication failure deep inside recovery, which is
/// indistinguishable from bitrot and reads to the user like data loss.
///
/// There is no wrapped key here and no indirection: the user's key *is* the volume key
/// (via [`derive_subkey`]). Losing it loses the volume, and changing it means re-encrypting
/// every generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeHeader {
    pub cipher: CipherSuite,
    /// Retired; see [`LegacyKeySource`]. Never consulted.
    legacy_key_source: LegacyKeySource,
    /// How newly written records are compressed. Governs writes only - each record carries
    /// its own tag inside the encrypted envelope, and that is what readers act on.
    #[serde(default)]
    pub compression: crate::compress::Compression,
    pub volume_id: [u8; 16],
    /// Retired with [`LegacyKeySource`]: the Argon2id salt of passphrase-derived volumes,
    /// zero on every other. Never consulted.
    legacy_kdf_salt: [u8; 16],
    /// Private: nothing outside this module has business reading or writing the check
    /// value. It is only ever produced by [`VolumeHeader::new_encrypted`] and consumed by
    /// [`VolumeHeader::unlock`].
    kcv_iv: [u8; 12],
    kcv_tag: [u8; 16],
}

impl VolumeHeader {
    /// An unencrypted volume: no key, no check value, zero overhead.
    /// Generates a random 16-byte volume ID.
    pub fn plaintext() -> Self {
        Self {
            cipher: CipherSuite::None,
            legacy_key_source: LegacyKeySource::None,
            compression: crate::compress::Compression::None,
            volume_id: generate_random_16(),
            legacy_kdf_salt: [0u8; 16],
            kcv_iv: [0u8; 12],
            kcv_tag: [0u8; 16],
        }
    }

    /// Creates an unencrypted volume header with an all-zero volume ID for deterministic tests.
    #[cfg(any(test, feature = "testing"))]
    pub fn plaintext_for_tests() -> Self {
        Self::deterministic_plaintext(crate::compress::Compression::None)
    }

    /// Internal helper for creating deterministic unencrypted headers (all-zero volume ID).
    pub(crate) fn deterministic_plaintext(compression: crate::compress::Compression) -> Self {
        Self {
            cipher: CipherSuite::None,
            legacy_key_source: LegacyKeySource::None,
            compression,
            volume_id: [0u8; 16],
            legacy_kdf_salt: [0u8; 16],
            kcv_iv: [0u8; 12],
            kcv_tag: [0u8; 16],
        }
    }

    /// Creates an encrypted volume header along with the key needed to read and write it.
    pub fn new_encrypted(
        master: &MasterKey,
        compression: crate::compress::Compression,
    ) -> Result<(Self, VolumeKey), CryptoError> {
        let volume_id = generate_random_16();
        let kcv_iv = generate_random_iv();
        Self::new_encrypted_with_params(master, volume_id, kcv_iv, compression)
    }

    /// Creates an encrypted volume header with explicit parameters (e.g. for deterministic testing/fixtures).
    pub fn new_encrypted_with_params(
        master: &MasterKey,
        volume_id: [u8; 16],
        kcv_iv: [u8; 12],
        compression: crate::compress::Compression,
    ) -> Result<(Self, VolumeKey), CryptoError> {
        let kcv_tag = compute_kcv(&master.key, &volume_id, &kcv_iv)?;

        let header = Self {
            cipher: CipherSuite::ChaCha20Poly1305,
            legacy_key_source: LegacyKeySource::KeyFile,
            compression,
            volume_id,
            legacy_kdf_salt: [0u8; 16],
            kcv_iv,
            kcv_tag,
        };
        let key = VolumeKey::new(
            volume_id,
            CipherSuite::ChaCha20Poly1305,
            derive_subkey(DATA_KEY_CONTEXT, &master.key),
        );

        Ok((header, key))
    }

    /// Verifies `master` against the key check value and returns the volume key.
    ///
    /// Returns [`CryptoError::WrongKey`] - never [`CryptoError::AuthFailed`] - when the key
    /// is simply wrong, so callers can report that plainly instead of alarming the user
    /// about corruption. The check is the AEAD tag comparison itself, so it is
    /// constant-time.
    pub fn unlock(&self, master: &MasterKey) -> Result<VolumeKey, CryptoError> {
        if self.cipher == CipherSuite::None {
            return Ok(VolumeKey::plaintext_with_volume_id(self.volume_id));
        }

        let kcv_key = derive_subkey(KCV_KEY_CONTEXT, &master.key);
        decrypt_payload(
            CipherSuite::ChaCha20Poly1305,
            &kcv_key,
            &self.kcv_iv,
            &self.volume_id,
            &[],
            &self.kcv_tag,
        )
        .map_err(|_| CryptoError::WrongKey)?;

        Ok(VolumeKey::new(
            self.volume_id,
            self.cipher,
            derive_subkey(DATA_KEY_CONTEXT, &master.key),
        ))
    }
}

/// Builds the associated data authenticated alongside a record payload.
///
/// The record nonce already covers `generation` and `sequence` (a mismatch there yields a
/// different nonce, which fails the tag), and `payload_len` is covered implicitly -
/// truncating or extending the ciphertext breaks authentication. `op_code` and `inode` have
/// no such protection, so a bug that mislabelled a record's type or attributed it to the
/// wrong inode would otherwise decrypt cleanly into the wrong place. They are bound here.
///
/// Nothing positional is bound: a record authenticates wherever it sits in its generation.
/// That is deliberate - see "Threat model" in `DESIGN.md` - and is what lets a record be
/// encrypted before its offset is known.
fn record_aad(op_code: u8, inode: u64) -> [u8; 9] {
    let mut aad = [0u8; 9];
    aad[0] = op_code;
    aad[1..9].copy_from_slice(&inode.to_be_bytes());
    aad
}

/// The unlocked key for a volume.
///
/// Immutable for the lifetime of a mount: there is exactly one key, it never rotates, and
/// nothing about it changes at runtime. That is what lets this be a plain value shared by
/// `Arc` with no interior mutability on the write path.
#[derive(Clone)]
pub struct VolumeKey {
    pub volume_id: [u8; 16],
    cipher: CipherSuite,
    key: [u8; 32],
}

impl Drop for VolumeKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Deliberately hand-written rather than derived: a derived `Debug` would print the raw
/// key bytes into any log line, panic message, or assertion failure that formats a value
/// containing one.
impl std::fmt::Debug for VolumeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VolumeKey")
            .field("volume_id", &self.volume_id)
            .field("cipher", &self.cipher)
            .field("key", &"<redacted>")
            .finish()
    }
}

impl VolumeKey {
    fn new(volume_id: [u8; 16], cipher: CipherSuite, key: [u8; 32]) -> Self {
        Self { volume_id, cipher, key }
    }

    /// A no-op key for unencrypted volumes: every operation is an identity pass-through.
    pub fn plaintext() -> Self {
        Self::plaintext_with_volume_id([0u8; 16])
    }

    pub fn plaintext_with_volume_id(volume_id: [u8; 16]) -> Self {
        Self {
            volume_id,
            cipher: CipherSuite::None,
            key: [0u8; 32],
        }
    }

    /// Convenience helper returning `Arc<VolumeKey>` for unencrypted volumes.
    pub fn plaintext_arc() -> Arc<Self> {
        Arc::new(Self::plaintext())
    }

    pub fn cipher(&self) -> CipherSuite {
        self.cipher
    }

    /// Derives the key for one log file from the random salt in its header.
    ///
    /// Each file gets its own key so that record nonces only need to be unique within a file.
    /// Two writers that share this volume key - a fork and its upstream, or two copies of a
    /// volume mounted at once - may well produce files with the same generation number and
    /// the same record sequences, but never with the same salt, and so never under the same
    /// key.
    pub fn log_file_key(&self, key_salt: &[u8; 16]) -> LogFileKey {
        if self.cipher == CipherSuite::None {
            return LogFileKey {
                cipher: CipherSuite::None,
                key: [0u8; 32],
            };
        }
        let mut material = [0u8; 48];
        material[..32].copy_from_slice(&self.key);
        material[32..].copy_from_slice(key_salt);
        let key = blake3::derive_key(LOG_FILE_KEY_CONTEXT, &material);
        material.zeroize();
        LogFileKey {
            cipher: self.cipher,
            key,
        }
    }

    /// Encrypts summary data with an explicit IV and AAD.
    pub fn encrypt_summary(&self, iv: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.cipher == CipherSuite::None {
            return Ok(plaintext.to_vec());
        }
        let mut ct = plaintext.to_vec();
        let tag = encrypt_payload_in_place(self.cipher, &self.key, iv, aad, &mut ct)?;
        ct.extend_from_slice(&tag);
        Ok(ct)
    }

    /// Decrypts summary data with an explicit IV and AAD.
    pub fn decrypt_summary(&self, iv: &[u8; 12], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.cipher == CipherSuite::None {
            return Ok(ciphertext.to_vec());
        }
        if ciphertext.len() < 16 {
            return Err(CryptoError::AuthFailed);
        }
        let (ct, tag) = ciphertext.split_at(ciphertext.len() - 16);
        let tag: &[u8; 16] = tag.try_into().unwrap();
        decrypt_payload(self.cipher, &self.key, iv, aad, ct, tag)
    }
}

/// The key one log file's records are encrypted under; see [`VolumeKey::log_file_key`].
pub struct LogFileKey {
    cipher: CipherSuite,
    key: [u8; 32],
}

impl Drop for LogFileKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Hand-written for the same reason as `VolumeKey`'s: never print key bytes.
impl std::fmt::Debug for LogFileKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogFileKey")
            .field("cipher", &self.cipher)
            .field("key", &"<redacted>")
            .finish()
    }
}

impl LogFileKey {
    /// Encrypts a record payload in-place. A plaintext volume returns it untouched.
    ///
    /// `op_code` and `inode` are authenticated but not encrypted - see [`record_aad`].
    pub fn encrypt_record_in_place(
        &self,
        sequence: u64,
        op_code: u8,
        inode: u64,
        buffer: &mut [u8],
    ) -> Result<[u8; 16], CryptoError> {
        let nonce = record_nonce(sequence);
        let aad = record_aad(op_code, inode);
        super::cipher::encrypt_payload_in_place(self.cipher, &self.key, &nonce, &aad, buffer)
    }

    /// Encrypts a record payload. A plaintext volume returns it untouched.
    ///
    /// `op_code` and `inode` are authenticated but not encrypted - see [`record_aad`].
    #[cfg(any(test, feature = "testing"))]
    pub fn encrypt_record(
        &self,
        sequence: u64,
        op_code: u8,
        inode: u64,
        payload: &[u8],
    ) -> Result<(Vec<u8>, [u8; 16]), CryptoError> {
        let nonce = record_nonce(sequence);
        let aad = record_aad(op_code, inode);
        encrypt_payload(self.cipher, &self.key, &nonce, &aad, payload)
    }

    /// Decrypts a record payload and verifies the authentication tag.
    ///
    /// Fails with `AuthFailed` if `sequence`, `op_code` or `inode` no longer match the values
    /// bound at write time, if the record is read under another file's key, or if the payload
    /// has been tampered with or corrupted.
    pub fn decrypt_record(
        &self,
        sequence: u64,
        op_code: u8,
        inode: u64,
        ciphertext: &[u8],
        expected_tag: &[u8; 16],
    ) -> Result<Vec<u8>, CryptoError> {
        let nonce = record_nonce(sequence);
        let aad = record_aad(op_code, inode);
        decrypt_payload(self.cipher, &self.key, &nonce, &aad, ciphertext, expected_tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stand-in opcode; the crypto layer treats it as an opaque byte.
    const OP: u8 = 1;
    /// Stand-in log file salt.
    const SALT: [u8; 16] = [0x5A; 16];

    #[test]
    fn test_volume_round_trip() {
        let master = MasterKey::new([0x33u8; 32]);
        let (header, key) = VolumeHeader::new_encrypted(&master, crate::compress::Compression::None).unwrap();
        assert_eq!(header.cipher, CipherSuite::ChaCha20Poly1305);

        let payload = b"Record payload for the volume key";
        let (ct, tag) = key.log_file_key(&SALT).encrypt_record(100, OP, 5, payload).unwrap();
        assert_ne!(&ct[..], &payload[..]);

        // A key recovered by unlocking the stored header decrypts what the original wrote.
        let reopened = header.unlock(&master).unwrap();
        assert_eq!(
            reopened
                .log_file_key(&SALT)
                .decrypt_record(100, OP, 5, &ct, &tag)
                .unwrap(),
            payload
        );
        assert_eq!(reopened.volume_id, header.volume_id);
    }

    /// Headers written under a retired credential mode must still parse, write back
    /// unchanged, and unlock with nothing but the key their key file now holds.
    #[test]
    fn test_retired_key_sources_unlock_with_the_key_alone() {
        let master = MasterKey::new([0x5eu8; 32]);
        for source in [LegacyKeySource::Passphrase, LegacyKeySource::KeyFileAndPassphrase] {
            let (mut header, _) = VolumeHeader::new_encrypted(&master, crate::compress::Compression::Zstd).unwrap();
            header.legacy_key_source = source;
            header.legacy_kdf_salt = [0x20u8; 16];

            let bytes = crate::wire::serialize(&header).unwrap();
            let read_back: VolumeHeader = crate::wire::deserialize(&bytes).unwrap();
            assert_eq!(read_back, header, "{:?}", source);
            assert_eq!(crate::wire::serialize(&read_back).unwrap(), bytes, "{:?}", source);
            assert!(read_back.unlock(&master).is_ok(), "{:?}", source);
        }
    }

    #[test]
    fn test_wrong_key_is_distinguishable_from_corruption() {
        let master = MasterKey::new([0x33u8; 32]);
        let (header, _key) = VolumeHeader::new_encrypted(&master, crate::compress::Compression::None).unwrap();

        // The whole point of the KCV: a wrong key is reported as WrongKey, not AuthFailed,
        // so a mount never tells the user their intact volume is corrupt.
        let wrong = MasterKey::new([0x99u8; 32]);
        assert_eq!(header.unlock(&wrong).unwrap_err(), CryptoError::WrongKey);

        // And the right key still opens it.
        assert!(header.unlock(&master).is_ok());
    }

    #[test]
    fn test_kcv_cannot_be_transplanted_between_volumes() {
        let master_a = MasterKey::new([0x11u8; 32]);
        let master_b = MasterKey::new([0x22u8; 32]);
        let (header_a, _) = VolumeHeader::new_encrypted(&master_a, crate::compress::Compression::None).unwrap();
        let (mut header_b, _) = VolumeHeader::new_encrypted(&master_b, crate::compress::Compression::None).unwrap();

        // Splicing A's check value into B's header must not make A's key open B, because
        // the KCV is bound to the volume ID it was minted for.
        header_b.kcv_iv = header_a.kcv_iv;
        header_b.kcv_tag = header_a.kcv_tag;
        assert_eq!(header_b.unlock(&master_a).unwrap_err(), CryptoError::WrongKey);
    }

    #[test]
    fn test_data_and_kcv_subkeys_are_independent() {
        let master = MasterKey::new([0x44u8; 32]);
        let data = derive_subkey(DATA_KEY_CONTEXT, &master.key);
        let kcv = derive_subkey(KCV_KEY_CONTEXT, &master.key);
        assert_ne!(data, kcv);
        assert_ne!(data, master.key);
        assert_ne!(kcv, master.key);
    }

    #[test]
    fn test_record_aad_binds_opcode_and_inode() {
        let master = MasterKey::new([0x33u8; 32]);
        let (_header, key) = VolumeHeader::new_encrypted(&master, crate::compress::Compression::None).unwrap();

        let payload = b"extent belonging to inode 5";
        let file_key = key.log_file_key(&SALT);
        let (ct, tag) = file_key.encrypt_record(32, OP, 5, payload).unwrap();

        // Baseline: the untampered record round-trips.
        assert_eq!(file_key.decrypt_record(32, OP, 5, &ct, &tag).unwrap(), payload);

        // Reattributing the payload to a different inode must fail, even though the
        // ciphertext is byte-for-byte intact.
        assert_eq!(
            file_key.decrypt_record(32, OP, 6, &ct, &tag).unwrap_err(),
            CryptoError::AuthFailed
        );

        // Relabelling the record as a different opcode must fail too.
        assert_eq!(
            file_key.decrypt_record(32, OP + 1, 5, &ct, &tag).unwrap_err(),
            CryptoError::AuthFailed
        );

        // The sequence remains bound via the nonce.
        assert_eq!(
            file_key.decrypt_record(33, OP, 5, &ct, &tag).unwrap_err(),
            CryptoError::AuthFailed
        );
    }

    /// Two log files never share a key, even with the same generation number and the same
    /// record sequences - the case of a fork and its upstream both writing their next
    /// generation. Identical inputs under the two keys must neither decrypt across nor
    /// produce the same ciphertext.
    #[test]
    fn test_log_files_with_different_salts_do_not_share_a_key() {
        let master = MasterKey::new([0x33u8; 32]);
        let (_header, key) = VolumeHeader::new_encrypted(&master, crate::compress::Compression::None).unwrap();
        let upstream = key.log_file_key(&[1u8; 16]);
        let fork = key.log_file_key(&[2u8; 16]);

        let payload = b"same position, same sequence, different branch";
        let (upstream_ct, upstream_tag) = upstream.encrypt_record(0, OP, 5, payload).unwrap();
        let (fork_ct, _) = fork.encrypt_record(0, OP, 5, payload).unwrap();
        assert_ne!(upstream_ct, fork_ct, "same keystream under two salts");
        assert_eq!(
            fork.decrypt_record(0, OP, 5, &upstream_ct, &upstream_tag).unwrap_err(),
            CryptoError::AuthFailed
        );

        // The derivation is deterministic, so a reader re-deriving from the header agrees.
        let reread = key.log_file_key(&[1u8; 16]);
        assert_eq!(
            reread.decrypt_record(0, OP, 5, &upstream_ct, &upstream_tag).unwrap(),
            payload
        );
    }

    #[test]
    fn test_plaintext_key_is_pass_through() {
        let key = VolumeKey::plaintext();
        let payload = b"unencrypted bytes";

        let file_key = key.log_file_key(&SALT);
        let (ct, tag) = file_key.encrypt_record(32, OP, 5, payload).unwrap();
        assert_eq!(&ct[..], &payload[..]);
        assert_eq!(file_key.decrypt_record(32, OP, 5, &ct, &tag).unwrap(), payload);
    }

    #[test]
    fn test_summary_round_trip() {
        let master = MasterKey::new([0x66u8; 32]);
        let (header, key) = VolumeHeader::new_encrypted(&master, crate::compress::Compression::None).unwrap();

        let iv = generate_random_iv();
        let aad = b"summary header bytes";
        let body = b"serialized summary body";

        let ct = key.encrypt_summary(&iv, aad, body).unwrap();
        let reopened = header.unlock(&master).unwrap();
        assert_eq!(reopened.decrypt_summary(&iv, aad, &ct).unwrap(), body);

        // A different AAD (a tampered summary header) must not verify.
        assert_eq!(
            reopened.decrypt_summary(&iv, b"other header", &ct).unwrap_err(),
            CryptoError::AuthFailed
        );
    }

    #[test]
    fn test_plaintext_volume_header_random_id() {
        let h1 = VolumeHeader::plaintext();
        let h2 = VolumeHeader::plaintext();
        assert_ne!(h1.volume_id, [0u8; 16]);
        assert_ne!(h2.volume_id, [0u8; 16]);
        assert_ne!(h1.volume_id, h2.volume_id);

        let h_zero = VolumeHeader::plaintext_for_tests();
        assert_eq!(h_zero.volume_id, [0u8; 16]);
    }
}
