use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use rand::RngCore;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use zeroize::Zeroize;

pub const PEM_HEADER_ENCRYPTED: &str = "-----BEGIN APPENDFS ENCRYPTED KEY-----";
pub const PEM_FOOTER_ENCRYPTED: &str = "-----END APPENDFS ENCRYPTED KEY-----";
pub const PEM_HEADER_UNENCRYPTED: &str = "-----BEGIN APPENDFS KEY-----";
pub const PEM_FOOTER_UNENCRYPTED: &str = "-----END APPENDFS KEY-----";

pub const PEM_HEADER: &str = PEM_HEADER_ENCRYPTED;
pub const PEM_FOOTER: &str = PEM_FOOTER_ENCRYPTED;
const AAD_V1: &[u8] = b"APPENDFS-ENCRYPTED-KEY-V1";
pub const CURRENT_KEY_FILE_VERSION: u32 = 1;

pub const DEFAULT_ARGON2_MEMORY_KIB: u32 = 64 * 1024;
pub const DEFAULT_ARGON2_ITERATIONS: u32 = 3;
pub const DEFAULT_ARGON2_PARALLELISM: u32 = 1;

/// Parsed metadata and encrypted payload from a PEM-armored key file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedKeyFile {
    pub version: u32,
    pub cipher: String,
    pub kdf: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub salt: [u8; 16],
    pub nonce: [u8; 12],
    pub body: Vec<u8>,
}

/// Checks whether raw file content begins with the encrypted key PEM header.
pub fn is_pem_encrypted_key(content: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(content) else {
        return false;
    };
    text.trim_start().starts_with(PEM_HEADER_ENCRYPTED)
}

/// Checks whether raw file content begins with the unencrypted key PEM header.
pub fn is_pem_unencrypted_key(content: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(content) else {
        return false;
    };
    text.trim_start().starts_with(PEM_HEADER_UNENCRYPTED)
}

#[derive(Default)]
struct RawHeaders {
    version: Option<u32>,
    cipher: Option<String>,
    kdf: Option<String>,
    memory_kib: Option<u32>,
    iterations: Option<u32>,
    parallelism: Option<u32>,
    salt: Option<[u8; 16]>,
    nonce: Option<[u8; 12]>,
    body: Option<Vec<u8>>,
}

impl RawHeaders {
    fn parse_line(&mut self, key: &str, val: &str) -> Result<(), String> {
        match key {
            "version" => {
                self.version = Some(
                    val.parse::<u32>()
                        .map_err(|_| format!("invalid version value '{}'", val))?,
                );
            }
            "cipher" => self.cipher = Some(val.to_string()),
            "kdf" => self.kdf = Some(val.to_string()),
            "argon2-memory" | "memory" => {
                self.memory_kib = Some(
                    val.parse::<u32>()
                        .map_err(|_| format!("invalid memory value '{}'", val))?,
                );
            }
            "argon2-iterations" | "iterations" => {
                self.iterations = Some(
                    val.parse::<u32>()
                        .map_err(|_| format!("invalid iterations value '{}'", val))?,
                );
            }
            "argon2-parallelism" | "parallelism" => {
                self.parallelism = Some(
                    val.parse::<u32>()
                        .map_err(|_| format!("invalid parallelism value '{}'", val))?,
                );
            }
            "salt" => {
                let bytes = hex::decode(val).map_err(|e| format!("invalid hex in salt: {}", e))?;
                if bytes.len() != 16 {
                    return Err(format!(
                        "expected 16-byte salt (32 hex characters), found {} bytes",
                        bytes.len()
                    ));
                }
                let mut s = [0u8; 16];
                s.copy_from_slice(&bytes);
                self.salt = Some(s);
            }
            "nonce" => {
                let bytes = hex::decode(val).map_err(|e| format!("invalid hex in nonce: {}", e))?;
                if bytes.len() != 12 {
                    return Err(format!(
                        "expected 12-byte nonce (24 hex characters), found {} bytes",
                        bytes.len()
                    ));
                }
                let mut n = [0u8; 12];
                n.copy_from_slice(&bytes);
                self.nonce = Some(n);
            }
            "body" => {
                let bytes = hex::decode(val).map_err(|e| format!("invalid hex in body: {}", e))?;
                if bytes.len() != 48 {
                    return Err(format!(
                        "expected 48-byte body (32 bytes key + 16 bytes tag), found {} bytes",
                        bytes.len()
                    ));
                }
                self.body = Some(bytes);
            }
            other => {
                log::debug!("Ignoring unknown header in encrypted key file: {}", other);
            }
        }
        Ok(())
    }
}

/// Parses a PEM-armored encrypted key file string into its components.
pub fn parse_pem_encrypted_key(content: &str) -> Result<EncryptedKeyFile, String> {
    let trimmed = content.trim();
    if !trimmed.starts_with(PEM_HEADER) {
        return Err(format!("missing PEM header '{}'", PEM_HEADER));
    }
    if !trimmed.ends_with(PEM_FOOTER) {
        return Err(format!("missing PEM footer '{}'", PEM_FOOTER));
    }

    let inner = &trimmed[PEM_HEADER.len()..trimmed.len() - PEM_FOOTER.len()];
    let mut raw = RawHeaders::default();

    for line in inner.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((key, val)) = line.split_once(':') else {
            return Err(format!("malformed line in PEM file: {:?}", line));
        };
        raw.parse_line(&key.trim().to_ascii_lowercase(), val.trim())?;
    }

    let version = raw.version.ok_or_else(|| "missing 'Version' header".to_string())?;
    if version != 1 {
        return Err(format!(
            "unsupported key file version {}; only version 1 is supported",
            version
        ));
    }

    let cipher = raw.cipher.ok_or_else(|| "missing 'Cipher' header".to_string())?;
    let normalized_cipher = cipher.to_ascii_lowercase().replace(['-', '_'], "");
    if normalized_cipher != "chacha20poly1305" {
        return Err(format!("unsupported cipher '{}'; expected ChaCha20-Poly1305", cipher));
    }

    let kdf = raw.kdf.ok_or_else(|| "missing 'KDF' header".to_string())?;
    if !kdf.eq_ignore_ascii_case("argon2id") {
        return Err(format!("unsupported KDF '{}'; expected Argon2id", kdf));
    }

    Ok(EncryptedKeyFile {
        version,
        cipher,
        kdf,
        memory_kib: raw.memory_kib.unwrap_or(DEFAULT_ARGON2_MEMORY_KIB),
        iterations: raw.iterations.unwrap_or(DEFAULT_ARGON2_ITERATIONS),
        parallelism: raw.parallelism.unwrap_or(DEFAULT_ARGON2_PARALLELISM),
        salt: raw.salt.ok_or_else(|| "missing 'Salt' header".to_string())?,
        nonce: raw.nonce.ok_or_else(|| "missing 'Nonce' header".to_string())?,
        body: raw.body.ok_or_else(|| "missing 'Body' header".to_string())?,
    })
}

/// Derives a 256-bit wrapping key from a passphrase and salt with specific Argon2id parameters.
fn derive_wrapping_key(
    passphrase: &[u8],
    salt: &[u8; 16],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<[u8; 32], String> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let params =
        Params::new(m_cost_kib, t_cost, p_cost, Some(32)).map_err(|e| format!("Argon2 params error: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| format!("Argon2 derivation error: {}", e))?;

    Ok(key)
}

/// Encrypts a 32-byte master key with a passphrase into PEM format using Argon2id and ChaCha20-Poly1305.
pub fn encrypt_key_to_pem(
    raw_key: &[u8; 32],
    passphrase: &str,
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<String, String> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);

    let mut wrapping_key = derive_wrapping_key(passphrase.as_bytes(), &salt, m_cost_kib, t_cost, p_cost)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&wrapping_key));
    wrapping_key.zeroize();

    let mut buffer = *raw_key;
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), AAD_V1, &mut buffer)
        .map_err(|e| format!("ChaCha20-Poly1305 encryption failed: {}", e))?;

    let mut body = Vec::with_capacity(48);
    body.extend_from_slice(&buffer);
    body.extend_from_slice(tag.as_slice());
    buffer.zeroize();

    let pem = format!(
        "{header}\n\
         Version: 1\n\
         Cipher: ChaCha20-Poly1305\n\
         KDF: Argon2id\n\
         Argon2-Memory: {m_cost}\n\
         Argon2-Iterations: {t_cost}\n\
         Argon2-Parallelism: {p_cost}\n\
         Salt: {salt}\n\
         Nonce: {nonce}\n\
         Body: {body}\n\
         {footer}\n",
        header = PEM_HEADER,
        m_cost = m_cost_kib,
        t_cost = t_cost,
        p_cost = p_cost,
        salt = hex::encode(salt),
        nonce = hex::encode(nonce),
        body = hex::encode(body),
        footer = PEM_FOOTER,
    );

    Ok(pem)
}

/// Decrypts a PEM-armored encrypted key file string, returning the 32-byte master key.
pub fn decrypt_pem_key(pem_content: &str, passphrase: &str) -> Result<[u8; 32], String> {
    let parsed = parse_pem_encrypted_key(pem_content)?;

    let mut wrapping_key = derive_wrapping_key(
        passphrase.as_bytes(),
        &parsed.salt,
        parsed.memory_kib,
        parsed.iterations,
        parsed.parallelism,
    )?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&wrapping_key));
    wrapping_key.zeroize();

    let mut key_buf = [0u8; 32];
    key_buf.copy_from_slice(&parsed.body[0..32]);
    let tag = Tag::from_slice(&parsed.body[32..48]);

    cipher
        .decrypt_in_place_detached(Nonce::from_slice(&parsed.nonce), AAD_V1, &mut key_buf, tag)
        .map_err(|_| "Incorrect passphrase or corrupted key file".to_string())?;

    Ok(key_buf)
}

/// Formats a 32-byte key as a PEM-armored unencrypted key file string.
pub fn format_unencrypted_pem_key(key: &[u8; 32]) -> String {
    format!(
        "{header}\n\
         Version: {version}\n\
         Body: {body}\n\
         {footer}\n",
        header = PEM_HEADER_UNENCRYPTED,
        version = CURRENT_KEY_FILE_VERSION,
        body = hex::encode(key),
        footer = PEM_FOOTER_UNENCRYPTED,
    )
}

/// Parses a PEM-armored unencrypted key file string, returning the 32-byte master key.
pub fn parse_pem_unencrypted_key(content: &str) -> Result<[u8; 32], String> {
    let trimmed = content.trim();
    if !trimmed.starts_with(PEM_HEADER_UNENCRYPTED) {
        return Err(format!("expected '{}' header", PEM_HEADER_UNENCRYPTED));
    }
    if !trimmed.ends_with(PEM_FOOTER_UNENCRYPTED) {
        return Err(format!("expected '{}' footer", PEM_FOOTER_UNENCRYPTED));
    }

    let inner = &trimmed[PEM_HEADER_UNENCRYPTED.len()..trimmed.len() - PEM_FOOTER_UNENCRYPTED.len()];
    let mut version: Option<u32> = None;
    let mut body_bytes: Option<Vec<u8>> = None;

    for line in inner.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim();
            match k.as_str() {
                "version" => {
                    let ver = v.parse::<u32>().map_err(|_| format!("invalid version value '{}'", v))?;
                    if ver != CURRENT_KEY_FILE_VERSION {
                        return Err(format!(
                            "unsupported key file version {}; only version {} is supported",
                            ver, CURRENT_KEY_FILE_VERSION
                        ));
                    }
                    version = Some(ver);
                }
                "body" | "key" => {
                    let bytes = if v.len() == 64 {
                        hex::decode(v).map_err(|e| format!("invalid hex in body: {}", e))?
                    } else {
                        use base64::Engine;
                        use base64::engine::general_purpose::STANDARD;
                        STANDARD
                            .decode(v)
                            .map_err(|e| format!("invalid base64 in body: {}", e))?
                    };
                    body_bytes = Some(bytes);
                }
                _ => {}
            }
        } else {
            let bytes = if line.len() == 64 {
                hex::decode(line).map_err(|e| format!("invalid hex in body line: {}", e))?
            } else {
                use base64::Engine;
                use base64::engine::general_purpose::STANDARD;
                STANDARD
                    .decode(line)
                    .map_err(|e| format!("invalid base64 in body line: {}", e))?
            };
            body_bytes = Some(bytes);
        }
    }

    if version.is_none() {
        return Err("missing 'Version' header".to_string());
    }

    let bytes = body_bytes.ok_or_else(|| "missing key body in PEM file".to_string())?;
    if bytes.len() != 32 {
        return Err(format!("expected 32-byte key, found {} bytes", bytes.len()));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Writes key file content atomically with `0400` file permissions.
///
/// Returns an error if the parent directory does not exist.
///
/// If `path` already exists, an open file descriptor is held to the existing file
/// prior to atomically swapping in the new file via `fs::rename`. Once the new file
/// is safely in place and synced, the old file's blocks are securely overwritten
/// with random garbage and synced before the descriptor is closed (a la `shred`),
/// ensuring atomic replacement safety without prematurely wiping the old key.
pub fn write_key_file_atomic(path: &Path, content: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        if !parent.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Directory '{}' does not exist", parent.display()),
            ));
        }
        if !parent.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                format!("'{}' is not a directory", parent.display()),
            ));
        }
    }

    let old_file = if path.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }
        OpenOptions::new().write(true).open(path).ok()
    } else {
        None
    };

    let pid = std::process::id();
    let tmp_path = format!("{}.tmp.{}", path.display(), pid);
    let tmp_path = Path::new(&tmp_path);

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(tmp_path)?;

    file.write_all(content)?;
    file.sync_all()?;
    drop(file);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(tmp_path, fs::Permissions::from_mode(0o400))?;
    }

    fs::rename(tmp_path, path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o400));
    }

    if let Some(mut old) = old_file
        && let Ok(metadata) = old.metadata()
    {
        let len = metadata.len();
        if len > 0 {
            use std::io::Seek;
            let mut garbage = vec![0u8; len as usize];
            rand::thread_rng().fill_bytes(&mut garbage);
            let _ = old.seek(std::io::SeekFrom::Start(0));
            let _ = old.write_all(&garbage);
            let _ = old.sync_all();
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pem_round_trip_encryption_decryption() {
        let raw_key = [0x42u8; 32];
        let passphrase = "correct horse battery staple";

        // Fast Argon2 params for unit test
        let pem = encrypt_key_to_pem(&raw_key, passphrase, 1024, 1, 1).unwrap();
        assert!(is_pem_encrypted_key(pem.as_bytes()));
        assert!(pem.contains(PEM_HEADER));
        assert!(pem.contains(PEM_FOOTER));
        assert!(pem.contains("Cipher: ChaCha20-Poly1305"));
        assert!(pem.contains("KDF: Argon2id"));

        let decrypted = decrypt_pem_key(&pem, passphrase).unwrap();
        assert_eq!(decrypted, raw_key);

        // Wrong passphrase must fail cleanly
        let err = decrypt_pem_key(&pem, "wrong passphrase").unwrap_err();
        assert!(err.contains("Incorrect passphrase or corrupted key file"));
    }

    #[test]
    fn test_pem_tampered_components_rejected() {
        let raw_key = [0x99u8; 32];
        let passphrase = "secret";
        let pem = encrypt_key_to_pem(&raw_key, passphrase, 1024, 1, 1).unwrap();

        // 1. Missing header
        let without_header = pem.replace(PEM_HEADER, "");
        assert!(parse_pem_encrypted_key(&without_header).is_err());

        // 2. Missing footer
        let without_footer = pem.replace(PEM_FOOTER, "");
        assert!(parse_pem_encrypted_key(&without_footer).is_err());

        // 3. Tampered salt
        let tampered_salt = pem.replace("Salt: ", "Salt: 0000");
        assert!(parse_pem_encrypted_key(&tampered_salt).is_err());

        // 4. Tampered body byte
        let parsed = parse_pem_encrypted_key(&pem).unwrap();
        let mut tampered_body = parsed.body.clone();
        tampered_body[0] ^= 0xff;
        let pem_tampered_body = pem.replace(&hex::encode(&parsed.body), &hex::encode(&tampered_body));
        let err = decrypt_pem_key(&pem_tampered_body, passphrase).unwrap_err();
        assert!(err.contains("Incorrect passphrase or corrupted key file"));
    }

    #[test]
    fn test_atomic_key_file_write_and_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("test.key");

        let content = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n";
        write_key_file_atomic(&key_path, content).unwrap();

        assert_eq!(fs::read(&key_path).unwrap(), content);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::metadata(&key_path).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o400);
        }
    }

    #[test]
    fn test_atomic_key_file_fails_if_parent_dir_missing() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("nonexistent_subdir/test.key");

        let content = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n";
        let err = write_key_file_atomic(&key_path, content).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(!key_path.exists());
    }

    #[test]
    fn test_unencrypted_pem_round_trip() {
        let raw_key = [0xa5u8; 32];
        let pem = format_unencrypted_pem_key(&raw_key);
        assert!(is_pem_unencrypted_key(pem.as_bytes()));
        assert!(!is_pem_encrypted_key(pem.as_bytes()));
        assert!(pem.contains(PEM_HEADER_UNENCRYPTED));
        assert!(pem.contains(PEM_FOOTER_UNENCRYPTED));
        assert!(pem.contains("Version: 1"));

        let parsed = parse_pem_unencrypted_key(&pem).unwrap();
        assert_eq!(parsed, raw_key);

        // Also test base64 variant in body
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD;
        let b64_pem = format!(
            "{}\nVersion: 1\nBody: {}\n{}\n",
            PEM_HEADER_UNENCRYPTED,
            STANDARD.encode(raw_key),
            PEM_FOOTER_UNENCRYPTED,
        );
        let parsed_b64 = parse_pem_unencrypted_key(&b64_pem).unwrap();
        assert_eq!(parsed_b64, raw_key);
    }

    #[test]
    fn test_atomic_key_file_shreds_old_file_on_replace() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("shred_test.key");

        let old_content = b"RECOGNIZEABLE_OLD_SECRET_KEY_MATERIAL_PAYLOAD_STRING_1234567890";
        write_key_file_atomic(&key_path, old_content).unwrap();

        // Keep an open read handle to the old inode before replacing
        let old_handle = fs::File::open(&key_path).unwrap();

        let new_content = b"NEW_KEY_CONTENT_9876543210";
        write_key_file_atomic(&key_path, new_content).unwrap();

        // The current path has the new content
        assert_eq!(fs::read(&key_path).unwrap(), new_content);

        // The old inode was shredded with random bytes
        use std::io::Read;
        let mut old_handle = old_handle;
        use std::io::Seek;
        old_handle.seek(std::io::SeekFrom::Start(0)).unwrap();
        let mut shredded = Vec::new();
        old_handle.read_to_end(&mut shredded).unwrap();
        assert_eq!(shredded.len(), old_content.len());
        assert_ne!(&shredded, old_content);
    }
}
