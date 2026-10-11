//! Key files: the one credential an encrypted volume is unlocked with.
//!
//! A key file holds the volume's 256-bit master key in a small PEM-style envelope, either
//! as-is (`APPENDFS KEY`) or wrapped under a passphrase (`APPENDFS ENCRYPTED KEY`). The
//! passphrase protects the file, not the volume: changing or removing it writes a new key
//! file and leaves every byte of the volume untouched.
//!
//! Key files are only ever written to a path that does not exist yet. Replacing one is left
//! to the user, so no command can destroy the only copy of a volume's key.

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use rand::RngCore;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

const PLAIN_BEGIN: &str = "-----BEGIN APPENDFS KEY-----";
const PLAIN_END: &str = "-----END APPENDFS KEY-----";
const ENCRYPTED_BEGIN: &str = "-----BEGIN APPENDFS ENCRYPTED KEY-----";
const ENCRYPTED_END: &str = "-----END APPENDFS ENCRYPTED KEY-----";

const VERSION: &str = "1";
const CIPHER: &str = "ChaCha20-Poly1305";
const KDF: &str = "Argon2id";
/// Associated data for the wrapped key, so a body can never be mistaken for any other
/// ChaCha20-Poly1305 ciphertext made under the same passphrase.
const AAD_V1: &[u8] = b"APPENDFS-ENCRYPTED-KEY-V1";

/// Argon2id cost parameters for wrapping a key under a passphrase. Recorded in each
/// encrypted key file, so raising the defaults never strands an existing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Argon2Params {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

impl Argon2Params {
    /// 64 MiB, 3 passes, 1 lane.
    const DEFAULT: Self = Self {
        memory_kib: 64 * 1024,
        iterations: 3,
        parallelism: 1,
    };
}

/// A volume's 256-bit master key, wiped from memory on drop.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct MasterKey {
    pub key: [u8; 32],
}

impl MasterKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// A fresh random key, for a new key file.
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        Self { key }
    }

    /// Loads the key from a key file, prompting for its passphrase if it has one.
    pub fn from_file(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        KeyFile::read(path)?
            .unlock(|| prompt_passphrase(&format!("Enter passphrase for key file '{}': ", path.display())))
            .map_err(|e| io::Error::new(e.kind(), format!("cannot unlock key file '{}': {}", path.display(), e)))
    }
}

/// A parsed key file.
pub enum KeyFile {
    /// The key itself, unprotected.
    Plain(MasterKey),
    /// The key wrapped under a passphrase.
    Encrypted(WrappedKey),
}

/// A master key encrypted with ChaCha20-Poly1305 under an Argon2id-stretched passphrase.
pub struct WrappedKey {
    params: Argon2Params,
    salt: [u8; 16],
    nonce: [u8; 12],
    /// The encrypted key followed by its 16-byte tag.
    body: [u8; 48],
}

impl KeyFile {
    /// Reads and parses the key file at `path`. Does not unlock it.
    pub fn read(path: &Path) -> io::Result<Self> {
        let invalid = |reason: &str| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("'{}' is not a valid key file: {}", path.display(), reason),
            )
        };
        let content = fs::read(path)
            .map_err(|e| io::Error::new(e.kind(), format!("cannot read key file '{}': {}", path.display(), e)))?;
        let text = std::str::from_utf8(&content).map_err(|_| invalid("it contains binary data"))?;
        Self::parse(text).map_err(|reason| invalid(&reason))
    }

    /// Parses key file text, accepting exactly what [`format_plain_key_file`] and
    /// [`format_encrypted_key_file`] produce - give or take surrounding whitespace.
    ///
    /// Anything else is rejected rather than interpreted: a key file that parses but means
    /// something other than what was written would silently become the wrong key.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
        let (end, encrypted) = match lines.next() {
            Some(PLAIN_BEGIN) => (PLAIN_END, false),
            Some(ENCRYPTED_BEGIN) => (ENCRYPTED_END, true),
            _ => return Err(format!("expected it to begin with '{}'", PLAIN_BEGIN)),
        };

        let mut fields = Fields(Vec::new());
        let mut closed = false;
        for line in lines {
            if closed {
                return Err(format!("unexpected content after '{}'", end));
            }
            if line == end {
                closed = true;
                continue;
            }
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| format!("malformed line {:?}", line))?;
            fields.0.push((name.trim(), value.trim()));
        }
        if !closed {
            return Err(format!("missing '{}'", end));
        }

        fields.expect("Version", VERSION)?;
        let file = if encrypted {
            fields.expect("Cipher", CIPHER)?;
            fields.expect("KDF", KDF)?;
            KeyFile::Encrypted(WrappedKey {
                params: Argon2Params {
                    memory_kib: fields.number("Argon2-Memory")?,
                    iterations: fields.number("Argon2-Iterations")?,
                    parallelism: fields.number("Argon2-Parallelism")?,
                },
                salt: fields.hex("Salt")?,
                nonce: fields.hex("Nonce")?,
                body: fields.hex("Body")?,
            })
        } else {
            let mut key = fields.hex("Body")?;
            let master = MasterKey::new(key);
            key.zeroize();
            KeyFile::Plain(master)
        };
        fields.finish()?;
        Ok(file)
    }

    pub fn is_encrypted(&self) -> bool {
        matches!(self, KeyFile::Encrypted(_))
    }

    /// Returns the key, calling `passphrase` only if the file is encrypted.
    pub fn unlock(self, passphrase: impl FnOnce() -> io::Result<Zeroizing<String>>) -> io::Result<MasterKey> {
        match self {
            KeyFile::Plain(key) => Ok(key),
            KeyFile::Encrypted(wrapped) => wrapped
                .decrypt(&passphrase()?)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
        }
    }
}

impl WrappedKey {
    fn decrypt(&self, passphrase: &str) -> Result<MasterKey, String> {
        let wrapping_key = derive_wrapping_key(passphrase, &self.salt, self.params)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(wrapping_key.as_ref()));

        let mut key = MasterKey::new([0u8; 32]);
        key.key.copy_from_slice(&self.body[..32]);
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&self.nonce),
                AAD_V1,
                &mut key.key,
                Tag::from_slice(&self.body[32..]),
            )
            .map_err(|_| "incorrect passphrase or corrupted key file".to_string())?;
        Ok(key)
    }
}

/// The `Name: value` lines of a key file, consumed one by one as they are validated.
struct Fields<'a>(Vec<(&'a str, &'a str)>);

impl<'a> Fields<'a> {
    fn take(&mut self, name: &str) -> Result<&'a str, String> {
        let index = self
            .0
            .iter()
            .position(|(n, _)| *n == name)
            .ok_or_else(|| format!("missing '{}' field", name))?;
        Ok(self.0.remove(index).1)
    }

    fn expect(&mut self, name: &str, expected: &str) -> Result<(), String> {
        let value = self.take(name)?;
        if value != expected {
            return Err(format!("unsupported {} '{}'; expected '{}'", name, value, expected));
        }
        Ok(())
    }

    fn number(&mut self, name: &str) -> Result<u32, String> {
        let value = self.take(name)?;
        value
            .parse()
            .map_err(|_| format!("'{}' must be a number, found '{}'", name, value))
    }

    fn hex<const N: usize>(&mut self, name: &str) -> Result<[u8; N], String> {
        let mut bytes = hex::decode(self.take(name)?).map_err(|e| format!("'{}' is not valid hex: {}", name, e))?;
        let array = <[u8; N]>::try_from(bytes.as_slice())
            .map_err(|_| format!("'{}' must be {} hex characters, found {}", name, N * 2, bytes.len() * 2));
        bytes.zeroize();
        array
    }

    /// Fails on any field left over, which includes a duplicate of one already taken.
    fn finish(self) -> Result<(), String> {
        match self.0.first() {
            Some((name, _)) => Err(format!("unexpected '{}' field", name)),
            None => Ok(()),
        }
    }
}

fn derive_wrapping_key(passphrase: &str, salt: &[u8; 16], params: Argon2Params) -> Result<Zeroizing<[u8; 32]>, String> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let argon2_params = Params::new(params.memory_kib, params.iterations, params.parallelism, Some(32))
        .map_err(|e| format!("invalid Argon2 parameters: {}", e))?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params)
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut())
        .map_err(|e| format!("Argon2 derivation failed: {}", e))?;
    Ok(key)
}

/// Formats `key` as an unprotected key file.
pub fn format_plain_key_file(key: &MasterKey) -> Zeroizing<String> {
    Zeroizing::new(format!(
        "{PLAIN_BEGIN}\n\
         Version: {VERSION}\n\
         Body: {body}\n\
         {PLAIN_END}\n",
        body = hex::encode(key.key),
    ))
}

/// Formats `key` as a key file wrapped under `passphrase`, with a fresh salt and nonce.
pub fn format_encrypted_key_file(key: &MasterKey, passphrase: &str) -> Result<String, String> {
    let params = Argon2Params::DEFAULT;
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);

    let wrapping_key = derive_wrapping_key(passphrase, &salt, params)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(wrapping_key.as_ref()));

    let mut body = [0u8; 48];
    body[..32].copy_from_slice(&key.key);
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), AAD_V1, &mut body[..32])
        .map_err(|e| format!("ChaCha20-Poly1305 encryption failed: {}", e))?;
    body[32..].copy_from_slice(&tag);

    Ok(format!(
        "{ENCRYPTED_BEGIN}\n\
         Version: {VERSION}\n\
         Cipher: {CIPHER}\n\
         KDF: {KDF}\n\
         Argon2-Memory: {memory}\n\
         Argon2-Iterations: {iterations}\n\
         Argon2-Parallelism: {parallelism}\n\
         Salt: {salt}\n\
         Nonce: {nonce}\n\
         Body: {body}\n\
         {ENCRYPTED_END}\n",
        memory = params.memory_kib,
        iterations = params.iterations,
        parallelism = params.parallelism,
        salt = hex::encode(salt),
        nonce = hex::encode(nonce),
        body = hex::encode(body),
    ))
}

/// Prompts on the terminal for a passphrase without echo, or reads one line from stdin
/// when it is not a terminal.
pub fn prompt_passphrase(prompt: &str) -> io::Result<Zeroizing<String>> {
    use std::io::{BufRead, IsTerminal};

    if io::stdin().is_terminal() {
        return rpassword::prompt_password(prompt).map(Zeroizing::new);
    }
    let mut line = Zeroizing::new(String::new());
    io::stdin().lock().read_line(&mut line)?;
    if line.ends_with('\n') {
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
    }
    Ok(line)
}

/// Writes a new key file at `path`, which must not exist yet.
///
/// The file is created read-only for its owner (`0400`) before a byte of the key reaches
/// it, so there is no window in which it is readable by anyone else. It is never written
/// over: a key file is often the only copy of a volume's key, and replacing one is left to
/// the user. A write that fails part-way removes what it created rather than leave a
/// truncated key behind.
pub fn write_new_key_file(path: &Path, content: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(path)
        .map_err(|e| match e.kind() {
            io::ErrorKind::AlreadyExists => io::Error::new(
                e.kind(),
                format!("'{}' already exists; refusing to overwrite it", path.display()),
            ),
            _ => io::Error::new(e.kind(), format!("cannot create '{}': {}", path.display(), e)),
        })?;

    let written = file.write_all(content).and_then(|()| file.sync_all());
    if let Err(e) = written {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(io::Error::new(
            e.kind(),
            format!("cannot write '{}': {}", path.display(), e),
        ));
    }

    // Make the new directory entry durable too, or a crash could lose the file outright.
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(dir)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passphrase(p: &str) -> impl FnOnce() -> io::Result<Zeroizing<String>> + '_ {
        move || Ok(Zeroizing::new(p.to_string()))
    }

    fn no_passphrase() -> io::Result<Zeroizing<String>> {
        panic!("an unencrypted key file must not ask for a passphrase")
    }

    fn unlock(text: &str, pass: &str) -> io::Result<[u8; 32]> {
        Ok(KeyFile::parse(text).unwrap().unlock(passphrase(pass))?.key)
    }

    #[test]
    fn test_plain_round_trip() {
        let key = MasterKey::new([0xa5u8; 32]);
        let text = format_plain_key_file(&key);
        let parsed = KeyFile::parse(&text).unwrap();
        assert!(!parsed.is_encrypted());
        assert_eq!(parsed.unlock(no_passphrase).unwrap().key, key.key);
    }

    #[test]
    fn test_encrypted_round_trip_needs_the_right_passphrase() {
        let key = MasterKey::new([0x42u8; 32]);
        let text = format_encrypted_key_file(&key, "correct horse").unwrap();
        assert!(KeyFile::parse(&text).unwrap().is_encrypted());
        assert_eq!(unlock(&text, "correct horse").unwrap(), key.key);

        let err = unlock(&text, "wrong horse").unwrap_err();
        assert!(err.to_string().contains("incorrect passphrase"), "{}", err);
    }

    /// Key files written before this parser existed must keep opening: the production
    /// volume's key file is one of these, byte for byte.
    #[test]
    fn test_existing_key_files_still_parse() {
        let plain = "-----BEGIN APPENDFS KEY-----\n\
                     Version: 1\n\
                     Body: 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\n\
                     -----END APPENDFS KEY-----\n";
        assert_eq!(unlock(plain, "").unwrap()[..4], [1, 2, 3, 4]);

        // The v1_passphrase_compressed fixture's key file, written with cheap Argon2
        // parameters by the since-removed `--fast` flag. Such files must keep opening too.
        let encrypted = "-----BEGIN APPENDFS ENCRYPTED KEY-----\n\
                         Version: 1\n\
                         Cipher: ChaCha20-Poly1305\n\
                         KDF: Argon2id\n\
                         Argon2-Memory: 1024\n\
                         Argon2-Iterations: 1\n\
                         Argon2-Parallelism: 1\n\
                         Salt: f61e01e40f1486f6a86753bfe4d7cdcf\n\
                         Nonce: 7ffc285a9177fa58f2038134\n\
                         Body: 5ca38c7633b9c9d756197c8a5d2f240f53f5d20ffef7094db8d0f0b24a1123534b3cd72b9b8507c629b46d9d1c9e3b8f\n\
                         -----END APPENDFS ENCRYPTED KEY-----\n";
        assert_eq!(
            hex::encode(unlock(encrypted, "passphrase").unwrap()),
            "4d193aa79c5c88868873474601f95bac7b8b5e0fa0a1a4eaed518e53f977b0eb"
        );
    }

    #[test]
    fn test_surrounding_whitespace_is_ignored() {
        let key = MasterKey::new([0x17u8; 32]);
        let text = format_plain_key_file(&key);
        for variant in [
            format!("\n\n{}\n\n", *text),
            text.replace('\n', "\r\n"),
            text.replace(": ", ":   "),
        ] {
            assert_eq!(unlock(&variant, "").unwrap(), key.key, "{:?}", variant);
        }
    }

    #[test]
    fn test_anything_but_a_key_file_is_rejected() {
        let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let plain = format!("{PLAIN_BEGIN}\nVersion: 1\nBody: {hex}\n{PLAIN_END}\n");
        let cases: Vec<(&str, String)> = vec![
            ("legacy bare hex key", format!("{}\n", hex)),
            ("empty file", String::new()),
            ("missing end", plain.replace(PLAIN_END, "")),
            ("mismatched end", plain.replace(PLAIN_END, ENCRYPTED_END)),
            ("content after end", format!("{}trailing\n", plain)),
            ("missing version", plain.replace("Version: 1\n", "")),
            ("unsupported version", plain.replace("Version: 1", "Version: 2")),
            ("missing body", plain.replace(&format!("Body: {hex}\n"), "")),
            ("short body", plain.replace(hex, &hex[..62])),
            ("non-hex body", plain.replace(hex, &hex.replace('0', "z"))),
            (
                "base64 body",
                plain.replace(hex, "ASNFZ4mrze8BI0VniavN7wEjRWeJq83vASNFZ4mrze8="),
            ),
            (
                "duplicate body",
                plain.replace("Version: 1\n", &format!("Version: 1\nBody: {hex}\n")),
            ),
            (
                "unknown field",
                plain.replace("Version: 1\n", "Version: 1\nComment: hi\n"),
            ),
            ("field name case", plain.replace("Body:", "body:")),
            (
                "line without colon",
                plain.replace("Version: 1\n", "Version: 1\noops\n"),
            ),
        ];
        for (name, text) in cases {
            assert!(KeyFile::parse(&text).is_err(), "{} was accepted", name);
        }
    }

    #[test]
    fn test_tampered_encrypted_key_files_are_rejected() {
        let key = MasterKey::new([0x99u8; 32]);
        let text = format_encrypted_key_file(&key, "secret").unwrap();

        // Malformed or missing parameters fail to parse.
        assert!(KeyFile::parse(&text.replace("Salt: ", "Salt: 00")).is_err());
        assert!(KeyFile::parse(&text.replace("KDF: Argon2id", "KDF: scrypt")).is_err());
        assert!(KeyFile::parse(&text.replace("Argon2-Memory: 65536\n", "")).is_err());

        // A changed parameter parses but derives a different wrapping key, and a flipped
        // body byte breaks the tag; either way the passphrase no longer opens it.
        let body = text.lines().find_map(|l| l.strip_prefix("Body: ")).unwrap().to_string();
        let mut flipped = hex::decode(&body).unwrap();
        flipped[0] ^= 0xff;
        for tampered in [
            text.replace("Argon2-Iterations: 3", "Argon2-Iterations: 2"),
            text.replace(&body, &hex::encode(flipped)),
        ] {
            let err = unlock(&tampered, "secret").unwrap_err();
            assert!(err.to_string().contains("incorrect passphrase"), "{}", err);
        }
    }

    #[test]
    fn test_master_key_from_file_reports_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.key");
        fs::write(
            &path,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
        )
        .unwrap();
        let err = MasterKey::from_file(&path).err().expect("bare hex must be rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("bad.key"), "{}", err);
        assert!(err.to_string().contains("not a valid key file"), "{}", err);

        let key = MasterKey::new([0x3cu8; 32]);
        fs::write(&path, format_plain_key_file(&key).as_bytes()).unwrap();
        assert_eq!(MasterKey::from_file(&path).unwrap().key, key.key);
    }

    #[test]
    fn test_new_key_file_is_owner_read_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.key");

        write_new_key_file(&path, b"key material").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"key material");
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o400);
    }

    #[test]
    fn test_new_key_file_never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("existing.key");
        fs::write(&path, b"the only copy of a volume key").unwrap();

        let err = write_new_key_file(&path, b"a different key").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert!(err.to_string().contains("refusing to overwrite"), "{}", err);
        assert_eq!(fs::read(&path).unwrap(), b"the only copy of a volume key");
    }

    #[test]
    fn test_new_key_file_does_not_follow_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let link = dir.path().join("link.key");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert!(write_new_key_file(&link, b"key").is_err());
        assert!(!target.exists());
    }

    #[test]
    fn test_new_key_file_fails_if_parent_dir_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent_subdir/test.key");

        let err = write_new_key_file(&path, b"key").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(!path.exists());
    }
}
