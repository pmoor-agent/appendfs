# Design: Native In-Engine Encryption & Key Rotation

This document captures the proposed design for native at-rest encryption, envelope key management, key rotation, and cryptographic erasure in `appendfs`.

---

## 1. Core Architecture & Philosophy

`appendfs` uses **native, in-engine AEAD encryption** directly on `.log` records and `.summary` files. 

### Why Native In-Engine vs S3-Only?
1. **Zero-Knowledge by Default**: Local NVMe/SSDs, removable drives, and S3 object storage are all encrypted at rest.
2. **Bit-for-bit S3 Sync**: Uploading immutable `.log` and `.summary` files to S3 requires no cloud-side crypto proxy—S3 only ever stores opaque encrypted blobs.
3. **Selective Plaintext Mode**: Non-encrypted volumes incur zero performance or format overhead (`appendfs init --encrypt` vs default plaintext).

---

## 2. Cryptographic Primitives

- **Cipher Suite**: **XChaCha20-Poly1305** (or **AES-256-GCM**)
  - Authenticated Encryption with Associated Data (AEAD) with a 128-bit authentication tag per block/record.
  - 192-bit extended nonces allow safe random nonces per record/extent without nonce exhaustion or collision risk.
- **Key Derivation (KDF)**: **Argon2id** (memory-hard KDF resistant to GPU/ASIC attacks) to derive a Key Encryption Key (KEK) from a user passphrase, or raw 256-bit key files.

---

## 3. Envelope Encryption & KeyRing Hierarchy

```
                 +--------------------------------+
                 | Master Key / Passphrase (KEK)  |
                 +---------------+----------------+
                                 | (Wrapped via Argon2id + ChaCha/AES-KW)
        +------------------------+------------------------+
        |                                                 |
+-------v---------------+                         +-------v---------------+
| Key ID 1 (Retired)    |                         | Key ID 2 (Active)     |
| [256-bit DEK]         |                         | [256-bit DEK]         |
+-------+---------------+                         +-------+---------------+
        |                                                 |
        v                                                 v
(Decrypted during reads / GC)                      (Used for all new writes & summaries)
```

### KeyRing Metadata Format
Stored in the volume manifest (`manifest.json` / `manifest.summary`) or summary header:

```rust
pub enum KeyStatus {
    Active,
    Retired,
    Revoked,
}

pub struct KeyMetadata {
    pub key_id: u32,
    pub status: KeyStatus,
    pub created_at: SystemTime,
    pub cipher: CipherSuite,
    pub wrapped_dek: Vec<u8>, // DEK encrypted with Master Key KEK
    pub kdf_salt: [u8; 16],
}

pub struct KeyRing {
    pub active_key_id: u32,
    pub keys: Vec<KeyMetadata>,
}
```

---

## 4. Record & Summary On-Disk Layout

### A. Per-Record AEAD in `.log` Files
- Record header contains: `key_id: u32`, `nonce: [u8; 24]`, followed by `ciphertext` + `tag: [u8; 16]`.
- For `Write` payloads, only the file byte extent data (or entire payload) is encrypted with AEAD.
- **Random Access Efficiency**: Extent reads in `LogReader` only read and decrypt the exact byte extents requested, preserving fast O(1) random reads without decrypting entire generation files.

### B. Summary Snapshot AEAD
- `*.summary` files are encrypted under the active `key_id` at the time of export.
- Header remains authenticated unencrypted metadata (AAD), body (inode table, extent index) and footer are encrypted.

---

## 5. Key Rotation & Cryptographic Erasure Lifecycle

1. **Key Addition / Rotation (`appendfs key rotate`)**:
   - Generates `key_id = 2`, encrypts with KEK, and sets `active_key_id = 2`.
   - `key_id = 1` status is marked `Retired` (read-only for reading historical generations).
   - All subsequent log records and summaries are written with `key_id = 2`.

2. **Compaction & Re-Encryption (`appendfs gc` / `compact`)**:
   - The garbage collector reads surviving live extents from older generations (encrypted with `key_id = 1`), decrypts them in memory, and writes them into a new baseline generation encrypted with `key_id = 2`.
   - Superseded `.log` files from generation 1 are deleted.

3. **Cryptographic Erasure (`appendfs key purge 1`)**:
   - Once no active generation references `key_id = 1`, `key_id = 1` is purged from the KeyRing.
   - **Result**: Even if deleted sectors remain on flash media or cloud backup snapshots, data originally written under `key_id = 1` becomes mathematically unrecoverable.

---

## 6. Proposed CLI Interface

```bash
# Initialize encrypted volume
appendfs init /data/log --encrypt --key-file /secure/master.key

# Mount encrypted volume
appendfs mount /data/log /mnt/point --key-file /secure/master.key

# Rotate key
appendfs key rotate /data/log --key-file /secure/master.key

# Inspect keys
appendfs key list /data/log

# Compact and purge retired keys
appendfs gc /data/log --re-encrypt-to-active --purge-unused-keys
```
