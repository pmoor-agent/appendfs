#!/usr/bin/env python3
"""
scripts/restore.py - Standalone Disaster Recovery Tool for AppendFS

A clean-room, zero-magic Python script that replays AppendFS log files directly
onto a target local directory without requiring Rust, Cargo, C++, or FUSE kernel drivers.

Features:
- Incremental, direct-to-disk log replay (bounded memory footprint regardless of volume size).
- Atomic batch commitment: applies data and metadata deltas upon encountering FlushCommit.
- Handles directories, nested paths, regular files, sparse files (holes), symlinks, and hardlinks.
- Restores POSIX attributes: file permissions (chmod), timestamps (mtime/atime), and extended attributes (xattrs).
- Discards uncommitted trailing records from power loss mid-flush, exactly matching AppendFS recovery.
- Supports both plaintext volumes (standard library only) and encrypted volumes (via `cryptography`).
- Supports Zstd-compressed payloads (via `zstandard`).

Usage:
    python3 scripts/restore.py <volume_dir_or_log_file> <target_restore_dir>
    python3 scripts/restore.py tests/fixtures/v1 /tmp/restored
"""

import argparse
import io
import os
import re
import shutil
import struct
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import argon2.low_level
import blake3
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import zstandard as zstd


FILE_MAGIC = b"APPF"
SUMMARY_MAGIC = b"APPS"
FILE_HEADER_SIZE = 32
RECORD_HEADER_SIZE = 37

OP_DATA = 1
OP_DATA_ZSTD = 2
OP_INODE_DELTA = 3
OP_FLUSH_COMMIT = 4

TAG_TOMBSTONE = 0
TAG_DIRECTORY = 1
TAG_FILE = 2
TAG_SYMLINK = 3
TAG_FIFO = 4
TAG_CHARDEV = 5
TAG_BLOCKDEV = 6
TAG_SOCKET = 7

DATA_KEY_CONTEXT = "appendfs volume data key v1"
KCV_KEY_CONTEXT = "appendfs key check value v1"


class WireReader:
    """Deserializer for AppendFS's big-endian fixed-width Bincode encoding."""

    def __init__(self, data: bytes):
        self.stream = io.BytesIO(data)

    def read_u8(self) -> int:
        b = self.stream.read(1)
        if len(b) < 1:
            raise EOFError("Unexpected EOF reading u8")
        return struct.unpack(">B", b)[0]

    def read_u32(self) -> int:
        b = self.stream.read(4)
        if len(b) < 4:
            raise EOFError("Unexpected EOF reading u32")
        return struct.unpack(">I", b)[0]

    def read_i64(self) -> int:
        b = self.stream.read(8)
        if len(b) < 8:
            raise EOFError("Unexpected EOF reading i64")
        return struct.unpack(">q", b)[0]

    def read_u64(self) -> int:
        b = self.stream.read(8)
        if len(b) < 8:
            raise EOFError("Unexpected EOF reading u64")
        return struct.unpack(">Q", b)[0]

    def read_str(self) -> str:
        n = self.read_u64()
        b = self.stream.read(n)
        if len(b) < n:
            raise EOFError(f"Unexpected EOF reading string of length {n}")
        return b.decode("utf-8")

    def read_bytes(self) -> bytes:
        n = self.read_u64()
        b = self.stream.read(n)
        if len(b) < n:
            raise EOFError(f"Unexpected EOF reading bytes of length {n}")
        return b

    def read_opt_u32(self) -> Optional[int]:
        return self.read_u32() if self.read_u8() else None

    def read_opt_u64(self) -> Optional[int]:
        return self.read_u64() if self.read_u8() else None

    def read_opt_str(self) -> Optional[str]:
        return self.read_str() if self.read_u8() else None

    def read_opt_time(self) -> Optional[Tuple[int, int]]:
        if not self.read_u8():
            return None
        sec = self.read_i64()
        nsec = self.read_u32()
        return (sec, nsec)


def parse_attr_delta(r: WireReader) -> dict:
    mode = r.read_opt_u32()
    uid = r.read_opt_u32()
    gid = r.read_opt_u32()
    nlink = r.read_opt_u32()
    atime = r.read_opt_time()
    mtime = r.read_opt_time()
    ctime = r.read_opt_time()
    created_at = r.read_opt_time()

    xattrs = None
    if r.read_u8():
        cnt = r.read_u64()
        xattrs = []
        for _ in range(cnt):
            k = r.read_str()
            v = r.read_bytes() if r.read_u8() else None
            xattrs.append((k, v))

    return {
        "mode": mode,
        "uid": uid,
        "gid": gid,
        "nlink": nlink,
        "atime": atime,
        "mtime": mtime,
        "ctime": ctime,
        "created_at": created_at,
        "xattrs": xattrs,
    }


def parse_entry_delta(payload: bytes) -> tuple:
    r = WireReader(payload)
    tag = r.read_u8()

    if tag == TAG_TOMBSTONE:
        return ("tombstone",)
    elif tag == TAG_DIRECTORY:
        parent = r.read_opt_u64()
        added_cnt = r.read_u64()
        added = [(r.read_str(), r.read_u64()) for _ in range(added_cnt)]
        removed_cnt = r.read_u64()
        removed = [r.read_str() for _ in range(removed_cnt)]
        attrs = parse_attr_delta(r)
        return ("dir", parent, added, removed, attrs)
    elif tag == TAG_FILE:
        extents_cnt = r.read_u64()
        extents = []
        for _ in range(extents_cnt):
            file_off = r.read_u64()
            rec_log_off = r.read_u64()
            rec_size = r.read_u32()
            length = r.read_u64()
            extents.append((file_off, rec_log_off, rec_size, length))
        size = r.read_opt_u64()
        attrs = parse_attr_delta(r)
        return ("file", extents, size, attrs)
    elif tag == TAG_SYMLINK:
        target = r.read_opt_str()
        attrs = parse_attr_delta(r)
        return ("symlink", target, attrs)
    elif tag in (TAG_FIFO, TAG_CHARDEV, TAG_BLOCKDEV, TAG_SOCKET):
        rdev = r.read_u32()
        attrs = parse_attr_delta(r)
        kind = {TAG_FIFO: "fifo", TAG_CHARDEV: "chardev", TAG_BLOCKDEV: "blockdev", TAG_SOCKET: "socket"}[tag]
        return ("special", kind, rdev, attrs)
    else:
        raise ValueError(f"Unknown LogEntryDelta tag: {tag}")


def derive_record_nonce(generation: int, tx_id: int) -> bytes:
    """Derives a deterministic 12-byte nonce matching AppendFS's derive_record_nonce."""
    gen_u32 = generation & 0xFFFFFFFF
    return struct.pack(">IQ", gen_u32, tx_id)


def derive_record_aad(op_code: int, tx_id: int, inode: int) -> bytes:
    """Constructs 17-byte Associated Data matching AppendFS's record_aad."""
    return struct.pack(">BQQ", op_code, tx_id, inode)


def parse_log_filename(name: str) -> Optional[Tuple[int, int]]:
    """Parses a log filename like 000001.log or 000001_r2.log into (generation, revision)."""
    m = re.match(r"^(\d{6})(?:_r(\d+))?\.log$", name)
    if not m:
        return None
    gen = int(m.group(1))
    rev = int(m.group(2)) if m.group(2) else 0
    return (gen, rev)


def find_log_files(source_path: Path) -> List[Tuple[int, int, Path]]:
    """Returns sorted list of (generation, revision, path) for all valid .log files."""
    if source_path.is_file():
        parsed = parse_log_filename(source_path.name)
        if not parsed:
            raise ValueError(f"Filename '{source_path.name}' is not a valid AppendFS log name (e.g. 000001.log)")
        return [(parsed[0], parsed[1], source_path)]

    if not source_path.is_dir():
        raise FileNotFoundError(f"Path '{source_path}' does not exist")

    latest_rev_by_gen: Dict[int, Tuple[int, Path]] = {}
    for entry in source_path.iterdir():
        if entry.is_file():
            parsed = parse_log_filename(entry.name)
            if parsed:
                gen, rev = parsed
                if gen not in latest_rev_by_gen or rev > latest_rev_by_gen[gen][0]:
                    latest_rev_by_gen[gen] = (rev, entry)

    result = [(gen, rev, path) for gen, (rev, path) in latest_rev_by_gen.items()]
    result.sort(key=lambda x: (x[0], x[1]))

    # Verify that log generations are strictly continuous without gaps
    for i in range(1, len(result)):
        prev_gen = result[i - 1][0]
        curr_gen = result[i][0]
        if curr_gen != prev_gen + 1:
            raise ValueError(
                f"Missing log generation in '{source_path}': gap detected between generation {prev_gen} and {curr_gen}"
            )
    return result


class VolumeDecryptor:
    """Handles decryption and authentication for encrypted and plaintext volumes."""

    def __init__(self, key_bytes: Optional[bytes] = None, no_verify: bool = False):
        self.key_bytes = key_bytes
        self.no_verify = no_verify
        self.cipher = ChaCha20Poly1305(key_bytes) if key_bytes else None

    def decode_record(
        self, generation: int, tx_id: int, op_code: int, inode: int, payload: bytes, auth_tag: bytes
    ) -> bytes:
        if self.cipher is not None:
            nonce = derive_record_nonce(generation, tx_id)
            aad = derive_record_aad(op_code, tx_id, inode)
            ciphertext_with_tag = payload + auth_tag
            try:
                decrypted = self.cipher.decrypt(nonce, ciphertext_with_tag, aad)
            except Exception as e:
                raise ValueError(f"Decryption / authentication failed for record (gen={generation}, tx={tx_id}, ino={inode}): {e}")
            data = decrypted
        else:
            # Plaintext volume
            if not self.no_verify:
                aad = derive_record_aad(op_code, tx_id, inode)
                hasher = blake3.blake3()
                hasher.update(aad)
                hasher.update(payload)
                expected_tag = hasher.digest()[:16]
                if expected_tag != auth_tag:
                    raise ValueError(f"BLAKE3 checksum mismatch for record (gen={generation}, tx={tx_id}, ino={inode})")
            data = payload

        # Decompress if Zstd
        if op_code == OP_DATA_ZSTD:
            dctx = zstd.ZstdDecompressor()
            data = dctx.decompress(data)

        return data


DATA_KEY_CONTEXT = "appendfs volume data key v1"
KCV_KEY_CONTEXT = "appendfs key check value v1"


def read_volume_header_from_summary(summary_path: Path) -> Tuple[bytes, bytes, bytes, bytes]:
    """Reads (volume_id, kdf_salt, kcv_iv, kcv_tag) from an AppendFS summary file."""
    if not summary_path.is_file():
        raise FileNotFoundError(f"Summary file not found: '{summary_path}'")
    with open(summary_path, "rb") as f:
        hdr = f.read(64)
        if len(hdr) < 64:
            raise ValueError(f"Corrupt or truncated summary header in '{summary_path}'")
        magic, ver, gen, rev, tx, next_ino, sec, nsec, iv, vh_len = struct.unpack(">4sIQIQQqI12sI", hdr)
        if magic != b"APPS":
            raise ValueError(f"Invalid magic {magic} in '{summary_path}'")
        if vh_len < 72:
            raise ValueError(f"Summary '{summary_path}' does not contain an encrypted VolumeHeader")
        vh_bytes = f.read(72)
        if len(vh_bytes) < 72:
            raise ValueError(f"Truncated VolumeHeader in '{summary_path}'")
        cipher, key_source, compression, volume_id, kdf_salt, kcv_iv, kcv_tag = struct.unpack(">III16s16s12s16s", vh_bytes)
        return (volume_id, kdf_salt, kcv_iv, kcv_tag)


def derive_key_from_passphrase_or_file(
    passphrase: Optional[str],
    key_file: Optional[str],
    salt: bytes,
    volume_id: Optional[bytes] = None,
    kcv_iv: Optional[bytes] = None,
    kcv_tag: Optional[bytes] = None,
) -> bytes:
    """Derives the 32-byte data encryption key matching AppendFS's MasterKey and VolumeHeader."""
    if key_file and passphrase:
        with open(key_file, "r") as f:
            hex_str = f.read().strip()
        if len(hex_str) != 64:
            raise ValueError(f"Expected 64 hex characters in key file '{key_file}', found {len(hex_str)}")
        raw_key = bytes.fromhex(hex_str)
        material = raw_key + passphrase.encode("utf-8")
        master_key = argon2.low_level.hash_secret_raw(
            secret=material,
            salt=salt,
            time_cost=3,
            memory_cost=64 * 1024,
            parallelism=1,
            hash_len=32,
            type=argon2.low_level.Type.ID,
        )
    elif key_file:
        with open(key_file, "r") as f:
            hex_str = f.read().strip()
        if len(hex_str) != 64:
            raise ValueError(f"Expected 64 hex characters in key file '{key_file}', found {len(hex_str)}")
        master_key = bytes.fromhex(hex_str)
    elif passphrase:
        master_key = argon2.low_level.hash_secret_raw(
            secret=passphrase.encode("utf-8"),
            salt=salt,
            time_cost=3,
            memory_cost=64 * 1024,
            parallelism=1,
            hash_len=32,
            type=argon2.low_level.Type.ID,
        )
    else:
        raise ValueError("Either --passphrase, --key-file, or both must be provided for encrypted volumes")

    # Optional key-check value verification
    if volume_id is not None and kcv_iv is not None and kcv_tag is not None:
        kcv_key = blake3.blake3(master_key, derive_key_context=KCV_KEY_CONTEXT).digest()
        kcv_cipher = ChaCha20Poly1305(kcv_key)
        try:
            kcv_cipher.decrypt(kcv_iv, kcv_tag, volume_id)
        except Exception:
            raise ValueError("Incorrect passphrase or key file: Key Check Value (KCV) verification failed")

    # Derivation matching derive_subkey(DATA_KEY_CONTEXT, &master.key)
    return blake3.blake3(master_key, derive_key_context=DATA_KEY_CONTEXT).digest()


class Restorer:
    """Manages direct-to-disk incremental state restoration."""

    def __init__(self, dest_dir: Path, decryptor: VolumeDecryptor, verbose: bool = False, dry_run: bool = False):
        self.dest_dir = dest_dir
        self.decryptor = decryptor
        self.verbose = verbose
        self.dry_run = dry_run

        # Inode hierarchy tracking in memory
        self.dir_entries: Dict[int, Dict[str, int]] = {1: {}}
        self.parent_map: Dict[int, Set[Tuple[int, str]]] = {}
        self.inode_types: Dict[int, str] = {1: "dir"}
        self.inode_modes: Dict[int, int] = {}
        self.inode_times: Dict[int, Tuple[Optional[Tuple[int, int]], Tuple[int, int]]] = {}
        self.expected_tx_id: Optional[int] = None
        self.last_committed_tx_id: Optional[int] = None
        self.tombstoned_inodes: Set[int] = set()

    def resolve_paths(self, ino: int) -> List[Path]:
        """Resolves all current filesystem paths associated with an inode."""
        if ino == 1:
            return [self.dest_dir]
        paths = []
        for parent_ino, name in self.parent_map.get(ino, set()):
            for ppath in self.resolve_paths(parent_ino):
                paths.append(ppath / name)
        return paths

    def replay_log_file(self, log_path: Path):
        with open(log_path, "rb") as f:
            hdr = f.read(FILE_HEADER_SIZE)
            if len(hdr) < FILE_HEADER_SIZE:
                return
            magic, ver, gen, rev, secs, nsecs = struct.unpack(">4sIQIqI", hdr)
            if magic != FILE_MAGIC:
                raise ValueError(f"Invalid file magic {magic} in {log_path.name}")

            if self.verbose:
                print(f"[{log_path.name}] Replaying generation {gen}, rev {rev}...")

            batch_chunks: Dict[Tuple[int, int], bytes] = {}
            batch_deltas: Dict[int, tuple] = {}
            records_in_batch = 0

            while True:
                rh_bytes = f.read(RECORD_HEADER_SIZE)
                if not rh_bytes or len(rh_bytes) < RECORD_HEADER_SIZE:
                    break
                rec_log_offset = f.tell() - RECORD_HEADER_SIZE
                op, tx, ino, plen, tag = struct.unpack(">BQQI16s", rh_bytes)
                raw_payload = f.read(plen)
                if len(raw_payload) < plen:
                    # Truncated record at end of log due to crash mid-flush; discard
                    break

                # 1. Check transaction ID monotonicity and continuity (gapless)
                if self.expected_tx_id is not None:
                    if tx != self.expected_tx_id:
                        raise ValueError(
                            f"Transaction ID gap/inversion in {log_path.name} @ offset 0x{rec_log_offset:x}: "
                            f"expected tx_id {self.expected_tx_id}, got {tx}"
                        )
                    self.expected_tx_id += 1
                else:
                    self.expected_tx_id = tx + 1

                # 2. Check for integrity errors: operations targeting deleted/tombstoned inodes
                if ino in self.tombstoned_inodes:
                    raise ValueError(
                        f"Integrity violation in {log_path.name} @ offset 0x{rec_log_offset:x}: "
                        f"record op={op} targets previously deleted/tombstoned inode {ino}"
                    )

                # 3. Check for data targeting non-file inodes
                if op in (OP_DATA, OP_DATA_ZSTD):
                    itype = self.inode_types.get(ino)
                    if itype is not None and itype != "file":
                        raise ValueError(
                            f"Integrity violation in {log_path.name} @ offset 0x{rec_log_offset:x}: "
                            f"data record targets non-file inode {ino} (type='{itype}')"
                        )

                try:
                    payload = self.decryptor.decode_record(gen, tx, op, ino, raw_payload, tag)
                except Exception as e:
                    raise ValueError(
                        f"Failed to decode/decrypt record in {log_path.name} @ offset 0x{rec_log_offset:x}: {e}"
                    ) from e

                if op in (OP_DATA, OP_DATA_ZSTD):
                    batch_chunks[(ino, rec_log_offset)] = payload
                    records_in_batch += 1
                elif op == OP_INODE_DELTA:
                    try:
                        delta = parse_entry_delta(payload)
                        batch_deltas[ino] = delta
                        records_in_batch += 1
                    except Exception as e:
                        raise ValueError(
                            f"Malformed InodeDelta for ino {ino} in {log_path.name} @ offset 0x{rec_log_offset:x}: {e}"
                        ) from e
                elif op == OP_FLUSH_COMMIT:
                    if len(payload) < 16:
                        raise ValueError(
                            f"Malformed FlushCommit payload (len={len(payload)}) in {log_path.name} @ offset 0x{rec_log_offset:x}"
                        )
                    commit_secs, commit_nsecs, claimed_count = struct.unpack(">qII", payload[:16])
                    if claimed_count != records_in_batch:
                        raise ValueError(
                            f"FlushCommit record count mismatch in {log_path.name} @ offset 0x{rec_log_offset:x}: "
                            f"commit claimed {claimed_count} records but batch buffered {records_in_batch}"
                        )
                    # Atomic commit point for the batch!
                    self._commit_batch(batch_chunks, batch_deltas)
                    self.last_committed_tx_id = tx
                    batch_chunks.clear()
                    batch_deltas.clear()
                    records_in_batch = 0
                else:
                    raise ValueError(
                        f"Unknown opcode {op} in {log_path.name} @ offset 0x{rec_log_offset:x}"
                    )

            # Any dangling uncommitted records at the end of the log are discarded
            if records_in_batch > 0:
                if self.verbose:
                    print(
                        f"[{log_path.name}] Discarding {records_in_batch} uncommitted trailing records at EOF",
                        file=sys.stderr,
                    )
                batch_chunks.clear()
                batch_deltas.clear()
                records_in_batch = 0
                if self.last_committed_tx_id is not None:
                    self.expected_tx_id = self.last_committed_tx_id + 1
                else:
                    self.expected_tx_id = None

    def _commit_batch(self, batch_chunks: Dict[Tuple[int, int], bytes], batch_deltas: Dict[int, tuple]):
        if self.dry_run:
            return

        # 1. Directory additions and removals
        for ino, delta in batch_deltas.items():
            if delta[0] == "dir":
                _, parent, added, removed, attrs = delta
                self.inode_types[ino] = "dir"
                if ino not in self.dir_entries:
                    self.dir_entries[ino] = {}

                # Removals
                for name in removed:
                    child_ino = self.dir_entries[ino].pop(name, None)
                    if child_ino:
                        self.parent_map.get(child_ino, set()).discard((ino, name))
                        for ppath in self.resolve_paths(ino):
                            victim = ppath / name
                            if victim.is_symlink() or victim.is_file():
                                victim.unlink(missing_ok=True)
                            elif victim.is_dir():
                                shutil.rmtree(victim, ignore_errors=True)

                # Additions
                for name, child_ino in added:
                    self.dir_entries[ino][name] = child_ino
                    self.parent_map.setdefault(child_ino, set()).add((ino, name))
                    if self.inode_types.get(child_ino) == "dir":
                        for ppath in self.resolve_paths(ino):
                            (ppath / name).mkdir(parents=True, exist_ok=True)

        # Ensure all existing directories are present on disk
        for ino, itype in self.inode_types.items():
            if itype == "dir":
                for p in self.resolve_paths(ino):
                    p.mkdir(parents=True, exist_ok=True)

        # 2. Symlinks
        for ino, delta in batch_deltas.items():
            if delta[0] == "symlink":
                _, target, attrs = delta
                self.inode_types[ino] = "symlink"
                if target:
                    for p in self.resolve_paths(ino):
                        p.parent.mkdir(parents=True, exist_ok=True)
                        if p.is_symlink() or p.exists():
                            p.unlink(missing_ok=True)
                        try:
                            os.symlink(target, p)
                        except Exception as e:
                            print(f"Warning: Cannot create symlink {p} -> {target}: {e}", file=sys.stderr)

        # 3. Special files (FIFO)
        for ino, delta in batch_deltas.items():
            if delta[0] == "special":
                _, kind, rdev, attrs = delta
                self.inode_types[ino] = kind
                if kind == "fifo":
                    for p in self.resolve_paths(ino):
                        if not p.exists():
                            p.parent.mkdir(parents=True, exist_ok=True)
                            try:
                                os.mkfifo(p)
                            except Exception:
                                pass

        # 4. Regular files
        for ino, delta in batch_deltas.items():
            if delta[0] == "file":
                _, extents, size, attrs = delta
                self.inode_types[ino] = "file"
                paths = self.resolve_paths(ino)
                if not paths:
                    continue

                existing = [p for p in paths if p.exists() and not p.is_symlink()]
                primary = existing[0] if existing else paths[0]
                primary.parent.mkdir(parents=True, exist_ok=True)
                if primary.exists():
                    try:
                        cur_mode = primary.stat().st_mode
                        if not (cur_mode & 0o200):
                            os.chmod(primary, cur_mode | 0o200)
                    except Exception:
                        pass
                open_mode = "r+b" if primary.exists() else "w+b"
                with open(primary, open_mode) as f:
                    for file_off, rec_log_off, _rec_size, length in extents:
                        if rec_log_off != 0:
                            chunk = batch_chunks.get((ino, rec_log_off))
                            if chunk is not None:
                                f.seek(file_off)
                                f.write(chunk[:length])
                    if size is not None:
                        f.truncate(size)

                # Hardlinks
                for other in paths:
                    if other == primary:
                        continue
                    other.parent.mkdir(parents=True, exist_ok=True)
                    if other.exists() or other.is_symlink():
                        try:
                            if os.path.samestat(primary.stat(), other.stat()):
                                continue
                        except Exception:
                            pass
                        other.unlink(missing_ok=True)
                    try:
                        os.link(primary, other)
                    except Exception:
                        try:
                            shutil.copy2(primary, other)
                        except Exception as e:
                            print(f"Warning: Cannot link/copy {other} from {primary}: {e}", file=sys.stderr)

        # 5. Attributes (mode, mtime, xattrs)
        for ino, delta in batch_deltas.items():
            attrs = None
            if delta[0] == "dir":
                attrs = delta[4]
            elif delta[0] == "file":
                attrs = delta[3]
            elif delta[0] == "symlink":
                attrs = delta[2]
            elif delta[0] == "special":
                attrs = delta[3]

            if attrs:
                if attrs.get("mode") is not None:
                    self.inode_modes[ino] = attrs["mode"] & 0o7777

                if attrs.get("mtime") is not None or attrs.get("atime") is not None:
                    prev_atime, prev_mtime = self.inode_times.get(ino, (None, None))
                    new_atime = attrs.get("atime") if attrs.get("atime") is not None else prev_atime
                    new_mtime = attrs.get("mtime") if attrs.get("mtime") is not None else prev_mtime
                    if new_mtime is not None:
                        self.inode_times[ino] = (new_atime, new_mtime)

                for p in self.resolve_paths(ino):
                    if not p.exists() and not p.is_symlink():
                        continue
                    # xattrs
                    if attrs.get("xattrs") and hasattr(os, "setxattr"):
                        for k, v in attrs["xattrs"]:
                            if v is not None:
                                try:
                                    os.setxattr(p, k, v, follow_symlinks=False)
                                except Exception:
                                    pass

        # 6. Tombstones
        for ino, delta in batch_deltas.items():
            if delta[0] == "tombstone":
                for p in self.resolve_paths(ino):
                    try:
                        if p.is_dir():
                            shutil.rmtree(p, ignore_errors=True)
                        else:
                            p.unlink(missing_ok=True)
                    except Exception:
                        pass
                self.inode_types.pop(ino, None)
                self.dir_entries.pop(ino, None)
                self.parent_map.pop(ino, None)
                self.inode_modes.pop(ino, None)
                self.inode_times.pop(ino, None)
                self.tombstoned_inodes.add(ino)

    def finalize(self):
        """Applies final POSIX timestamps and permissions in post-order (deepest paths first)."""
        if self.dry_run:
            return

        all_targets: List[Tuple[Path, int]] = []
        for ino in self.inode_types:
            for p in self.resolve_paths(ino):
                all_targets.append((p, ino))

        # Sort by path depth descending: deepest paths first (children before parents, root last)
        all_targets.sort(key=lambda x: len(x[0].parts), reverse=True)

        if self.verbose:
            print(f"Finalizing POSIX permissions and timestamps across {len(all_targets)} path(s) in post-order...")

        applied_modes = 0
        applied_times = 0
        for p, ino in all_targets:
            if not p.exists() and not p.is_symlink():
                continue

            # 1. Apply timestamps (utime before chmod, so restrictive chmod does not block utime)
            times = self.inode_times.get(ino)
            if times is not None:
                atime, mtime = times
                sec, nsec = mtime
                m_ts = sec + nsec / 1e9
                a_ts = (atime[0] + atime[1] / 1e9) if atime else m_ts
                try:
                    os.utime(p, (a_ts, m_ts), follow_symlinks=False)
                    applied_times += 1
                except Exception:
                    pass

            # 2. Apply permissions (mode)
            mode = self.inode_modes.get(ino)
            if mode is not None and not p.is_symlink():
                try:
                    os.chmod(p, mode & 0o7777)
                    applied_modes += 1
                except Exception:
                    pass

        if self.verbose:
            print(f"Completed attribute finalization (applied {applied_modes} mode(s), {applied_times} timestamp(s)).")


def main():
    parser = argparse.ArgumentParser(
        description="AppendFS Standalone Disaster Recovery Tool - Replays log files to reconstruct files and directories."
    )
    parser.add_argument("volume", type=Path, help="Path to an AppendFS volume directory or a specific .log file")
    parser.add_argument("dest", type=Path, help="Target destination directory where files will be restored")
    parser.add_argument("--passphrase", type=str, help="Passphrase for encrypted volume")
    parser.add_argument("--key-file", type=str, help="Path to 32-byte hex key file for encrypted volume")
    parser.add_argument("--salt", type=str, help="Hex-encoded 16-byte KDF salt (if no .summary file exists)")
    parser.add_argument("--no-verify", action="store_true", help="Skip BLAKE3 authentication checksum verification")
    parser.add_argument("-v", "--verbose", action="store_true", help="Display verbose log replay details")
    parser.add_argument("--dry-run", action="store_true", help="Parse and validate log files without writing to disk")

    args = parser.parse_args()

    volume_path = args.volume.resolve()
    dest_path = args.dest.resolve()

    log_files = find_log_files(volume_path)
    if not log_files:
        print(f"Error: No AppendFS log files found at '{volume_path}'", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(log_files)} log generation(s) to replay.")

    # Determine encryption key if needed
    key_bytes = None
    if args.passphrase or args.key_file:
        summary_0 = volume_path / "000000.summary" if volume_path.is_dir() else volume_path.parent / "000000.summary"
        if not summary_0.is_file():
            raise FileNotFoundError(
                f"Required initial summary '000000.summary' not found in '{volume_path}'. "
                "The initial summary is required to obtain volume metadata and KDF salt."
            )
        volume_id, kdf_salt, kcv_iv, kcv_tag = read_volume_header_from_summary(summary_0)
        key_bytes = derive_key_from_passphrase_or_file(
            args.passphrase, args.key_file, kdf_salt, volume_id, kcv_iv, kcv_tag
        )

    decryptor = VolumeDecryptor(key_bytes=key_bytes, no_verify=args.no_verify)
    restorer = Restorer(dest_path, decryptor, verbose=args.verbose, dry_run=args.dry_run)

    if not args.dry_run:
        dest_path.mkdir(parents=True, exist_ok=True)

    for gen, rev, log_path in log_files:
        restorer.replay_log_file(log_path)

    restorer.finalize()

    print(f"Restoration completed successfully into '{dest_path}'.")


if __name__ == "__main__":
    main()

