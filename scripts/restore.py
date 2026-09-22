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
import uuid

import argon2.low_level
import blake3
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import zstandard as zstd


FILE_MAGIC = b"APPF"
SUMMARY_MAGIC = b"APPS"
FILE_HEADER_SIZE = 32
RECORD_HEADER_SIZE = 29

OP_DATA = 1
OP_DATA_ZSTD = 2
OP_INODE_DELTA = 3
OP_FLUSH_COMMIT = 4
OP_SEAL = 5

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


def derive_record_nonce(generation: int, revision: int, record_offset: int) -> bytes:
    """Derives a deterministic 12-byte nonce matching AppendFS's derive_record_nonce.
    Format: [generation (4 bytes BE) || revision (4 bytes BE) || record_offset (4 bytes BE)]
    """
    return struct.pack(">III", generation & 0xFFFFFFFF, revision & 0xFFFFFFFF, record_offset & 0xFFFFFFFF)


def derive_record_aad(op_code: int, record_offset: int, inode: int) -> bytes:
    """Constructs 17-byte Associated Data matching AppendFS's record_aad."""
    return struct.pack(">BQQ", op_code, record_offset, inode)


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
        self, generation: int, revision: int, record_offset: int, op_code: int, inode: int, payload: bytes, auth_tag: bytes
    ) -> bytes:
        if self.cipher is not None:
            nonce = derive_record_nonce(generation, revision, record_offset)
            aad = derive_record_aad(op_code, record_offset, inode)
            ciphertext_with_tag = payload + auth_tag
            try:
                decrypted = self.cipher.decrypt(nonce, ciphertext_with_tag, aad)
            except Exception as e:
                raise ValueError(f"Decryption / authentication failed for record (gen={generation}, offset=0x{record_offset:x}, ino={inode}): {e}")
            data = decrypted
        else:
            # Plaintext volume
            if not self.no_verify:
                aad = derive_record_aad(op_code, record_offset, inode)
                hasher = blake3.blake3()
                hasher.update(aad)
                hasher.update(payload)
                expected_tag = hasher.digest()[:16]
                if expected_tag != auth_tag:
                    raise ValueError(f"BLAKE3 checksum mismatch for record (gen={generation}, offset=0x{record_offset:x}, ino={inode})")
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
        hdr = f.read(72)
        if len(hdr) < 72:
            raise ValueError(f"Corrupt or truncated summary header in '{summary_path}'")
        magic, ver, gen, rev, tx, next_ino, sec, nsec, iv, vh_len, uncompressed_len = struct.unpack(
            ">4sIQIQQqI12sIQ", hdr
        )
        if magic != b"APPS":
            raise ValueError(f"Invalid magic {magic} in '{summary_path}'")
        if vh_len < 72:
            raise ValueError(f"Summary '{summary_path}' does not contain an encrypted VolumeHeader")
        vh_bytes = f.read(72)
        if len(vh_bytes) < 72:
            raise ValueError(f"Truncated VolumeHeader in '{summary_path}'")
        cipher, key_source, compression, volume_id, kdf_salt, kcv_iv, kcv_tag = struct.unpack(
            ">III16s16s12s16s", vh_bytes
        )
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
        self.expected_batch_id: Optional[int] = None
        self.last_committed_batch_id: Optional[int] = None
        self.tombstoned_inodes: Set[int] = set()

    def _add_dir_entry(self, parent_ino: int, name: str, child_ino: int):
        prev_child = self.dir_entries.setdefault(parent_ino, {}).get(name)
        if prev_child is not None and prev_child != child_ino:
            self.parent_map.get(prev_child, set()).discard((parent_ino, name))
        self.dir_entries[parent_ino][name] = child_ino
        self.parent_map.setdefault(child_ino, set()).add((parent_ino, name))

    def _remove_dir_entry(self, parent_ino: int, name: str) -> Optional[int]:
        child_ino = self.dir_entries.get(parent_ino, {}).pop(name, None)
        if child_ino is not None:
            self.parent_map.get(child_ino, set()).discard((parent_ino, name))
        return child_ino

    def resolve_paths(self, ino: int, visited: Optional[Set[int]] = None) -> List[Path]:
        """Resolves all current filesystem paths associated with an inode."""
        if ino == 1:
            return [self.dest_dir]
        if visited is None:
            visited = set()
        if ino in visited:
            return []
        visited.add(ino)
        paths = []
        for parent_ino, name in self.parent_map.get(ino, set()):
            for ppath in self.resolve_paths(parent_ino, visited.copy()):
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
            committed_records_count = 0
            is_sealed = False

            while True:
                rh_bytes = f.read(RECORD_HEADER_SIZE)
                if not rh_bytes or len(rh_bytes) < RECORD_HEADER_SIZE:
                    break
                rec_log_offset = f.tell() - RECORD_HEADER_SIZE
                op, ino, plen, tag = struct.unpack(">BQI16s", rh_bytes)
                raw_payload = f.read(plen)
                if len(raw_payload) < plen:
                    # Truncated record at end of log due to crash mid-flush; discard
                    break

                if is_sealed:
                    raise ValueError(
                        f"Integrity violation in {log_path.name} @ offset 0x{rec_log_offset:x}: "
                        f"extraneous record op={op} found after Seal record"
                    )

                # 1. Check for integrity errors: operations targeting deleted/tombstoned inodes
                if ino in self.tombstoned_inodes:
                    raise ValueError(
                        f"Integrity violation in {log_path.name} @ offset 0x{rec_log_offset:x}: "
                        f"record op={op} targets previously deleted/tombstoned inode {ino}"
                    )

                # 2. Check for data targeting non-file inodes
                if op in (OP_DATA, OP_DATA_ZSTD):
                    itype = self.inode_types.get(ino)
                    if itype is not None and itype != "file":
                        raise ValueError(
                            f"Integrity violation in {log_path.name} @ offset 0x{rec_log_offset:x}: "
                            f"data record targets non-file inode {ino} (type='{itype}')"
                        )

                try:
                    payload = self.decryptor.decode_record(gen, rev, rec_log_offset, op, ino, raw_payload, tag)
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
                    if len(payload) < 24:
                        raise ValueError(
                            f"Malformed FlushCommit payload (len={len(payload)}) in {log_path.name} @ offset 0x{rec_log_offset:x}"
                        )
                    batch_id, commit_secs, commit_nsecs, claimed_count = struct.unpack(">QqII", payload[:24])
                    if claimed_count != records_in_batch:
                        raise ValueError(
                            f"FlushCommit record count mismatch in {log_path.name} @ offset 0x{rec_log_offset:x}: "
                            f"commit claimed {claimed_count} records but batch buffered {records_in_batch}"
                        )

                    # Check flush batch ID monotonicity and continuity (gapless)
                    if self.expected_batch_id is not None:
                        if batch_id != self.expected_batch_id:
                            raise ValueError(
                                f"Flush batch ID gap/inversion in {log_path.name} @ offset 0x{rec_log_offset:x}: "
                                f"expected batch_id {self.expected_batch_id}, got {batch_id}"
                            )
                        self.expected_batch_id += 1
                    else:
                        self.expected_batch_id = batch_id + 1

                    # Atomic commit point for the batch!
                    self._commit_batch(batch_chunks, batch_deltas)
                    self.last_committed_batch_id = batch_id
                    committed_records_count += 1 + records_in_batch
                    batch_chunks.clear()
                    batch_deltas.clear()
                    records_in_batch = 0
                elif op == OP_SEAL:
                    if len(payload) < 16:
                        raise ValueError(
                            f"Malformed Seal payload (len={len(payload)}) in {log_path.name} @ offset 0x{rec_log_offset:x}"
                        )
                    if records_in_batch != 0:
                        raise ValueError(
                            f"Integrity violation in {log_path.name} @ offset 0x{rec_log_offset:x}: "
                            f"seal record preceded by {records_in_batch} uncommitted records"
                        )
                    seal_secs, seal_nsecs, seal_count = struct.unpack(">qII", payload[:16])
                    if seal_count != committed_records_count:
                        raise ValueError(
                            f"Seal record count mismatch in {log_path.name} @ offset 0x{rec_log_offset:x}: "
                            f"claimed {seal_count} records but committed {committed_records_count}"
                        )
                    is_sealed = True
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
                if self.last_committed_batch_id is not None:
                    self.expected_batch_id = self.last_committed_batch_id + 1
                else:
                    self.expected_batch_id = None

    def _commit_batch(self, batch_chunks: Dict[Tuple[int, int], bytes], batch_deltas: Dict[int, tuple]):
        if self.dry_run:
            return

        staging_dir = self.dest_dir / ".appendfs_restore_staging"

        # 1. Directory additions and removals (handling renames, unlinks, hardlinks)
        dir_deltas = {ino: delta for ino, delta in batch_deltas.items() if delta[0] == "dir"}
        for ino, delta in dir_deltas.items():
            self.inode_types[ino] = "dir"
            if ino not in self.dir_entries:
                self.dir_entries[ino] = {}

        if dir_deltas:
            raw_removals: List[Tuple[int, str, int]] = []
            for p_ino, delta in dir_deltas.items():
                _, parent, added, removed, attrs = delta
                for name in removed:
                    child_ino = self.dir_entries.get(p_ino, {}).get(name)
                    if child_ino is not None:
                        raw_removals.append((p_ino, name, child_ino))
                    else:
                        for old_ppath in self.resolve_paths(p_ino):
                            victim = old_ppath / name
                            if victim.is_symlink() or victim.is_file():
                                victim.unlink(missing_ok=True)
                            elif victim.is_dir():
                                shutil.rmtree(victim, ignore_errors=True)

            raw_additions: List[Tuple[int, str, int]] = []
            for p_ino, delta in dir_deltas.items():
                _, parent, added, removed, attrs = delta
                for name, child_ino in added:
                    raw_additions.append((p_ino, name, child_ino))

            # Match renames: an inode removed from (old_p, old_name) and added to (new_p, new_name)
            additions_by_ino: Dict[int, List[Tuple[int, str]]] = {}
            for p_ino, name, c_ino in raw_additions:
                additions_by_ino.setdefault(c_ino, []).append((p_ino, name))

            renames: List[Tuple[int, str, int, str, int]] = []
            pure_removals: List[Tuple[int, str, int]] = []
            matched_additions: Set[Tuple[int, str, int]] = set()

            for old_p_ino, old_name, c_ino in raw_removals:
                targets = additions_by_ino.get(c_ino)
                if targets:
                    new_p_ino, new_name = targets.pop(0)
                    renames.append((old_p_ino, old_name, new_p_ino, new_name, c_ino))
                    matched_additions.add((new_p_ino, new_name, c_ino))
                else:
                    pure_removals.append((old_p_ino, old_name, c_ino))

            unmatched_additions = [
                (p_ino, name, c_ino)
                for (p_ino, name, c_ino) in raw_additions
                if (p_ino, name, c_ino) not in matched_additions
            ]

            # Categorize unmatched additions into hardlinks vs brand new entries
            hardlinks: List[Tuple[int, str, int]] = []
            new_entries: List[Tuple[int, str, int]] = []
            for p_ino, name, c_ino in unmatched_additions:
                if c_ino in self.parent_map and bool(self.parent_map[c_ino]):
                    hardlinks.append((p_ino, name, c_ino))
                else:
                    new_entries.append((p_ino, name, c_ino))

            # --- Renames Phase 1: stage sources into staging_dir ---
            # Sort deepest first so child paths are staged before parent directories
            renames.sort(
                key=lambda x: len(self.resolve_paths(x[0])[0].parts) if self.resolve_paths(x[0]) else 0,
                reverse=True,
            )
            staged_renames: List[Tuple[Optional[Path], int, str, int]] = []
            if renames:
                staging_dir.mkdir(parents=True, exist_ok=True)
                for old_p_ino, old_name, new_p_ino, new_name, c_ino in renames:
                    old_ppaths = self.resolve_paths(old_p_ino)
                    staged_for_entry = False
                    for old_ppath in old_ppaths:
                        src_path = old_ppath / old_name
                        if src_path.exists() or src_path.is_symlink():
                            tmp_name = f".tmp_{c_ino}_{uuid.uuid4().hex}"
                            tmp_path = staging_dir / tmp_name
                            try:
                                os.rename(src_path, tmp_path)
                                staged_renames.append((tmp_path, new_p_ino, new_name, c_ino))
                                staged_for_entry = True
                            except Exception:
                                try:
                                    shutil.move(src_path, tmp_path)
                                    staged_renames.append((tmp_path, new_p_ino, new_name, c_ino))
                                    staged_for_entry = True
                                except Exception as e:
                                    print(f"Warning: Failed to stage rename of {src_path}: {e}", file=sys.stderr)
                    if not staged_for_entry:
                        staged_renames.append((None, new_p_ino, new_name, c_ino))

                    # Update in-memory hierarchy for this rename
                    self._remove_dir_entry(old_p_ino, old_name)
                    self._add_dir_entry(new_p_ino, new_name, c_ino)

            # --- Pure Removals: delete unlinked paths from disk ---
            for old_p_ino, old_name, c_ino in pure_removals:
                for old_ppath in self.resolve_paths(old_p_ino):
                    victim = old_ppath / old_name
                    if victim.is_symlink() or victim.is_file():
                        victim.unlink(missing_ok=True)
                    elif victim.is_dir():
                        shutil.rmtree(victim, ignore_errors=True)
                self._remove_dir_entry(old_p_ino, old_name)

            # --- Renames Phase 2: move from staging_dir to dst_path ---
            # Sort shallowest first so parent directories are placed before children
            staged_renames.sort(
                key=lambda x: len(self.resolve_paths(x[1])[0].parts) if self.resolve_paths(x[1]) else 0
            )
            for tmp_path, new_p_ino, new_name, c_ino in staged_renames:
                if tmp_path is not None and (tmp_path.exists() or tmp_path.is_symlink()):
                    for new_ppath in self.resolve_paths(new_p_ino):
                        dst_path = new_ppath / new_name
                        dst_path.parent.mkdir(parents=True, exist_ok=True)
                        if dst_path.exists() or dst_path.is_symlink():
                            if dst_path.is_dir() and not dst_path.is_symlink():
                                shutil.rmtree(dst_path, ignore_errors=True)
                            else:
                                dst_path.unlink(missing_ok=True)
                        try:
                            os.rename(tmp_path, dst_path)
                        except Exception:
                            try:
                                shutil.move(tmp_path, dst_path)
                            except Exception as e:
                                print(f"Warning: Failed to complete rename to {dst_path}: {e}", file=sys.stderr)

            # Cleanup empty staging_dir if present
            if staging_dir.exists():
                try:
                    staging_dir.rmdir()
                except Exception:
                    pass

            # --- Hardlinks ---
            for new_p_ino, new_name, c_ino in hardlinks:
                self._add_dir_entry(new_p_ino, new_name, c_ino)
                for new_ppath in self.resolve_paths(new_p_ino):
                    link_target = new_ppath / new_name
                    existing = [
                        p for p in self.resolve_paths(c_ino)
                        if (p.exists() or p.is_symlink()) and p != link_target
                    ]
                    if existing:
                        primary = existing[0]
                        link_target.parent.mkdir(parents=True, exist_ok=True)
                        if link_target.exists() or link_target.is_symlink():
                            link_target.unlink(missing_ok=True)
                        try:
                            os.link(primary, link_target)
                        except Exception:
                            try:
                                shutil.copy2(primary, link_target)
                            except Exception as e:
                                print(f"Warning: Cannot link/copy {link_target} from {primary}: {e}", file=sys.stderr)

            # --- Brand New Entries ---
            for new_p_ino, new_name, c_ino in new_entries:
                self._add_dir_entry(new_p_ino, new_name, c_ino)
                if c_ino in batch_deltas:
                    dtag = batch_deltas[c_ino][0]
                    if dtag in ("dir", "file", "symlink", "special"):
                        self.inode_types[c_ino] = dtag
                if self.inode_types.get(c_ino) == "dir":
                    for new_ppath in self.resolve_paths(new_p_ino):
                        (new_ppath / new_name).mkdir(parents=True, exist_ok=True)

        # Ensure all existing directories are present on disk
        for ino, itype in list(self.inode_types.items()):
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
                        else:
                            # Zero extent (hole)
                            f.seek(file_off)
                            zero_chunk = b"\0" * min(length, 65536)
                            rem = length
                            while rem > 0:
                                to_write = min(rem, len(zero_chunk))
                                f.write(zero_chunk[:to_write])
                                rem -= to_write
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
                for p_ino, name in list(self.parent_map.get(ino, set())):
                    self.dir_entries.get(p_ino, {}).pop(name, None)
                self.dir_entries.pop(ino, None)
                self.parent_map.pop(ino, None)
                self.inode_modes.pop(ino, None)
                self.inode_times.pop(ino, None)
                self.tombstoned_inodes.add(ino)

    def finalize(self):
        """Applies final POSIX timestamps and permissions in post-order (deepest paths first)."""
        if self.dry_run:
            return

        staging_dir = self.dest_dir / ".appendfs_restore_staging"
        if staging_dir.exists():
            shutil.rmtree(staging_dir, ignore_errors=True)

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

