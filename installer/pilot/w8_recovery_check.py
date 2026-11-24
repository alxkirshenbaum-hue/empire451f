"""Read-only bounded inspection of existing g3_snapshot plaintext archives.

Call only after existing owner envelope authentication/decryption. This module
never grants verified/restored status and never extracts or changes runtime.
"""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import os
import stat

LIMIT = 32 * 1024 * 1024
MAX_MEMBERS = 4096


def require(condition):
    if not condition:
        raise ValueError("Backup artifact refused")


def admit_raw_tar(source, archive_bytes, max_bytes):
    """Bound physical records before tarfile can materialize extensions."""
    source.seek(0)
    records = 0
    logical = 0
    def number(field):
        # Binary base-256 signed encoding: only nonnegative values admitted.
        if field[0] & 0x80:
            require(not field[0] & 0x40)
            return int.from_bytes(bytes([field[0] & 0x7f]) + field[1:], "big")
        raw = field.rstrip(b"\0 ").lstrip(b" ")
        require(bool(raw) and all(48 <= byte <= 55 for byte in raw))
        return int(raw, 8)
    while source.tell() < archive_bytes:
        header = source.read(512)
        require(len(header) == 512)
        if header == bytes(512):
            require(source.read(512) == bytes(512))
            while source.tell() < archive_bytes:
                chunk = source.read(min(65536, archive_bytes - source.tell()))
                require(bool(chunk) and not any(chunk))
            return
        records += 1
        require(records <= MAX_MEMBERS)
        expected = number(header[148:156])
        require(expected == sum(header[:148]) + 8 * 32 + sum(header[156:]))
        require(header[156:157] in (b"0", b"\0", b"5"))
        size = number(header[124:136])
        require(size <= max_bytes and (header[156:157] != b"5" or size == 0))
        logical += size
        require(logical <= max_bytes)
        padded = ((size + 511) // 512) * 512
        require(padded <= archive_bytes - source.tell())
        remaining = size
        while remaining:
            chunk = source.read(min(65536, remaining))
            require(bool(chunk))
            remaining -= len(chunk)
        padding = padded - size
        require(source.read(padding) == bytes(padding))
    require(False)  # Two end records are mandatory.

def inspect_archive(path, expected_sha256, expected_generation, required_paths=(),
                    max_bytes=LIMIT):
    """Return a plan only; digest must come from the authenticated receipt.

    G3 metadata inventories source files, but does not bind SQLite generation.
    Consequently DB/schema/credential checks remain explicit pending gates.
    """
    require(type(max_bytes) is int and 0 < max_bytes <= LIMIT)
    require(type(expected_generation) is int and expected_generation >= 0)
    require(isinstance(expected_sha256, str) and
            re.fullmatch(r"[0-9a-f]{64}", expected_sha256))
    path = Path(path)
    require(not path.is_symlink() and path.is_file())
    files = {}
    total = 0
    metadata_bytes = None
    # Portable caller boundary: private immutable staging, including parents.
    # O_NOFOLLOW is only a leaf protection; Windows has no equivalent here.
    descriptor_fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor_fd, "rb") as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1)
        require(os.fstat(source.fileno()).st_size <= max_bytes)
        digest = hashlib.sha256()
        archive_bytes = 0
        while True:
            chunk = source.read(65536)
            if not chunk:
                break
            archive_bytes += len(chunk)
            require(archive_bytes <= max_bytes)
            digest.update(chunk)
        require(digest.hexdigest() == expected_sha256)
        admit_raw_tar(source, archive_bytes, max_bytes)
        source.seek(0)
        with tarfile.open(fileobj=source, mode="r:") as archive:
            for count, member in enumerate(archive, 1):
                require(count <= MAX_MEMBERS)
                name = member.name
                while name.startswith("./"):
                    name = name[2:]
                if name in ("", "."):
                    require(member.isdir())
                    continue
                require(not name.startswith("/") and "\\" not in name and
                        all(part not in ("", ".", "..") for part in name.split("/")) and
                        ":" not in name and str(PurePosixPath(name)) == name)
                require(name not in files and (member.isfile() or member.isdir()))
                require(not member.pax_headers and not member.sparse)
                require(0 <= member.size <= max_bytes)
                total += member.size
                require(total <= max_bytes)
                descriptor = {"kind": "directory", "sha256": None, "attrs": [member.uid, member.gid, member.mode]}
                if member.isfile():
                    handle = archive.extractfile(member)
                    require(handle is not None)
                    digest = hashlib.sha256()
                    remaining = member.size
                    content = bytearray()
                    if name == "G3-SNAPSHOT.json":
                        require(remaining <= 1024 * 1024)
                    while remaining:
                        chunk = handle.read(min(65536, remaining))
                        require(bool(chunk))
                        remaining -= len(chunk)
                        digest.update(chunk)
                        if name == "G3-SNAPSHOT.json":
                            content.extend(chunk)
                    if name == "G3-SNAPSHOT.json":
                        metadata_bytes = bytes(content)
                    descriptor = {"kind": "file", "sha256": digest.hexdigest(), "attrs": [member.uid, member.gid, member.mode]}
                files[name] = descriptor
        after = os.fstat(source.fileno())
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns))
    require("G3-SNAPSHOT.json" in files)
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result)
            result[key] = value
        return result
    metadata = json.loads(metadata_bytes, object_pairs_hook=unique)
    require(metadata.get("format") == "vpn-control-g3-snapshot-v1")
    require(type(metadata.get("generation")) is int and
            metadata["generation"] == expected_generation)
    inventory = metadata.get("files")
    require(isinstance(inventory, dict) and bool(inventory))
    for original, attrs in inventory.items():
        require(isinstance(original, str) and original.startswith("/"))
        name = original[1:]
        require(name in files and isinstance(attrs, list) and len(attrs) == 5)
        require(all(type(value) is int and value >= 0 for value in attrs[:3]))
        require(attrs[2] <= 0o7777 and files[name]["attrs"] == attrs[:3])
        require(isinstance(attrs[4], dict) and not attrs[4])
        digest = attrs[3]
        require(digest is None or (isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest)))
        if digest is not None:
            require(files[name]["kind"] == "file" and
                    files[name]["sha256"] == digest)
        else:
            require(files[name]["kind"] == "directory")
    allowed = {original[1:] for original in inventory}
    allowed.update(("G3-SNAPSHOT.json", "var/lib/vpn-control/state.db"))
    for name in files:
        require(name in allowed or (files[name]["kind"] == "directory" and
                any(child.startswith(name + "/") for child in allowed)))
    require(all(name in files and files[name]["kind"] == "file"
                for name in required_paths))
    require(not any(name.endswith(("-wal", "-shm")) for name in files))
    return {"status": "artifact_check_passed", "registry_consistency": "not_run", "generation": expected_generation,
            "archive_bytes": archive_bytes, "logical_bytes": total,
            "members": len(files), "runtime_changes": False,
            "pending": ["envelope_authentication", "sqlite_schema_integrity",
                        "sqlite_generation_binding", "unfinished_operations",
                        "credential_master_protected_revoked_semantics",
                        "fresh_owner_and_profile_stack", "allocated_disk_ram_peak"]}