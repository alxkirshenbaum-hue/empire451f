"""Read-only bounded inspection of existing g3_snapshot plaintext archives.

Call only after existing owner envelope authentication/decryption. This module
never grants verified/restored status and never extracts or changes runtime.
"""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile

LIMIT = 32 * 1024 * 1024
MAX_MEMBERS = 4096


def require(condition):
    if not condition:
        raise ValueError("Backup artifact refused")


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
    with path.open("rb") as source:
        import os
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
                descriptor = {"kind": "directory", "sha256": None}
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
                    descriptor = {"kind": "file", "sha256": digest.hexdigest()}
                files[name] = descriptor
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
        digest = attrs[3]
        if digest is not None:
            require(files[name]["kind"] == "file" and
                    files[name]["sha256"] == digest)
        else:
            require(files[name]["kind"] == "directory")
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