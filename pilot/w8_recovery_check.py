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
    with path.open("rb") as source:
        data = source.read(max_bytes + 1)
    require(len(data) <= max_bytes)
    require(hashlib.sha256(data).hexdigest() == expected_sha256)
    import io
    files = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
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
            files[name] = None
            if member.isfile():
                handle = archive.extractfile(member)
                require(handle is not None)
                content = handle.read(max_bytes + 1)
                require(len(content) == member.size)
                files[name] = content
    require("G3-SNAPSHOT.json" in files)
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result)
            result[key] = value
        return result
    metadata = json.loads(files["G3-SNAPSHOT.json"], object_pairs_hook=unique)
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
            require(isinstance(files[name], bytes) and
                    hashlib.sha256(files[name]).hexdigest() == digest)
        else:
            require(files[name] is None)
    require(all(name in files and isinstance(files[name], bytes)
                for name in required_paths))
    require(not any(name.endswith(("-wal", "-shm")) for name in files))
    return {"status": "artifact_check_passed", "registry_consistency": "not_run", "generation": expected_generation,
            "archive_bytes": len(data), "logical_bytes": total,
            "members": len(files), "runtime_changes": False,
            "pending": ["envelope_authentication", "sqlite_schema_integrity",
                        "sqlite_generation_binding", "unfinished_operations",
                        "credential_master_protected_revoked_semantics",
                        "fresh_owner_and_profile_stack", "allocated_disk_ram_peak"]}