import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("w8_recovery", Path(__file__).resolve().parents[1] / "pilot/w8_recovery_check.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ArtifactTests(unittest.TestCase):
    def archive(self, extra=None, generation=3, reference="/payload"):
        payload = b"synthetic"
        metadata = {"format": "vpn-control-g3-snapshot-v1", "generation": generation,
                    "files": {reference: [0, 0, 384, hashlib.sha256(payload).hexdigest(), {}]}}
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as tar:
            for name, content in [("payload", payload), ("G3-SNAPSHOT.json", json.dumps(metadata).encode())]:
                item = tarfile.TarInfo(name)
                item.size = len(content)
                item.mode = 384
                tar.addfile(item, io.BytesIO(content))
            if extra:
                tar.addfile(extra)
        return output.getvalue()

    def check(self, data, **kwargs):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact.tar"
            path.write_bytes(data)
            return module.inspect_archive(path, kwargs.pop("digest", hashlib.sha256(data).hexdigest()), 3, **kwargs)

    def test_existing_envelope(self):
        recovery_spec = importlib.util.spec_from_file_location("recovery", Path(__file__).resolve().parents[1] / "pilot/recovery_rehearsal.py")
        recovery = importlib.util.module_from_spec(recovery_spec)
        recovery_spec.loader.exec_module(recovery)
        from cryptography.hazmat.primitives import serialization
        from cryptography.exceptions import InvalidTag
        key = recovery.rsa.generate_private_key(public_exponent=65537, key_size=2048)
        wrong = recovery.rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        envelope = recovery.seal(public, b"synthetic")
        self.assertEqual(recovery.decrypt(key, envelope), b"synthetic")
        with self.assertRaises(ValueError):
            recovery.decrypt(wrong, envelope)
        parts = envelope.decode().split(".")
        body = bytearray(recovery.unb64(parts[3]))
        body[0] ^= 1
        parts[3] = recovery.b64(bytes(body))
        with self.assertRaises(InvalidTag):
            recovery.decrypt(key, ".".join(parts).encode())

    def test_bounded_archive_reads(self):
        from unittest.mock import patch
        original = module.os.fdopen
        class Guard:
            def __init__(self, file): self.file = file
            def __enter__(self): return self
            def __exit__(self, *args): self.file.close()
            def read(self, size=-1):
                if not 0 <= size <= 65536:
                    raise AssertionError("unbounded read")
                return self.file.read(size)
            def __getattr__(self, name): return getattr(self.file, name)
        def guarded(path, *args, **kwargs):
            return Guard(original(path, *args, **kwargs))
        with patch.object(module.os, "fdopen", guarded):
            self.check(self.archive())
    def test_plan_only(self):
        self.assertEqual(self.check(self.archive())["status"], "artifact_check_passed")

    def test_digest_generation_reference_bounds(self):
        for data, options in [(self.archive(), {"digest": "0" * 64}),
                              (self.archive(generation=4), {}),
                              (self.archive(reference="/missing"), {}),
                              (self.archive(), {"max_bytes": 10}),
                              (self.archive(), {"required_paths": ["absent"]})]:
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.check(data, **options)

    def test_paths_links_duplicates_wal(self):
        for name, kind in [("../escape", tarfile.REGTYPE), ("/absolute", tarfile.REGTYPE),
                           ("a\\b", tarfile.REGTYPE), ("link", tarfile.SYMTYPE),
                           ("hard", tarfile.LNKTYPE), ("payload", tarfile.REGTYPE),
                           ("state.db-wal", tarfile.REGTYPE)]:
            item = tarfile.TarInfo(name)
            item.type = kind
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.check(self.archive(item))


if __name__ == "__main__":
    unittest.main()