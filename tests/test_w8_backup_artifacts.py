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
                tar.addfile(item, io.BytesIO(content))
            if extra:
                tar.addfile(extra)
        return output.getvalue()

    def check(self, data, **kwargs):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact.tar"
            path.write_bytes(data)
            return module.inspect_archive(path, kwargs.pop("digest", hashlib.sha256(data).hexdigest()), 3, **kwargs)

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