import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import backup_artifact as artifact
from pilot import recovery_rehearsal as recovery


class ArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.public = cls.key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        cls.private = cls.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pub, self.priv = self.root/'public', self.root/'private'
        self.pub.write_bytes(self.public)
        self.priv.write_bytes(self.private)

    def decrypt(self, envelope, expected=None):
        path = self.root/'jwe'
        path.write_bytes(envelope)
        return artifact.decrypt_file(path, self.priv, self.root/'result', expected or hashlib.sha256(envelope).hexdigest())

    def test_bidirectional_and_boundaries(self):
        for size in (0, 1, 2, 3, 65535, 65536, 65537, 140000):
            with self.subTest(size=size):
                payload = os.urandom(size)
                source, sealed = self.root/'source', self.root/'sealed'
                source.write_bytes(payload)
                receipt = artifact.seal_file(source, self.pub, sealed)
                envelope = sealed.read_bytes()
                self.assertEqual(recovery.decrypt(self.key, envelope), payload)
                self.assertEqual(receipt['sha256'], hashlib.sha256(envelope).hexdigest())
                self.assertEqual(receipt['size_bytes'], len(envelope))
                self.assertEqual(set(receipt), {'sha256', 'size_bytes', 'key_fingerprint'})
                receipt = self.decrypt(recovery.seal(self.public, payload))
                self.assertEqual((self.root/'result').read_bytes(), payload)
                self.assertEqual(receipt['sha256'], hashlib.sha256(payload).hexdigest())
                sealed.unlink()
                (self.root/'result').unlink()

    def test_rejections_cleanup(self):
        valid = recovery.seal(self.public, b'synthetic secret')
        parts = valid.split(b'.')
        mutations = [b'.'.join(parts[:4]+[b'X'+parts[4][1:]]), valid+b'.', valid+b'=',
                     b'.'.join([recovery.b64(b'{"alg":"RSA-OAEP-256","alg":"RSA-OAEP-256","enc":"A256GCM"}').encode()]+parts[1:]),
                     b'.'.join([recovery.b64(b'{"alg":"RSA-OAEP-256","enc":"A256GCM","extra":1}').encode()]+parts[1:]),
                     b'.'.join(parts[:3]+[b'A',parts[4]]), b'.'.join(parts[:2]+[b'AA',*parts[3:]])]
        for envelope in mutations:
            with self.subTest(envelope=envelope[:10]):
                with self.assertRaises(Exception):
                    self.decrypt(envelope)
                self.assertFalse((self.root/'result').exists())
                self.assertFalse(list(self.root.glob('.artifact-*')))
        with self.assertRaises(ValueError):
            self.decrypt(valid, '0'*64)
        wrong = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.priv.write_bytes(wrong.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        with self.assertRaises(ValueError):
            self.decrypt(valid)
        self.assertFalse((self.root/'result').exists())

    def test_no_overwrite_and_size(self):
        source, output = self.root/'source', self.root/'out'
        source.write_bytes(b'12345')
        output.write_bytes(b'keep')
        with self.assertRaises(FileExistsError):
            artifact.seal_file(source, self.pub, output)
        self.assertEqual(output.read_bytes(), b'keep')
        with self.assertRaises(FileExistsError):
            artifact.decrypt_file(source, self.priv, output, '0'*64)
        self.assertEqual(output.read_bytes(), b'keep')
        output.unlink()
        with mock.patch.object(artifact, 'MAX_PLAIN', 4):
            with self.assertRaises(ValueError):
                artifact.seal_file(source, self.pub, output)
        with mock.patch.object(artifact, 'MAX_ENVELOPE', 4):
            with self.assertRaises(ValueError):
                self.decrypt(recovery.seal(self.public, b'x'))
        self.assertFalse(output.exists())

    def test_bounded_reads_and_interruption(self):
        source, output = self.root/'source', self.root/'out'
        source.write_bytes(os.urandom(200000))
        original = artifact._open
        class Guard:
            def __init__(self, stream): self.stream = stream
            def __enter__(self): return self
            def __exit__(self, *args): self.stream.close()
            def read(self, size=-1):
                if not 0 <= size <= 65536: raise AssertionError('unbounded read')
                return self.stream.read(size)
        with mock.patch.object(artifact, '_open', side_effect=lambda *a: Guard(original(*a))):
            receipt = artifact.seal_file(source, self.pub, output)
            artifact.decrypt_file(output, self.priv, self.root/'result', receipt['sha256'])
        (self.root/'result').unlink()
        with mock.patch.object(artifact._Reader, 'tail', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                artifact.decrypt_file(output, self.priv, self.root/'result', receipt['sha256'])
        self.assertFalse((self.root/'result').exists())
        output.unlink()
        with mock.patch.object(artifact, '_b64', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                artifact.seal_file(source, self.pub, output)
        self.assertFalse(output.exists())
        self.assertFalse(list(self.root.glob('.artifact-*')))

    @unittest.skipUnless(os.name == 'posix', 'POSIX directory fsync')
    def test_publication_durability_order_and_failure(self):
        source, output = self.root/'source', self.root/'out'
        source.write_bytes(b'synthetic')
        events = []
        real_fsync, real_link = os.fsync, os.link
        def sync(fd):
            import stat
            events.append('directory' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'file')
            real_fsync(fd)
        def link(*args):
            events.append('link')
            real_link(*args)
        with mock.patch.object(artifact.os, 'fsync', side_effect=sync), mock.patch.object(artifact.os, 'link', side_effect=link):
            artifact.seal_file(source, self.pub, output)
        self.assertEqual(events, ['file', 'link', 'directory'])
        output.unlink()
        def fail_directory(fd):
            import stat
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError('synthetic sensitive diagnostic')
            real_fsync(fd)
        with mock.patch.object(artifact.os, 'fsync', side_effect=fail_directory):
            with self.assertRaises(artifact.PublicationUncertainError) as error:
                artifact.seal_file(source, self.pub, output)
        self.assertEqual(str(error.exception), 'artifact publication uncertain; reconcile existing output')
        self.assertTrue(output.is_file())
        published = output.read_bytes()
        with self.assertRaises(FileExistsError):
            artifact.seal_file(source, self.pub, output)
        self.assertEqual(output.read_bytes(), published)
        self.assertFalse(list(self.root.glob('.artifact-*')))

    @unittest.skipUnless(os.name == 'posix', 'POSIX mode and symlink checks')
    def test_symlink_and_private_mode(self):
        source, link = self.root/'source', self.root/'link'
        source.write_bytes(b'x')
        link.symlink_to(source)
        with self.assertRaises(ValueError):
            artifact.seal_file(link, self.pub, self.root/'out')
        artifact.seal_file(source, self.pub, self.root/'out')
        self.assertEqual((self.root/'out').stat().st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()
