"""Bounded local compact-JWE artifacts; private keys must remain off-node.

Callers must provide trusted, immutable parent directories and an ACL-private
output parent on Windows. POSIX staging directories/files use 0700/0600;
Windows mode bits do not establish an ACL. No CLI or live-server operations.
"""
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import tempfile

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

CHUNK = 65536
MAX_PLAIN = 32 * 1024 * 1024
MAX_ENVELOPE = 48 * 1024 * 1024
MAX_PEM = 65536
HEADER = b'eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0'


def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=')


def _unb64(data):
    if not re.fullmatch(rb'[A-Za-z0-9_-]*', data) or len(data) % 4 == 1:
        raise ValueError('invalid artifact encoding')
    result = base64.b64decode(data + b'=' * (-len(data) % 4), altchars=b'-_', validate=True)
    if _b64(result) != data:
        raise ValueError('noncanonical artifact encoding')
    return result


def _open(path, limit):
    path = Path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise ValueError('invalid artifact input')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
    try:
        after = os.fstat(fd)
        if not stat.S_ISREG(after.st_mode) or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise ValueError('artifact input changed')
        return os.fdopen(fd, 'rb')
    except BaseException:
        os.close(fd)
        raise


def _key(path, private=False):
    with _open(path, MAX_PEM) as stream:
        data = stream.read(MAX_PEM)
        if stream.read(1):
            raise ValueError('key exceeds limit')
    key = (serialization.load_pem_private_key(data, password=None) if private
           else serialization.load_pem_public_key(data))
    if not isinstance(key, rsa.RSAPrivateKey if private else rsa.RSAPublicKey) or not 2048 <= key.key_size <= 8192:
        raise ValueError('unsupported recipient key')
    return key


def _fingerprint(key):
    if isinstance(key, rsa.RSAPrivateKey):
        key = key.public_key()
    return hashlib.sha256(key.public_bytes(serialization.Encoding.DER,
                         serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def _oaep():
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


class _Reader:
    def __init__(self, stream):
        self.stream, self.buf, self.eof = stream, b'', False
        self.digest, self.size = hashlib.sha256(), 0

    def part(self, bound):
        # Yield base64 text in multiples of four except the final fragment.
        total = 0
        while True:
            end = self.buf.find(b'.')
            if end >= 0:
                data, self.buf = self.buf[:end], self.buf[end + 1:]
                total += len(data)
                if total > bound:
                    raise ValueError('artifact segment exceeds limit')
                yield data
                return
            if self.eof:
                raise ValueError('missing artifact segment')
            count = len(self.buf) // 4 * 4
            if count:
                data, self.buf = self.buf[:count], self.buf[count:]
                total += len(data)
                if total > bound:
                    raise ValueError('artifact segment exceeds limit')
                yield data
            data = self.stream.read(CHUNK)
            self.digest.update(data)
            self.size += len(data)
            if self.size > MAX_ENVELOPE:
                raise ValueError('artifact exceeds limit')
            self.eof = not data
            self.buf += data

    def metadata(self, bound):
        return b''.join(self.part(bound))

    def tail(self):
        data = self.buf
        if len(data) > 24:
            raise ValueError('invalid authentication tag')
        while not self.eof:
            chunk = self.stream.read(25)
            self.digest.update(chunk)
            self.size += len(chunk)
            self.eof = not chunk
            data += chunk
            if len(data) > 24 or self.size > MAX_ENVELOPE:
                raise ValueError('invalid authentication tag')
        return data


class PublicationUncertainError(RuntimeError):
    """Output was linked, but durability or staging cleanup did not complete.

    Callers must reconcile the existing output before retrying. Never delete
    it blindly: it may already be the successfully published artifact.
    """


def _sync_parent(parent):
    # Windows does not support opening/fsyncing a directory via this API.
    # Its parent ACL and platform durability policy remain caller concerns.
    if os.name != 'posix':
        return
    fd = os.open(parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _publish(output, operation):
    output = Path(output)
    if os.path.lexists(output):
        raise FileExistsError('artifact output occupied')
    published = False
    try:
        # New private child prevents unauthenticated plaintext from being visible
        # at the destination. Parent must not be writable by an adversary.
        with tempfile.TemporaryDirectory(prefix='.artifact-', dir=output.parent) as directory:
            stage = Path(directory) / 'data'
            fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0), 0o600)
            with os.fdopen(fd, 'wb') as stream:
                receipt = operation(stream)
                stream.flush()
                os.fsync(stream.fileno())
            # Atomic no-replace publication, including POSIX where rename overwrites.
            os.link(stage, output)
            published = True
            _sync_parent(output.parent)
        return receipt
    except BaseException:
        if published:
            raise PublicationUncertainError('artifact publication uncertain; reconcile existing output') from None
        raise


def seal_file(source, public_key_path, output):
    """Encrypt a bounded file; return envelope digest, size, recipient fingerprint."""
    recipient = _key(public_key_path)
    key, nonce = os.urandom(32), os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    cipher.authenticate_additional_data(HEADER)

    def operation(out):
        digest, size, plain_size = hashlib.sha256(), 0, 0
        def write(data):
            nonlocal size
            size += len(data)
            if size > MAX_ENVELOPE:
                raise ValueError('artifact exceeds limit')
            digest.update(data)
            out.write(data)
        write(HEADER + b'.' + _b64(recipient.encrypt(key, _oaep())) + b'.' + _b64(nonce) + b'.')
        pending = b''
        with _open(source, MAX_PLAIN) as stream:
            while True:
                block = stream.read(CHUNK)
                if not block:
                    break
                plain_size += len(block)
                if plain_size > MAX_PLAIN:
                    raise ValueError('plaintext exceeds limit')
                pending += cipher.update(block)
                count = len(pending) // 3 * 3
                write(_b64(pending[:count]))
                pending = pending[count:]
        pending += cipher.finalize()
        write(_b64(pending) + b'.' + _b64(cipher.tag))
        return dict(sha256=digest.hexdigest(), size_bytes=size, key_fingerprint=_fingerprint(recipient))
    return _publish(output, operation)


def decrypt_file(envelope, private_key_path, output, expected_sha256):
    """Publish plaintext only after GCM authentication and envelope SHA verification."""
    if not isinstance(expected_sha256, str) or not re.fullmatch('[0-9a-f]{64}', expected_sha256):
        raise ValueError('invalid expected artifact digest')
    recipient = _key(private_key_path, True)

    def operation(out):
        with _open(envelope, MAX_ENVELOPE) as stream:
            reader = _Reader(stream)
            header = reader.metadata(1024)
            def pairs(items):
                result = {}
                for name, value in items:
                    if name in result:
                        raise ValueError('duplicate artifact header')
                    result[name] = value
                return result
            if json.loads(_unb64(header), object_pairs_hook=pairs) != {'alg': 'RSA-OAEP-256', 'enc': 'A256GCM'}:
                raise ValueError('unsupported artifact header')
            wrapped = _unb64(reader.metadata(2048))
            nonce = _unb64(reader.metadata(32))
            if len(wrapped) != recipient.key_size // 8 or len(nonce) != 12:
                raise ValueError('invalid artifact parameters')
            key = recipient.decrypt(wrapped, _oaep())
            if len(key) != 32:
                raise ValueError('invalid content key')
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce)).decryptor()
            cipher.authenticate_additional_data(header)
            size, digest = 0, hashlib.sha256()
            for encoded in reader.part((MAX_PLAIN * 4 + 2) // 3):
                plain = cipher.update(_unb64(encoded))
                size += len(plain)
                if size > MAX_PLAIN:
                    raise ValueError('plaintext exceeds limit')
                digest.update(plain)
                out.write(plain)
            tag = _unb64(reader.tail())
            if len(tag) != 16:
                raise ValueError('invalid authentication tag')
            cipher.finalize_with_tag(tag)
            if not hmac.compare_digest(reader.digest.hexdigest(), expected_sha256):
                raise ValueError('artifact digest mismatch')
            return dict(sha256=digest.hexdigest(), size_bytes=size, key_fingerprint=_fingerprint(recipient))
    return _publish(output, operation)
