"""Tests for hashing utilities"""

import hashlib
import tempfile
from pathlib import Path

import pytest

from secsuite.utils.hashing import (
    hash_file,
    hash_bytes,
    hash_stream,
    verify_hmac,
    generate_hmac,
    IncrementalHasher,
    HashAlgorithm
)


class TestHashing:
    """Test hashing functions"""

    def test_hash_bytes_sha256(self):
        data = b"hello world"
        result = hash_bytes(data, HashAlgorithm.SHA256)
        expected = hashlib.sha256(data).hexdigest()
        assert result == expected

    def test_hash_bytes_sha512(self):
        data = b"test data"
        result = hash_bytes(data, HashAlgorithm.SHA512)
        expected = hashlib.sha512(data).hexdigest()
        assert result == expected

    def test_hash_file(self):
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b"file content for hashing")
            temp_path = f.name

        try:
            result = hash_file(temp_path, HashAlgorithm.SHA256)
            expected = hashlib.sha256(b"file content for hashing").hexdigest()
            assert result == expected
        finally:
            Path(temp_path).unlink()

    def test_hash_file_nonexistent(self):
        result = hash_file("/nonexistent/file.txt", HashAlgorithm.SHA256)
        assert result is None

    def test_hash_stream(self):
        import io
        data = b"stream data for hashing"
        stream = io.BytesIO(data)
        result = hash_stream(stream, HashAlgorithm.SHA256)
        expected = hashlib.sha256(data).hexdigest()
        assert result == expected

    def test_incremental_hasher(self):
        hasher = IncrementalHasher(HashAlgorithm.SHA256)
        hasher.update(b"part1")
        hasher.update(b"part2")
        result = hasher.hexdigest()
        expected = hashlib.sha256(b"part1part2").hexdigest()
        assert result == expected

    def test_incremental_hasher_copy(self):
        hasher = IncrementalHasher(HashAlgorithm.SHA256)
        hasher.update(b"part1")
        copy = hasher.copy()
        hasher.update(b"part2")
        copy.update(b"part3")

        assert hasher.hexdigest() == hashlib.sha256(b"part1part2").hexdigest()
        assert copy.hexdigest() == hashlib.sha256(b"part1part3").hexdigest()

    def test_hmac_generate_verify(self):
        key = b"secret-key"
        data = b"message to authenticate"

        sig = generate_hmac(data, key, HashAlgorithm.SHA256)
        assert verify_hmac(data, sig, key, HashAlgorithm.SHA256)

        # Wrong key should fail
        assert not verify_hmac(data, sig, b"wrong-key", HashAlgorithm.SHA256)

        # Wrong data should fail
        assert not verify_hmac(b"different", sig, key, HashAlgorithm.SHA256)

    def test_algorithm_from_string(self):
        assert HashAlgorithm.from_string("sha256") == HashAlgorithm.SHA256
        assert HashAlgorithm.from_string("SHA256") == HashAlgorithm.SHA256
        assert HashAlgorithm.from_string("sha512") == HashAlgorithm.SHA512
        assert HashAlgorithm.from_string("invalid") == HashAlgorithm.SHA256  # default