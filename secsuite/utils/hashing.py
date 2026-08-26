"""Cryptographic hashing utilities"""

import hashlib
import hmac
from enum import Enum
from pathlib import Path
from typing import BinaryIO, Generator, Optional, Union


class HashAlgorithm(Enum):
    """Supported hash algorithms"""
    SHA256 = "sha256"
    SHA512 = "sha512"
    SHA3_256 = "sha3_256"
    SHA3_512 = "sha3_512"
    BLAKE2B = "blake2b"
    BLAKE2S = "blake2s"

    @classmethod
    def from_string(cls, value: str) -> 'HashAlgorithm':
        """Create from string, defaulting to SHA256"""
        try:
            return cls(value.lower())
        except ValueError:
            return cls.SHA256


DEFAULT_CHUNK_SIZE = 4096


def _get_hasher(algorithm: Union[str, HashAlgorithm]) -> hashlib._Hash:
    """Get hasher instance for algorithm"""
    if isinstance(algorithm, HashAlgorithm):
        algorithm = algorithm.value
    return hashlib.new(algorithm)


def hash_file(
    file_path: Union[str, Path],
    algorithm: Union[str, HashAlgorithm] = HashAlgorithm.SHA256,
    chunk_size: int = DEFAULT_CHUNK_SIZE
) -> Optional[str]:
    """
    Hash a file in chunks to handle large files efficiently.

    Args:
        file_path: Path to file
        algorithm: Hash algorithm to use
        chunk_size: Read chunk size in bytes

    Returns:
        Hex digest string or None on error
    """
    hasher = _get_hasher(algorithm)
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (PermissionError, OSError, IOError):
        return None


def hash_stream(
    stream: BinaryIO,
    algorithm: Union[str, HashAlgorithm] = HashAlgorithm.SHA256,
    chunk_size: int = DEFAULT_CHUNK_SIZE
) -> str:
    """
    Hash data from a stream.

    Args:
        stream: Binary stream to read from
        algorithm: Hash algorithm to use
        chunk_size: Read chunk size in bytes

    Returns:
        Hex digest string
    """
    hasher = _get_hasher(algorithm)
    for chunk in iter(lambda: stream.read(chunk_size), b""):
        hasher.update(chunk)
    return hasher.hexdigest()


def hash_bytes(
    data: bytes,
    algorithm: Union[str, HashAlgorithm] = HashAlgorithm.SHA256
) -> str:
    """Hash a bytes object"""
    hasher = _get_hasher(algorithm)
    hasher.update(data)
    return hasher.hexdigest()


def verify_hmac(
    data: bytes,
    signature: str,
    key: bytes,
    algorithm: Union[str, HashAlgorithm] = HashAlgorithm.SHA256
) -> bool:
    """Verify HMAC signature"""
    expected = hmac.new(key, data, _get_hasher(algorithm).name).hexdigest()
    return hmac.compare_digest(expected, signature)


def generate_hmac(
    data: bytes,
    key: bytes,
    algorithm: Union[str, HashAlgorithm] = HashAlgorithm.SHA256
) -> str:
    """Generate HMAC signature"""
    return hmac.new(key, data, _get_hasher(algorithm).name).hexdigest()


class IncrementalHasher:
    """Incremental hasher for streaming large data"""

    def __init__(self, algorithm: Union[str, HashAlgorithm] = HashAlgorithm.SHA256):
        self.hasher = _get_hasher(algorithm)
        self.algorithm = algorithm

    def update(self, data: bytes) -> 'IncrementalHasher':
        """Update hash with more data"""
        self.hasher.update(data)
        return self

    def update_file(self, file_path: Union[str, Path], chunk_size: int = DEFAULT_CHUNK_SIZE) -> 'IncrementalHasher':
        """Update hash with file contents"""
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                self.hasher.update(chunk)
        return self

    def hexdigest(self) -> str:
        """Get final hex digest"""
        return self.hasher.hexdigest()

    def copy(self) -> 'IncrementalHasher':
        """Create a copy of current state"""
        new_hasher = IncrementalHasher(self.algorithm)
        new_hasher.hasher = self.hasher.copy()
        return new_hasher