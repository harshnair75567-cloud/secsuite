"""FIM Engine - File Integrity Monitoring"""

import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from ...logging import get_logger
from ...utils.fs import walk_files
from ...utils.hashing import HashAlgorithm, hash_file


@dataclass
class FileEntry:
    """File manifest entry"""
    hash: str
    last_seen: str
    size: int
    mtime: float


class PyHashEngine:
    """File integrity monitoring engine"""

    def __init__(
        self,
        target_dir: str,
        algorithm: str = "sha256",
        chunk_size: int = 4096,
        exclude_patterns: Optional[List[str]] = None
    ):
        self.target_dir = Path(target_dir).resolve()
        self.algorithm = HashAlgorithm.from_string(algorithm)
        self.chunk_size = chunk_size
        self.exclude_patterns = exclude_patterns or [
            ".git", "__pycache__", "*.pyc", "*.log", "*.pid", "*.json"
        ]
        self.manifest: Dict[str, FileEntry] = {}
        self._lock = threading.Lock()
        self.logger = get_logger("fim.engine")

    def collect(self) -> Dict[str, FileEntry]:
        """
        Scan directory and build manifest.

        Returns:
            Dictionary of relative path -> FileEntry
        """
        self.logger.info(f"Scanning directory: {self.target_dir}")
        new_manifest = {}

        for path in walk_files(self.target_dir, self.exclude_patterns):
            try:
                rel_path = str(path.relative_to(self.target_dir))
                file_hash = hash_file(path, self.algorithm, self.chunk_size)

                if file_hash:
                    stat = path.stat()
                    new_manifest[rel_path] = FileEntry(
                        hash=file_hash,
                        last_seen=datetime.now().isoformat(),
                        size=stat.st_size,
                        mtime=stat.st_mtime
                    )
            except (OSError, ValueError) as e:
                self.logger.warning(f"Failed to hash {path}: {e}")

        with self._lock:
            self.manifest = new_manifest

        self.logger.info(f"Scan complete: {len(self.manifest)} files indexed")
        return self.manifest.copy()

    def get_manifest(self) -> Dict[str, FileEntry]:
        """Get current manifest"""
        with self._lock:
            return self.manifest.copy()

    def set_manifest(self, manifest: Dict[str, FileEntry]) -> None:
        """Set manifest (for loading baseline)"""
        with self._lock:
            self.manifest = manifest

    def hash_single(self, rel_path: str) -> Optional[str]:
        """Hash a single file by relative path"""
        full_path = self.target_dir / rel_path
        return hash_file(full_path, self.algorithm, self.chunk_size)

    def verify_file(self, rel_path: str) -> bool:
        """Verify a single file against manifest"""
        with self._lock:
            if rel_path not in self.manifest:
                return False
            expected_hash = self.manifest[rel_path].hash

        current_hash = self.hash_single(rel_path)
        return current_hash == expected_hash

    def get_stats(self) -> Dict:
        """Get engine statistics"""
        with self._lock:
            return {
                "target_dir": str(self.target_dir),
                "algorithm": self.algorithm.value,
                "files_tracked": len(self.manifest),
                "total_size": sum(e.size for e in self.manifest.values())
            }