"""Tests for FIM engine"""

import tempfile
from pathlib import Path

import pytest

from secsuite.modules.fim.engine import PyHashEngine, FileEntry
from secsuite.modules.fim.audit import verify_integrity, IntegrityChanges, report_findings
from secsuite.modules.fim.manifest import create_baseline, audit_directory, save_manifest, load_manifest


class TestPyHashEngine:
    """Test FIM engine"""

    def test_collect(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "file1.txt").write_text("content1")
            (root / "file2.txt").write_text("content2")
            (root / "subdir").mkdir()
            (root / "subdir" / "file3.txt").write_text("content3")

            engine = PyHashEngine(str(root))
            manifest = engine.collect()

            assert len(manifest) == 3
            assert "file1.txt" in manifest
            assert "file2.txt" in manifest
            assert "subdir/file3.txt" in manifest

            for entry in manifest.values():
                assert isinstance(entry, FileEntry)
                assert len(entry.hash) == 64  # SHA256
                assert entry.size > 0

    def test_collect_with_exclude(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "file.txt").write_text("content")
            (root / "ignore.log").write_text("log")
            (root / "__pycache__").mkdir()
            (root / "__pycache__" / "cached.pyc").write_text("bytecode")

            engine = PyHashEngine(str(root), exclude_patterns=["*.log", "__pycache__", "*.pyc"])
            manifest = engine.collect()

            assert len(manifest) == 1
            assert "file.txt" in manifest

    def test_verify_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "test.txt").write_text("original content")

            engine = PyHashEngine(str(root))
            engine.collect()

            assert engine.verify_file("test.txt") is True

            # Modify file
            (root / "test.txt").write_text("modified content")
            assert engine.verify_file("test.txt") is False

    def test_get_stats(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "file1.txt").write_text("a" * 100)
            (root / "file2.txt").write_text("b" * 200)

            engine = PyHashEngine(str(root))
            engine.collect()

            stats = engine.get_stats()
            assert stats["files_tracked"] == 2
            assert stats["total_size"] == 300


class TestVerifyIntegrity:
    """Test integrity verification"""

    def test_no_changes(self):
        baseline = {
            "file1.txt": FileEntry(hash="abc123", last_seen="2024-01-01", size=10, mtime=1000),
            "file2.txt": FileEntry(hash="def456", last_seen="2024-01-01", size=20, mtime=1000)
        }
        current = {
            "file1.txt": FileEntry(hash="abc123", last_seen="2024-01-02", size=10, mtime=2000),
            "file2.txt": FileEntry(hash="def456", last_seen="2024-01-02", size=20, mtime=2000)
        }

        changes = verify_integrity(baseline, current)
        assert not changes.has_changes()

    def test_modified_file(self):
        baseline = {
            "file1.txt": FileEntry(hash="abc123", last_seen="2024-01-01", size=10, mtime=1000)
        }
        current = {
            "file1.txt": FileEntry(hash="xyz789", last_seen="2024-01-02", size=10, mtime=2000)
        }

        changes = verify_integrity(baseline, current)
        assert changes.has_changes()
        assert "file1.txt" in changes.modified

    def test_added_file(self):
        baseline = {}
        current = {
            "new_file.txt": FileEntry(hash="abc123", last_seen="2024-01-01", size=10, mtime=1000)
        }

        changes = verify_integrity(baseline, current)
        assert changes.has_changes()
        assert "new_file.txt" in changes.added

    def test_deleted_file(self):
        baseline = {
            "deleted.txt": FileEntry(hash="abc123", last_seen="2024-01-01", size=10, mtime=1000)
        }
        current = {}

        changes = verify_integrity(baseline, current)
        assert changes.has_changes()
        assert "deleted.txt" in changes.deleted


class TestManifest:
    """Test manifest operations"""

    def test_save_load_manifest(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "file.txt").write_text("content")

            engine = PyHashEngine(str(root))
            engine.collect()

            baseline_file = str(root / "baseline.json")
            assert save_manifest(engine, baseline_file)

            loaded = load_manifest(baseline_file)
            assert loaded is not None
            assert len(loaded) == 1
            assert "file.txt" in loaded

    def test_create_baseline(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "file.txt").write_text("content")

            baseline_file = str(root / "baseline.json")
            assert create_baseline(str(root), baseline_file)

            loaded = load_manifest(baseline_file)
            assert loaded is not None

    def test_audit_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "file.txt").write_text("original")

            baseline_file = str(root / "baseline.json")
            create_baseline(str(root), baseline_file)

            # Modify file
            (root / "file.txt").write_text("modified")

            result = audit_directory(str(root), baseline_file)
            assert result is not None
            assert result["changes"].has_changes()
            assert "file.txt" in result["changes"].modified