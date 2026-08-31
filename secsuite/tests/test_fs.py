"""Tests for filesystem utilities"""

import tempfile
from pathlib import Path

from secsuite.utils.fs import (
    atomic_write,
    ensure_dir,
    find_files,
    get_dir_size,
    get_file_info,
    read_json,
    read_text,
    walk_files,
    write_json,
    write_text,
)


class TestFS:
    """Test filesystem utilities"""

    def test_walk_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "file1.txt").write_text("content1")
            (root / "subdir").mkdir()
            (root / "subdir" / "file2.txt").write_text("content2")
            (root / "subdir" / "file3.log").write_text("log")

            files = list(walk_files(root))
            assert len(files) == 3

            # Test exclude patterns
            files = list(walk_files(root, exclude_patterns=["*.log"]))
            assert len(files) == 2

    def test_read_write_json(self):
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            temp_path = f.name

        try:
            data = {"key": "value", "number": 42, "list": [1, 2, 3]}
            assert write_json(temp_path, data)
            loaded = read_json(temp_path)
            assert loaded == data
        finally:
            Path(temp_path).unlink()

    def test_read_json_missing(self):
        result = read_json("/nonexistent/file.json", default="default_value")
        assert result == "default_value"

    def test_atomic_write(self):
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            temp_path = f.name

        try:
            result = atomic_write(temp_path, writer=lambda f: f.write("atomic content"))
            assert result is True
            assert Path(temp_path).read_text() == "atomic content"
        finally:
            Path(temp_path).unlink()

    def test_atomic_write_failure(self):
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            temp_path = f.name

        try:
            try:
                result = atomic_write(temp_path, writer=lambda f: (f.write("content"), exec("raise ValueError('Intentional error')")))
            except ValueError:
                pass

            # Original file should not exist or be unchanged
            assert not Path(temp_path).exists() or Path(temp_path).read_text() != "content"
        finally:
            if Path(temp_path).exists():
                Path(temp_path).unlink()

    def test_read_write_text(self):
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            temp_path = f.name

        try:
            assert write_text(temp_path, "hello world")
            assert read_text(temp_path) == "hello world"
        finally:
            Path(temp_path).unlink()

    def test_ensure_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            new_dir = Path(tmpdir) / "new" / "nested" / "dir"
            result = ensure_dir(new_dir)
            assert result == new_dir
            assert new_dir.exists()
            assert new_dir.is_dir()

    def test_get_file_info(self):
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False, mode='w') as f:
            f.write("test content")
            temp_path = f.name

        try:
            info = get_file_info(temp_path)
            assert info is not None
            assert info["is_file"] is True
            assert info["is_dir"] is False
            assert info["size"] == 12
        finally:
            Path(temp_path).unlink()

    def test_get_file_info_missing(self):
        info = get_file_info("/nonexistent/file.txt")
        assert info is None

    def test_find_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "test.py").write_text("print('hello')")
            (root / "test.txt").write_text("text")
            (root / "subdir").mkdir()
            (root / "subdir" / "another.py").write_text("more")

            py_files = find_files(root, ["*.py"])
            assert len(py_files) == 2

            txt_files = find_files(root, ["*.txt"])
            assert len(txt_files) == 1

    def test_get_dir_size(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "file1.txt").write_text("a" * 100)
            (root / "file2.txt").write_text("b" * 200)
            (root / "subdir").mkdir()
            (root / "subdir" / "file3.txt").write_text("c" * 300)

            size = get_dir_size(root)
            assert size == 600