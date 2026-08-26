"""Filesystem utilities"""

import json
import os
import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Generator, Iterator, List, Optional, Set, Union


def walk_files(
    root: Union[str, Path],
    exclude_patterns: Optional[List[str]] = None,
    follow_symlinks: bool = False
) -> Iterator[Path]:
    """
    Walk files in directory tree.

    Args:
        root: Root directory
        exclude_patterns: Patterns to exclude (fnmatch style)
        follow_symlinks: Follow symbolic links

    Yields:
        File paths
    """
    import fnmatch

    root = Path(root).resolve()
    exclude_patterns = exclude_patterns or []

    def should_exclude(path: Path) -> bool:
        rel = path.relative_to(root)
        for pattern in exclude_patterns:
            if fnmatch.fnmatch(str(rel), pattern) or fnmatch.fnmatch(path.name, pattern):
                return True
        return False

    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        dirpath = Path(dirpath)

        if should_exclude(dirpath):
            dirnames[:] = []
            continue

        dirnames[:] = [d for d in dirnames if not should_exclude(dirpath / d)]

        for filename in filenames:
            filepath = dirpath / filename
            if not should_exclude(filepath):
                yield filepath


def read_json(path: Union[str, Path], default: Any = None) -> Any:
    """
    Read JSON file safely.

    Args:
        path: File path
        default: Default value if file doesn't exist or is invalid

    Returns:
        Parsed JSON or default
    """
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, IOError):
        return default


def write_json(path: Union[str, Path], data: Any, indent: int = 2) -> bool:
    """
    Write JSON file atomically.

    Args:
        path: File path
        data: Data to write
        indent: JSON indentation

    Returns:
        True if successful
    """
    return atomic_write(path, writer=lambda f: json.dump(data, f, indent=indent))


def atomic_write(
    path: Union[str, Path],
    writer = None,
    mode: str = 'w',
    **kwargs
) -> bool:
    """
    Atomically write to a file using a temporary file.

    Args:
        path: Target file path
        writer: Optional callable that receives the file object to write
        mode: File mode (used if writer is None)
        **kwargs: Additional arguments for open()

    Returns:
        True if successful
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile(
        mode=mode,
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
        **kwargs
    ) as tmp:
        try:
            if writer is not None:
                writer(tmp)
            tmp.flush()
            os.fsync(tmp.fileno())
            os.replace(tmp.name, path)
            return True
        except Exception:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass
            return False


def read_text(path: Union[str, Path], default: str = "") -> str:
    """Read text file safely"""
    try:
        return Path(path).read_text()
    except (FileNotFoundError, IOError):
        return default


def write_text(path: Union[str, Path], content: str) -> bool:
    """Write text file atomically"""
    return atomic_write(path, writer=lambda f: f.write(content))


def copy_tree(src: Union[str, Path], dst: Union[str, Path], exclude: Optional[Set[str]] = None) -> bool:
    """Copy directory tree with optional exclusions"""
    try:
        exclude = exclude or set()
        shutil.copytree(
            src, dst,
            ignore=shutil.ignore_patterns(*exclude) if exclude else None,
            dirs_exist_ok=True
        )
        return True
    except (OSError, shutil.Error):
        return False


def remove_tree(path: Union[str, Path]) -> bool:
    """Remove directory tree"""
    try:
        shutil.rmtree(path)
        return True
    except (OSError, FileNotFoundError):
        return False


def ensure_dir(path: Union[str, Path]) -> Path:
    """Ensure directory exists"""
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_file_info(path: Union[str, Path]) -> Optional[Dict]:
    """Get file metadata"""
    try:
        stat = Path(path).stat()
        return {
            "path": str(path),
            "size": stat.st_size,
            "mtime": stat.st_mtime,
            "atime": stat.st_atime,
            "ctime": stat.st_ctime,
            "mode": stat.st_mode,
            "is_file": Path(path).is_file(),
            "is_dir": Path(path).is_dir(),
            "is_symlink": Path(path).is_symlink()
        }
    except (OSError, FileNotFoundError):
        return None


def find_files(
    root: Union[str, Path],
    patterns: List[str],
    exclude_patterns: Optional[List[str]] = None
) -> List[Path]:
    """Find files matching patterns"""
    import fnmatch

    root = Path(root)
    results = []

    for filepath in walk_files(root, exclude_patterns):
        for pattern in patterns:
            if fnmatch.fnmatch(filepath.name, pattern):
                results.append(filepath)
                break

    return results


def get_dir_size(path: Union[str, Path]) -> int:
    """Get total size of directory in bytes"""
    total = 0
    for filepath in walk_files(path):
        try:
            total += filepath.stat().st_size
        except OSError:
            pass
    return total