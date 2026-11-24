import hashlib
import json
import os
from fnmatch import fnmatchcase
from pathlib import Path

MAX_FILE = 20 * 1024 * 1024
MAX_FILES = 30000
MAX_BYTES = 300 * 1024 * 1024


def matches_workspace(path: str, pattern: str) -> bool:
    # Only simple segment globs are supported; never guess extglob/negation semantics.
    if any(token in pattern for token in ["**", "!", "{", "}", "(", ")"]):
        return False
    parts, patterns = path.split("/"), pattern.rstrip("/").split("/")
    return len(parts) == len(patterns) and all(fnmatchcase(part, glob) for part, glob in zip(parts, patterns))


def safe_file(root: Path, relative: str) -> Path:
    """Only read regular, contained files with no symlink in the path."""
    root = root.resolve()
    parts = Path(relative).parts
    if Path(relative).is_absolute() or ".." in parts:
        raise ValueError("File path escapes repository")
    current = root
    for part in parts:
        current /= part
        if current.is_symlink():
            raise ValueError("Symlink source files are not supported")
    if not current.is_file() or not current.resolve().is_relative_to(root):
        raise ValueError(f"Not a regular repository file: {relative}")
    if current.stat().st_size > MAX_FILE:
        raise ValueError(f"Source file exceeds {MAX_FILE} bytes: {relative}")
    return current


def read_json(root: Path, relative: str) -> tuple[dict, str]:
    raw = safe_file(root, relative).read_bytes()
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError(f"Invalid JSON in {relative}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object in {relative}")
    return value, hashlib.sha256(raw).hexdigest()


def walk_files(root: Path):
    count = total = 0
    for directory, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in {".git", "node_modules"}
                         and not (Path(directory) / d).is_symlink())
        for name in sorted(names):
            path = Path(directory) / name
            if path.is_symlink() or not path.is_file():
                continue
            count += 1
            total += path.stat().st_size
            if count > MAX_FILES or total > MAX_BYTES:
                raise ValueError("Repository exceeds file-count or total-size limit")
            yield path


def write_json(path: Path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=True) + "\n")
    temporary.replace(path)
