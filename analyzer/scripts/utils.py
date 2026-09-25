"""Shared utilities for analyzer scripts."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Generator


def walk_source_files(
    root: Path, extensions: set[str] | None = None
) -> Generator[Path, None, None]:
    """Yield all source files under a directory tree.

    Args:
        root: Directory to walk.
        extensions: If provided, only yield files with these extensions.
    """
    if not root.exists():
        return

    if extensions is None:
        extensions = {".java", ".kt", ".smali", ".xml", ".json", ".properties"}

    for dirpath, _, filenames in os.walk(root):
        for fname in filenames:
            fpath = Path(dirpath) / fname
            if fpath.suffix.lower() in extensions:
                yield fpath


def safe_read_text(path: Path, max_size: int = 5 * 1024 * 1024) -> str:
    """Read a text file safely, skipping files that are too large."""
    try:
        if path.stat().st_size > max_size:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return ""
