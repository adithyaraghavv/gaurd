"""Small helper to walk source files, skipping dependency and build folders."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build",
             ".next", "guard_out", ".mypy_cache", ".pytest_cache", "vendor"}
MAX_BYTES = 1_000_000

# Set by `guard scan --diff-since`: when not None, only these (resolved) files are reported as changed.
CHANGED: set[Path] | None = None


def is_changed(path) -> bool:
    """True when no diff restriction is active, or the file is in the changed set."""
    return CHANGED is None or Path(path).resolve() in CHANGED


def walk(root: str, suffixes: tuple[str, ...], all_files: bool = False) -> Iterator[Path]:
    """Source files under root. With a diff restriction active only changed files come back, unless
    `all_files` is set (cross-file checks need the whole picture for context and filter their findings)."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if name.endswith(suffixes):
                p = Path(dirpath) / name
                if not all_files and not is_changed(p):
                    continue
                try:
                    if p.stat().st_size <= MAX_BYTES:
                        yield p
                except OSError:
                    continue
