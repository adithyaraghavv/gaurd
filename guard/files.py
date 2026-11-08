"""Small helper to walk source files, skipping dependency and build folders."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build",
             ".next", "guard_out", ".mypy_cache", ".pytest_cache", "vendor"}
MAX_BYTES = 1_000_000


def walk(root: str, suffixes: tuple[str, ...]) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if name.endswith(suffixes):
                p = Path(dirpath) / name
                try:
                    if p.stat().st_size <= MAX_BYTES:
                        yield p
                except OSError:
                    continue
