from __future__ import annotations

import os
from pathlib import Path

LIBRARY_ROOT = Path(__file__).resolve().parents[2]


def tools_root() -> Path:
    env = os.environ.get("HOUSE_SECURITY_TOOLS_ROOT")
    if env:
        return Path(env).expanduser().resolve()
    return (Path.home() / ".local" / "share" / "house-security-tools").resolve()


def bin_dir() -> Path:
    return tools_root() / "bin"


def manifest_path() -> Path:
    return tools_root() / "install-manifest.json"
