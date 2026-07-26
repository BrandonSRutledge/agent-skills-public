from __future__ import annotations

import json
import os
import platform
import shutil
import stat
import subprocess
import tarfile
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .paths import LIBRARY_ROOT, bin_dir, manifest_path, tools_root


def _utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _load_pins() -> dict[str, Any]:
    path = LIBRARY_ROOT / "tools" / "pins.yaml"
    text = path.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore

        return yaml.safe_load(text)
    except ImportError:
        # Minimal parse for our pins file
        data: dict[str, Any] = {"tools": {}}
        current = None
        for line in text.splitlines():
            if line.startswith("  gitleaks:"):
                current = "gitleaks"
                data["tools"][current] = {}
            elif current and line.startswith("    version:"):
                data["tools"][current]["version"] = line.split(":", 1)[1].strip().strip('"')
            elif current and line.startswith("    github_repo:"):
                data["tools"][current]["github_repo"] = line.split(":", 1)[1].strip()
            elif current and line.startswith("    asset:"):
                data["tools"][current]["asset"] = line.split(":", 1)[1].strip().strip('"')
            elif current and line.startswith("    binary:"):
                data["tools"][current]["binary"] = line.split(":", 1)[1].strip()
        return data


def _arch() -> str:
    m = platform.machine().lower()
    if m in ("x86_64", "amd64"):
        return "x64"
    if m in ("aarch64", "arm64"):
        return "arm64"
    raise RuntimeError(f"Unsupported arch: {m}")


def _read_manifest() -> dict[str, Any]:
    p = manifest_path()
    if not p.is_file():
        return {"schema_version": "1.0.0", "installed": {}}
    return json.loads(p.read_text(encoding="utf-8"))


def _write_manifest(data: dict[str, Any]) -> None:
    tools_root().mkdir(parents=True, exist_ok=True)
    manifest_path().write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def which_gitleaks() -> str | None:
    # Prefer house-managed bin
    managed = bin_dir() / "gitleaks"
    if managed.is_file() and os.access(managed, os.X_OK):
        return str(managed)
    path = shutil.which("gitleaks")
    return path


def install_tools(*, force: bool = False) -> int:
    """Install pinned scanner tools. Returns 0 on success."""
    pins = _load_pins()
    tools = pins.get("tools") or {}
    if "gitleaks" not in tools:
        print("ERROR: pins.yaml missing gitleaks", flush=True)
        return 1

    gl = tools["gitleaks"]
    version = gl["version"]
    existing = which_gitleaks()
    if existing and not force:
        # Verify version soft
        try:
            out = subprocess.run(
                [existing, "version"],
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
            ver_txt = (out.stdout or out.stderr or "").strip()
            if version in ver_txt or ver_txt:
                print(f"OK: gitleaks already present ({existing}) {ver_txt}")
                return 0
        except (OSError, subprocess.TimeoutExpired):
            pass

    arch = _arch()
    asset = gl["asset"].format(version=version, arch=arch)
    url = f"https://github.com/{gl['github_repo']}/releases/download/v{version}/{asset}"
    dest_bin = bin_dir()
    dest_bin.mkdir(parents=True, exist_ok=True)
    target = dest_bin / gl.get("binary", "gitleaks")

    print(f"Installing gitleaks {version} from {url}")
    with tempfile.TemporaryDirectory() as tmp:
        tgz = Path(tmp) / "gitleaks.tgz"
        urllib.request.urlretrieve(url, tgz)  # noqa: S310 — pinned release URL
        with tarfile.open(tgz, "r:gz") as tf:
            tf.extractall(tmp)
        src = Path(tmp) / gl.get("binary", "gitleaks")
        if not src.is_file():
            # search
            found = list(Path(tmp).rglob("gitleaks"))
            if not found:
                print("ERROR: gitleaks binary not in archive", flush=True)
                return 1
            src = found[0]
        shutil.copy2(src, target)
        target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    man = _read_manifest()
    man.setdefault("installed", {})["gitleaks"] = {
        "version": version,
        "path": str(target),
        "installed_utc": _utc(),
        "url": url,
    }
    _write_manifest(man)
    print(f"OK: installed {target}")
    # Ensure PATH hint
    print(f"HINT: export PATH=\"{dest_bin}:$PATH\"")
    return 0


def uninstall_tools() -> int:
    """Remove only house-managed installs from manifest."""
    man = _read_manifest()
    installed = man.get("installed") or {}
    if not installed:
        print("OK: nothing house-managed to uninstall")
        return 0
    for name, meta in list(installed.items()):
        path = Path(meta.get("path") or "")
        if path.is_file() and str(tools_root()) in str(path.resolve()):
            path.unlink()
            print(f"OK: removed {path}")
        else:
            print(f"SKIP: not removing unmanaged path for {name}: {path}")
        del installed[name]
    man["installed"] = installed
    man["uninstalled_utc"] = _utc()
    _write_manifest(man)
    return 0


def ensure_gitleaks() -> str:
    path = which_gitleaks()
    if path:
        return path
    code = install_tools()
    if code != 0:
        raise RuntimeError("failed to install gitleaks")
    path = which_gitleaks()
    if not path:
        raise RuntimeError("gitleaks not found after install")
    return path
