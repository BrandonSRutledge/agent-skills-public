"""Repo-local house_scan configuration (security/house_scan.yaml)."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ScanConfig:
    """Optional per-repo scan config.

    exclude_globs: paths relative to repo root (git-style). Supports * and **.
    Used so fixture fail-trees can live in-repo without failing the fixtures
    repo's own CI while still being copied into mini-repos for harness tests.
    """

    schema_version: str = "1.0.0"
    exclude_globs: list[str] = field(default_factory=list)
    path: Path | None = None


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    """Minimal YAML subset for house_scan.yaml (no nested maps beyond lists)."""
    data: dict[str, Any] = {}
    lines = text.splitlines()
    i = 0
    current_list_key: str | None = None
    while i < len(lines):
        line = lines[i]
        raw = line.rstrip()
        if not raw.strip() or raw.lstrip().startswith("#"):
            i += 1
            continue
        # list item under previous key
        m_item = re.match(r"^(\s*)-\s+(.*)$", raw)
        if m_item and current_list_key:
            val = m_item.group(2).strip()
            if (val.startswith('"') and val.endswith('"')) or (
                val.startswith("'") and val.endswith("'")
            ):
                val = val[1:-1]
            data.setdefault(current_list_key, []).append(val)
            i += 1
            continue
        if ":" in raw and not raw.lstrip().startswith("-"):
            key, _, rest = raw.partition(":")
            key = key.strip()
            rest = rest.strip()
            current_list_key = None
            if rest == "" or rest == "|" or rest == ">" or rest == ">-":
                # maybe a list follows
                current_list_key = key
                data[key] = []
            else:
                if (rest.startswith('"') and rest.endswith('"')) or (
                    rest.startswith("'") and rest.endswith("'")
                ):
                    rest = rest[1:-1]
                data[key] = rest
            i += 1
            continue
        i += 1
    return data


def load_scan_config(repo: Path) -> ScanConfig:
    """Load security/house_scan.yaml if present; else empty defaults."""
    path = repo / "security" / "house_scan.yaml"
    if not path.is_file():
        # also accept .yml
        path = repo / "security" / "house_scan.yml"
    if not path.is_file():
        return ScanConfig()

    text = path.read_text(encoding="utf-8")
    # Phase D: stdlib-first (exclude_globs list subset only)
    raw = _parse_simple_yaml(text)

    if not isinstance(raw, dict):
        return ScanConfig(path=path)

    globs: list[str] = []
    eg = raw.get("exclude_globs") or raw.get("exclude_paths") or []
    if isinstance(eg, list):
        globs = [str(x) for x in eg if x is not None and str(x).strip()]
    elif isinstance(eg, str) and eg.strip():
        globs = [eg.strip()]

    return ScanConfig(
        schema_version=str(raw.get("schema_version") or "1.0.0"),
        exclude_globs=globs,
        path=path,
    )


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Convert a simple glob with * and ** to a fullmatch regex."""
    pat = pattern.replace("\\", "/").lstrip("./")
    # Escape then restore wildcards
    # ** → match across segments; * → single segment
    out: list[str] = []
    i = 0
    while i < len(pat):
        if pat.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pat.startswith("**", i):
            out.append(".*")
            i += 2
        elif pat[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pat[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pat[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def path_excluded(rel_path: str, exclude_globs: list[str]) -> bool:
    """Return True if rel_path matches any exclude glob (repo-relative)."""
    if not exclude_globs:
        return False
    rel = rel_path.replace("\\", "/").lstrip("./")
    for g in exclude_globs:
        g = g.replace("\\", "/").lstrip("./")
        if not g:
            continue
        # Directory-style: trailing /** already handled; also allow bare dir prefix
        if _glob_to_regex(g).match(rel):
            return True
        # If pattern ends with /**, also match the directory itself
        if g.endswith("/**"):
            prefix = g[:-3].rstrip("/")
            if rel == prefix or rel.startswith(prefix + "/"):
                # still require ** semantics: if prefix has no wildcards, prefix match is enough
                if "*" not in prefix and "?" not in prefix:
                    return True
                if _glob_to_regex(prefix + "/**").match(rel) or _glob_to_regex(prefix).match(rel):
                    return True
    return False


def filter_paths(paths: list[str], exclude_globs: list[str]) -> list[str]:
    """Drop paths that match exclude_globs."""
    if not exclude_globs:
        return paths
    return [p for p in paths if not path_excluded(p, exclude_globs)]
