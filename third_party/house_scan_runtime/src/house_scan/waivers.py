from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class Waiver:
    scanner_id: str
    check_id: str
    reason: str
    owner: str
    ticket: str
    expires_on: date
    path: Path
    valid: bool
    error: str | None = None

    @property
    def active(self) -> bool:
        """True if schema-valid and not expired (UTC date)."""
        if not self.valid:
            return False
        today = datetime.now(timezone.utc).date()
        return self.expires_on >= today


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    data: dict[str, Any] = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip() or line.lstrip().startswith("#"):
            i += 1
            continue
        if ":" not in line:
            i += 1
            continue
        key, _, rest = line.partition(":")
        key = key.strip()
        rest = rest.strip()
        if rest in (">-", "|", ">"):
            parts: list[str] = []
            i += 1
            while i < len(lines):
                nxt = lines[i]
                if nxt.startswith("  ") or nxt.startswith("\t"):
                    parts.append(nxt.strip())
                    i += 1
                    continue
                if not nxt.strip():
                    i += 1
                    continue
                break
            data[key] = " ".join(parts)
            continue
        if (rest.startswith('"') and rest.endswith('"')) or (
            rest.startswith("'") and rest.endswith("'")
        ):
            rest = rest[1:-1]
        data[key] = rest
        i += 1
    return data


def load_waiver_file(path: Path) -> Waiver:
    text = path.read_text(encoding="utf-8")
    # Phase D: stdlib-first. House waivers use a flat key: value subset.
    raw = _parse_simple_yaml(text)
    if not isinstance(raw, dict):
        return Waiver(
            scanner_id=path.stem,
            check_id=path.stem,
            reason="",
            owner="",
            ticket="",
            expires_on=date(1970, 1, 1),
            path=path,
            valid=False,
            error="waiver is not a mapping",
        )

    errors: list[str] = []
    scanner_id = str(raw.get("scanner_id") or "")
    check_id = str(raw.get("check_id") or scanner_id)
    reason = str(raw.get("reason") or "")
    owner = str(raw.get("owner") or "")
    ticket = str(raw.get("ticket") or "")
    exp_s = str(raw.get("expires_on") or "")

    if scanner_id != path.stem:
        errors.append(f"scanner_id {scanner_id!r} != file stem {path.stem!r}")
    if len(reason) < 20:
        errors.append("reason must be >= 20 chars")
    if not owner:
        errors.append("owner required")
    if len(ticket) < 3:
        errors.append("ticket required")
    try:
        expires = date.fromisoformat(exp_s)
    except ValueError:
        expires = date(1970, 1, 1)
        errors.append(f"invalid expires_on {exp_s!r}")

    # Pure-Python field checks above are the runtime contract (Phase D).
    # Author-time schema dogfood: scripts/validate_schemas.py

    return Waiver(
        scanner_id=scanner_id or path.stem,
        check_id=check_id or path.stem,
        reason=reason,
        owner=owner,
        ticket=ticket,
        expires_on=expires,
        path=path,
        valid=not errors,
        error="; ".join(errors) if errors else None,
    )


def load_waivers(repo: Path) -> dict[str, Waiver]:
    """Load per-scanner waivers from security/waivers/<scanner_id>.yaml."""
    d = repo / "security" / "waivers"
    out: dict[str, Waiver] = {}
    if not d.is_dir():
        return out
    for path in sorted(d.glob("*.yaml")) + sorted(d.glob("*.yml")):
        w = load_waiver_file(path)
        out[w.scanner_id] = w
    return out


def active_waiver_for(waivers: dict[str, Waiver], scanner_id: str) -> Waiver | None:
    w = waivers.get(scanner_id)
    if w is None:
        return None
    if w.active:
        return w
    return None
