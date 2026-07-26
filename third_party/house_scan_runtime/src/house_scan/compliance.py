from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .scanners import CheckResult

# Short unique badge labels per scanner_id (stable, human-readable)
SCANNER_BADGE_LABELS: dict[str, str] = {
    "baseline.secret_paths": "secret_paths",
    "baseline.gitleaks": "gitleaks",
    "baseline.waiver_schema": "waiver_schema",
    "baseline.workflow_softfail": "workflow_softfail",
}


def overall_status(results: list[CheckResult]) -> tuple[str, int, int]:
    """Return (overall_status, overall_pct, waived_count)."""
    if not results:
        return "passing", 100, 0
    pcts = [r.compliance_pct for r in results]
    overall_pct = int(round(sum(pcts) / len(pcts)))
    waived = sum(1 for r in results if r.status == "waived")
    hard_fail = any(r.status in ("fail", "error") for r in results)
    if hard_fail:
        return "failing", overall_pct, waived
    if waived:
        return "waived", overall_pct, waived
    return "passing", overall_pct, waived


def status_color(status: str, compliance_pct: int) -> str:
    if status == "waived":
        return "yellow"
    if status in ("fail", "error") or compliance_pct < 100:
        if status == "pass" and compliance_pct < 100:
            return "orange"
        if status in ("fail", "error"):
            return "red"
    if status == "pass" and compliance_pct >= 100:
        return "brightgreen"
    if status == "skip":
        return "lightgrey"
    if compliance_pct >= 100:
        return "brightgreen"
    if compliance_pct >= 50:
        return "orange"
    return "red"


def badge_label_for(scanner_id: str, name: str | None = None) -> str:
    if scanner_id in SCANNER_BADGE_LABELS:
        return SCANNER_BADGE_LABELS[scanner_id]
    # Unique, shields-safe: prefer id tail after last dot
    if "." in scanner_id:
        return scanner_id.rsplit(".", 1)[-1]
    if name:
        return re.sub(r"[^A-Za-z0-9_.-]+", "_", name)[:32] or scanner_id
    return scanner_id


def shields_badge_url(label: str, message: str, color: str) -> str:
    """
    Use shields.io static v1 query API — reliable vs hyphen-path badges
    (paths like house-scan-passing-100%-green 404 or mis-parse).
    """
    return (
        "https://img.shields.io/static/v1?"
        f"label={quote(label, safe='')}&"
        f"message={quote(message, safe='')}&"
        f"color={quote(color, safe='')}"
    )


def scanner_badge_markdown(r: CheckResult) -> str:
    label = badge_label_for(r.scanner_id, r.name)
    # Message shows percent; suffix waived when applicable
    if r.status == "waived":
        message = f"{r.compliance_pct}% waived"
    else:
        message = f"{r.compliance_pct}%"
    color = status_color(r.status, r.compliance_pct)
    url = shields_badge_url(label, message, color)
    # Alt text includes full scanner id for accessibility / uniqueness
    alt = f"{r.scanner_id} {message}"
    return f"![{alt}]({url})"


def overall_badge_markdown(status: str, overall_pct: int) -> str:
    color = {
        "passing": "brightgreen",
        "waived": "yellow",
        "failing": "red",
    }.get(status, "lightgrey")
    message = f"{overall_pct}%"
    if status == "waived":
        message = f"{overall_pct}% waived"
    elif status == "failing":
        message = f"{overall_pct}% failing"
    url = shields_badge_url("house_scan", message, color)
    return f"![house_scan {message}]({url})\n"


def render_table(results: list[CheckResult], overall_pct: int) -> str:
    """Two columns: scanner badge (name + %) | waiver link."""
    lines = [
        "| Scanner (badge) | Waiver |",
        "|-----------------|--------|",
    ]
    for r in results:
        badge = scanner_badge_markdown(r)
        if r.waiver_path:
            waiver_cell = f"[waiver]({r.waiver_path})"
        else:
            waiver_cell = "—"
        lines.append(f"| {badge} | {waiver_cell} |")
    # Overall row uses overall status colors via synthetic result
    status, _, _ = overall_status(results)
    overall = CheckResult(
        scanner_id="house_scan.overall",
        check_id="house_scan.overall",
        name="Overall",
        status="pass" if status == "passing" else ("waived" if status == "waived" else "fail"),
        compliance_pct=overall_pct,
    )
    # Force label Overall
    overall_badge = (
        f"![house_scan.overall {overall_pct}%]("
        f"{shields_badge_url('Overall', f'{overall_pct}%' + (' waived' if status == 'waived' else ''), status_color(overall.status, overall_pct))}"
        f")"
    )
    lines.append(f"| {overall_badge} | |")
    return "\n".join(lines) + "\n"


def badge_markdown(status: str, overall_pct: int) -> str:
    """Top-of-README overall badge."""
    return overall_badge_markdown(status, overall_pct)


def write_compliance_md(repo: Path, table: str) -> Path:
    sec = repo / "security"
    sec.mkdir(parents=True, exist_ok=True)
    path = sec / "COMPLIANCE.md"
    body = (
        "# House scan compliance\n\n"
        "_Generated by house_scan — do not hand-edit percentages or badges._\n\n"
        f"{table}\n"
    )
    path.write_text(body, encoding="utf-8")
    return path


def _replace_block(src: str, start: str, end: str, inner: str) -> tuple[str, bool]:
    if start not in src or end not in src:
        return src, False
    pattern = re.compile(
        re.escape(start) + r".*?" + re.escape(end),
        re.DOTALL,
    )
    repl = f"{start}\n{inner.rstrip()}\n{end}"
    new, n = pattern.subn(repl, src, count=1)
    return new, n > 0


def update_readme_markers(repo: Path, table: str, badge: str) -> bool:
    readme = repo / "README.md"
    if not readme.is_file():
        return False
    text = readme.read_text(encoding="utf-8")

    text, c1 = _replace_block(
        text, "<!-- HOUSE_BADGE:START -->", "<!-- HOUSE_BADGE:END -->", badge
    )
    text, c2 = _replace_block(
        text,
        "<!-- HOUSE_COMPLIANCE:START -->",
        "<!-- HOUSE_COMPLIANCE:END -->",
        table,
    )
    if c1 or c2:
        readme.write_text(text, encoding="utf-8")
        return True
    return False


def update_repo_role_badge(repo: Path, role_kind: str, color: str = "blue") -> bool:
    """Update <!-- HOUSE_REPO_ROLE:START/END --> if present."""
    readme = repo / "README.md"
    if not readme.is_file():
        return False
    text = readme.read_text(encoding="utf-8")
    if "<!-- HOUSE_REPO_ROLE:START -->" not in text:
        return False
    url = shields_badge_url("repo", role_kind, color)
    inner = f"![repo role: {role_kind}]({url})"
    text, ok = _replace_block(
        text, "<!-- HOUSE_REPO_ROLE:START -->", "<!-- HOUSE_REPO_ROLE:END -->", inner
    )
    if ok:
        readme.write_text(text, encoding="utf-8")
    return ok


def suite_report_dict(
    *,
    target: str,
    started: str,
    finished: str,
    results: list[CheckResult],
    library_commit: str | None,
) -> dict[str, Any]:
    status, pct, waived = overall_status(results)
    return {
        "schema_version": "1.0.0",
        "target_repo": target,
        "library_commit": library_commit,
        "started_utc": started,
        "finished_utc": finished,
        "overall_compliance_pct": pct,
        "overall_status": status,
        "waived_count": waived,
        "results": [r.to_dict() for r in results],
    }
