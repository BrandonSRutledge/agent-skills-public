from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .compliance import (
    badge_markdown,
    overall_status,
    render_table,
    suite_report_dict,
    update_readme_markers,
    write_compliance_md,
)
from .install import install_tools, uninstall_tools
from .issues import open_gap_issues
from .paths import LIBRARY_ROOT
from .scanners import (
    CheckResult,
    scan_gitleaks,
    scan_secret_paths,
    scan_secrets_content,
    scan_waiver_schema,
    scan_workflow_softfail,
)
from .waivers import active_waiver_for, load_waivers


def _utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _library_commit() -> str | None:
    try:
        p = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(LIBRARY_ROOT),
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        if p.returncode == 0:
            return p.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


def _apply_waivers(results: list[CheckResult], repo: Path) -> list[CheckResult]:
    waivers = load_waivers(repo)
    out: list[CheckResult] = []
    for r in results:
        if r.status not in ("fail", "error"):
            out.append(r)
            continue
        w = active_waiver_for(waivers, r.scanner_id)
        if w is None:
            # attach path if invalid/expired file exists for table link
            cand = repo / "security" / "waivers" / f"{r.scanner_id}.yaml"
            if cand.is_file():
                r.waiver_path = str(cand.relative_to(repo))
            out.append(r)
            continue
        r.status = "waived"
        r.waiver_path = str(w.path.relative_to(repo))
        r.message = f"waived: {w.reason[:80]}… ({w.ticket})" if len(w.reason) > 80 else f"waived: {w.reason} ({w.ticket})"
        out.append(r)
    return out


def cmd_scan(args: argparse.Namespace) -> int:
    repo = Path(args.repo).expanduser().resolve()
    if not repo.is_dir():
        print(f"ERROR: not a directory: {repo}", file=sys.stderr)
        return 2
    if not (repo / ".git").exists():
        print(f"WARN: {repo} has no .git — continuing")

    started = _utc()
    results: list[CheckResult] = []
    results.append(scan_secret_paths(repo))
    results.append(scan_secrets_content(repo))
    # Dual-run: first-party critical content + third-party gitleaks (Phase B)
    results.append(scan_gitleaks(repo, require_tool=not args.no_install))
    results.append(scan_waiver_schema(repo))
    results.append(scan_workflow_softfail(repo))

    results = _apply_waivers(results, repo)
    finished = _utc()
    status, pct, waived = overall_status(results)

    report = suite_report_dict(
        target=str(repo),
        started=started,
        finished=finished,
        results=results,
        library_commit=_library_commit(),
    )
    reports = repo / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    report_path = reports / "house-scan-latest.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    table = render_table(results, pct)
    badge = badge_markdown(status, pct)
    write_compliance_md(repo, table)
    if args.write_readme or True:
        # Always try compliance markers if present (not repo role — roles live as GitHub topics)
        update_readme_markers(repo, table, badge)

    print("=== house_scan summary ===")
    print(f"target: {repo}")
    print(f"overall: {status} ({pct}%)  waived={waived}")
    for r in results:
        print(f"  [{r.status:6}] {r.compliance_pct:3}%  {r.scanner_id}  {r.message}")
    print(f"report: {report_path}")
    print(f"table:  {repo / 'security' / 'COMPLIANCE.md'}")

    if args.open_issues:
        for msg in open_gap_issues(repo, results):
            print(msg)

    # Exit 0 only if no hard fail/error remain
    if any(r.status in ("fail", "error") for r in results):
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="house_scan",
        description="House security scanner suite (install tools, scan repos, compliance UX)",
    )
    p.add_argument("--version", action="version", version=f"house_scan {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("install", help="Install pinned scanner tools")
    sub.add_parser("uninstall", help="Remove house-managed scanner tools")

    s = sub.add_parser("scan", help="Scan a repository")
    s.add_argument("repo", nargs="?", default=".", help="Path to target repo")
    s.add_argument(
        "--open-issues",
        action="store_true",
        help="Open/dedupe GitHub issues for non-waived gaps",
    )
    s.add_argument(
        "--write-readme",
        action="store_true",
        help="Force README marker updates (also updates if markers present)",
    )
    s.add_argument(
        "--no-install",
        action="store_true",
        help="Do not auto-install gitleaks if missing",
    )
    s.add_argument(
        "--scaffold-waivers",
        action="store_true",
        help="Reserved: scaffold incomplete waiver stubs for failing scanners",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.cmd == "install":
        return install_tools()
    if args.cmd == "uninstall":
        return uninstall_tools()
    if args.cmd == "scan":
        return cmd_scan(args)
    parser.error(f"unknown command {args.cmd}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
