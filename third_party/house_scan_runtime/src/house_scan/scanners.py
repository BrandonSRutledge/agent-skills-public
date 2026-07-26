from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .config import load_scan_config, path_excluded
from .install import ensure_gitleaks


def _utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


SECRET_PATH_RE = re.compile(
    r"(^|/)\.env$|\.pem$|id_rsa|credentials\.json|secrets\.ya?ml$|\.ulf$",
    re.IGNORECASE,
)


@dataclass
class CheckResult:
    scanner_id: str
    check_id: str
    name: str
    status: str  # pass|fail|skip|error|waived
    compliance_pct: int
    message: str = ""
    findings_count: int = 0
    waiver_path: str | None = None
    evidence_refs: list[str] = field(default_factory=list)
    timestamp_utc: str = field(default_factory=_utc)

    def to_dict(self) -> dict:
        return {
            "scanner_id": self.scanner_id,
            "check_id": self.check_id,
            "name": self.name,
            "status": self.status,
            "compliance_pct": self.compliance_pct,
            "timestamp_utc": self.timestamp_utc,
            "message": self.message,
            "findings_count": self.findings_count,
            "waiver_path": self.waiver_path,
            "evidence_refs": self.evidence_refs,
        }


def scan_secret_paths(repo: Path) -> CheckResult:
    sid = "baseline.secret_paths"
    try:
        cfg = load_scan_config(repo)
        out = subprocess.run(
            ["git", "ls-files"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        if out.returncode != 0:
            return CheckResult(
                scanner_id=sid,
                check_id=sid,
                name="Secret-like path denylist",
                status="error",
                compliance_pct=0,
                message=f"git ls-files failed: {out.stderr.strip()}",
            )
        tracked = [line for line in out.stdout.splitlines() if line.strip()]
        # Fail-tree fixtures may be committed for harness use; exclude_globs
        # keeps the fixtures repo's own CI green (see house-test-fixtures).
        candidates = [
            p for p in tracked if not path_excluded(p, cfg.exclude_globs)
        ]
        bad = [line for line in candidates if SECRET_PATH_RE.search(line)]
        if bad:
            return CheckResult(
                scanner_id=sid,
                check_id=sid,
                name="Secret-like path denylist",
                status="fail",
                compliance_pct=0,
                message=f"{len(bad)} forbidden path(s)",
                findings_count=len(bad),
                evidence_refs=bad[:20],
            )
        excluded_note = ""
        if cfg.exclude_globs:
            excluded_note = f" (exclude_globs={len(cfg.exclude_globs)})"
        return CheckResult(
            scanner_id=sid,
            check_id=sid,
            name="Secret-like path denylist",
            status="pass",
            compliance_pct=100,
            message=f"No forbidden paths{excluded_note}",
        )
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            scanner_id=sid,
            check_id=sid,
            name="Secret-like path denylist",
            status="error",
            compliance_pct=0,
            message=str(exc),
        )


def scan_gitleaks(repo: Path, *, require_tool: bool = True) -> CheckResult:
    """Third-party gitleaks wrapper (dependency scanner).

    Pass/fail fixture trees are intentionally **not** maintained for this
    scanner in house-test-fixtures — prefer first-party secret scanners long
    term (see docs/DEPENDENCY_REDUCTION.md). Ephemeral known-bad probes remain
    in fixtures dogfood_probes. exclude_globs may still skip fixture fail paths
    if present.
    """
    sid = "baseline.gitleaks"
    try:
        if require_tool:
            gl = ensure_gitleaks()
        else:
            from .install import which_gitleaks

            gl = which_gitleaks()
            if not gl:
                return CheckResult(
                    scanner_id=sid,
                    check_id=sid,
                    name="Gitleaks",
                    status="error",
                    compliance_pct=0,
                    message="gitleaks not installed",
                )
        cfg = load_scan_config(repo)
        cmd = [gl, "detect", "--source", str(repo), "-v", "--no-banner"]
        # If exclude_globs set, pass a temporary gitleaks config allowlist so
        # committed fail-tree material (other scanners) does not trip gitleaks
        # on the fixtures repo. No gitleaks pass/fail fixture trees required.
        cfg_path = None
        if cfg.exclude_globs:
            import tempfile

            # gitleaks allowlist paths are regexes
            allow_paths = []
            for g in cfg.exclude_globs:
                # rough glob → regex: fixtures/**/fail/** → fixtures/.*/fail/.*
                rx = (
                    g.replace("\\", "/")
                    .lstrip("./")
                    .replace("**/", ".*/")
                    .replace("**", ".*")
                    .replace("*", "[^/]*")
                )
                allow_paths.append(rx)
            body = ["title = \"house_scan exclude_globs\"", "[allowlist]", "paths = ["]
            for p in allow_paths:
                body.append(f'  """{p}""",')
            body.append("]")
            td = tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".toml",
                delete=False,
                encoding="utf-8",
            )
            td.write("\n".join(body) + "\n")
            td.close()
            cfg_path = td.name
            cmd.extend(["--config", cfg_path])
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=300,
            )
        finally:
            if cfg_path:
                try:
                    Path(cfg_path).unlink(missing_ok=True)
                except OSError:
                    pass
        # gitleaks exit 0 = clean, 1 = leaks (depending on version; action uses exit-code 2)
        combined = (proc.stdout or "") + (proc.stderr or "")
        if proc.returncode == 0:
            return CheckResult(
                scanner_id=sid,
                check_id=sid,
                name="Gitleaks",
                status="pass",
                compliance_pct=100,
                message="no leaks found",
            )
        return CheckResult(
            scanner_id=sid,
            check_id=sid,
            name="Gitleaks",
            status="fail",
            compliance_pct=0,
            message="leaks found" if "leak" in combined.lower() or proc.returncode != 0 else combined[-500:],
            findings_count=1,
        )
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            scanner_id=sid,
            check_id=sid,
            name="Gitleaks",
            status="error",
            compliance_pct=0,
            message=str(exc),
        )


def scan_waiver_schema(repo: Path) -> CheckResult:
    """Validate any present per-scanner waiver files; missing dir is pass."""
    from .waivers import load_waivers

    sid = "baseline.waiver_schema"
    waivers = load_waivers(repo)
    if not waivers:
        return CheckResult(
            scanner_id=sid,
            check_id=sid,
            name="Per-scanner waiver schema",
            status="pass",
            compliance_pct=100,
            message="no waivers present",
        )
    bad = [w for w in waivers.values() if not w.valid]
    expired = [w for w in waivers.values() if w.valid and not w.active]
    if bad:
        return CheckResult(
            scanner_id=sid,
            check_id=sid,
            name="Per-scanner waiver schema",
            status="fail",
            compliance_pct=0,
            message="; ".join(f"{w.scanner_id}: {w.error}" for w in bad),
            findings_count=len(bad),
        )
    if expired:
        # Expired waivers fail closed as their own concern — still a schema/liveness fail
        return CheckResult(
            scanner_id=sid,
            check_id=sid,
            name="Per-scanner waiver schema",
            status="fail",
            compliance_pct=0,
            message="expired: " + ", ".join(w.scanner_id for w in expired),
            findings_count=len(expired),
        )
    return CheckResult(
        scanner_id=sid,
        check_id=sid,
        name="Per-scanner waiver schema",
        status="pass",
        compliance_pct=100,
        message=f"{len(waivers)} valid unexpired waiver(s)",
    )


def scan_workflow_softfail(repo: Path) -> CheckResult:
    """Heuristic: fail if continue-on-error appears near gitleaks/security job names."""
    sid = "baseline.workflow_softfail"
    wf = repo / ".github" / "workflows"
    if not wf.is_dir():
        return CheckResult(
            scanner_id=sid,
            check_id=sid,
            name="Workflow soft-fail guard",
            status="pass",
            compliance_pct=100,
            message="no workflows",
        )
    findings: list[str] = []
    for path in wf.rglob("*.yml"):
        text = path.read_text(encoding="utf-8", errors="replace")
        if "continue-on-error" not in text:
            continue
        # crude: flag if file mentions gitleaks or security-baseline and continue-on-error
        lower = text.lower()
        if "gitleaks" in lower or "secret" in lower or "security-baseline" in lower:
            if re.search(r"continue-on-error\s*:\s*true", text):
                findings.append(str(path.relative_to(repo)))
    for path in wf.rglob("*.yaml"):
        text = path.read_text(encoding="utf-8", errors="replace")
        if "continue-on-error" not in text:
            continue
        lower = text.lower()
        if "gitleaks" in lower or "secret" in lower or "security-baseline" in lower:
            if re.search(r"continue-on-error\s*:\s*true", text):
                findings.append(str(path.relative_to(repo)))
    if findings:
        return CheckResult(
            scanner_id=sid,
            check_id=sid,
            name="Workflow soft-fail guard",
            status="fail",
            compliance_pct=0,
            message="continue-on-error on security-related workflows",
            findings_count=len(findings),
            evidence_refs=findings,
        )
    return CheckResult(
        scanner_id=sid,
        check_id=sid,
        name="Workflow soft-fail guard",
        status="pass",
        compliance_pct=100,
        message="no security continue-on-error",
    )


BASELINE_SCANNERS: list[Callable[[Path], CheckResult]] = [
    scan_secret_paths,
    # gitleaks wrapped separately for ensure install
]
