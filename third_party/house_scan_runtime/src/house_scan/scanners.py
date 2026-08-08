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

# Critical content shapes only (Phase B — docs/DEPENDENCY_REDUCTION.md).
# Keep patterns strict so docs mentioning rule *names* do not false-positive.
_SECRETS_CONTENT_RULES: list[tuple[str, re.Pattern[str]]] = [
    (
        "pem_private_key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"
        ),
    ),
    (
        "slack_token",
        re.compile(
            r"\bxox[baprs]-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{20,}\b"
        ),
    ),
    (
        "aws_access_key_id",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    (
        "github_pat",
        re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
    ),
    (
        "github_fine_grained_pat",
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    ),
    (
        "github_oauth_token",
        re.compile(r"\bgho_[A-Za-z0-9]{36}\b"),
    ),
    (
        "github_user_to_server",
        re.compile(r"\bghu_[A-Za-z0-9]{36}\b"),
    ),
    (
        "gitlab_pat",
        re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
    ),
    (
        "stripe_secret_key",
        re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{20,}\b"),
    ),
    (
        "npm_access_token",
        re.compile(r"\bnpm_[A-Za-z0-9]{36,}\b"),
    ),
    (
        "openai_api_key",
        # sk-proj-… / sk-… with long body (avoid matching short “sk-” prose)
        re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{32,}\b"),
    ),
    (
        "anthropic_api_key",
        re.compile(r"\bsk-ant-[A-Za-z0-9_-]{24,}\b"),
    ),
]

# Skip likely-binary / non-text when sampling content
_SECRETS_CONTENT_SKIP_SUFFIX = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".pdf",
    ".zip",
    ".gz",
    ".tgz",
    ".bz2",
    ".xz",
    ".7z",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp3",
    ".mp4",
    ".wav",
    ".ogg",
    ".wasm",
    ".dll",
    ".so",
    ".dylib",
    ".exe",
    ".bin",
    ".pyc",
    ".pyo",
}


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


def scan_secrets_content(repo: Path) -> CheckResult:
    """First-party critical secret *content* scanner (Phase B).

    Scans tracked text files for a small set of high-confidence secret shapes.
    Complements path denylist. Default content gate after Phase C (gitleaks
    retired from suite; optional --with-gitleaks dual-run only).
    No real secrets in fixtures — synthetic shapes that match patterns only.
    """
    sid = "baseline.secrets_content"
    try:
        cfg = load_scan_config(repo)
        out = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=str(repo),
            capture_output=True,
            check=False,
            timeout=60,
        )
        if out.returncode != 0:
            err = (out.stderr or b"").decode("utf-8", errors="replace").strip()
            return CheckResult(
                scanner_id=sid,
                check_id=sid,
                name="Critical secrets content",
                status="error",
                compliance_pct=0,
                message=f"git ls-files failed: {err}",
            )
        tracked = [
            p for p in out.stdout.decode("utf-8", errors="replace").split("\0") if p
        ]
        findings: list[str] = []
        for rel in tracked:
            if path_excluded(rel, cfg.exclude_globs):
                continue
            suffix = Path(rel).suffix.lower()
            if suffix in _SECRETS_CONTENT_SKIP_SUFFIX:
                continue
            path = repo / rel
            if not path.is_file():
                continue
            try:
                # Cap read size to avoid huge blobs
                raw = path.read_bytes()[:512_000]
            except OSError as exc:
                findings.append(f"{rel}: read error {exc}")
                continue
            if b"\0" in raw[:8192]:
                continue  # binary
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                text = raw.decode("utf-8", errors="replace")
            for rule_id, pattern in _SECRETS_CONTENT_RULES:
                if pattern.search(text):
                    findings.append(f"{rel}:{rule_id}")
                    if len(findings) >= 50:
                        break
            if len(findings) >= 50:
                break
        if findings:
            return CheckResult(
                scanner_id=sid,
                check_id=sid,
                name="Critical secrets content",
                status="fail",
                compliance_pct=0,
                message=f"{len(findings)} critical secret shape(s)",
                findings_count=len(findings),
                evidence_refs=findings[:20],
            )
        excluded_note = ""
        if cfg.exclude_globs:
            excluded_note = f" (exclude_globs={len(cfg.exclude_globs)})"
        return CheckResult(
            scanner_id=sid,
            check_id=sid,
            name="Critical secrets content",
            status="pass",
            compliance_pct=100,
            message=f"No critical secret shapes{excluded_note}",
        )
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            scanner_id=sid,
            check_id=sid,
            name="Critical secrets content",
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
    if present. Opt-in only via ``house_scan scan --with-gitleaks`` (Phase C).
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


_SECURITY_WF_MARKERS = re.compile(
    r"gitleaks|secret|security-baseline|house[-_]?scan|security[-_]?scan",
    re.I,
)


def scan_workflow_softfail(repo: Path) -> CheckResult:
    """Fail if continue-on-error:true appears in security-related workflow files.

    Security-related: mentions gitleaks, secret, security-baseline, house-scan /
    house_scan (house first-party suite), or security-scan.
    """
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
    for path in list(wf.rglob("*.yml")) + list(wf.rglob("*.yaml")):
        text = path.read_text(encoding="utf-8", errors="replace")
        if "continue-on-error" not in text:
            continue
        if not _SECURITY_WF_MARKERS.search(text):
            continue
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


def _on_events_with_path_filters(on_block: object) -> list[str]:
    """Return event names under workflow `on:` that set paths or paths-ignore."""
    found: list[str] = []
    if not isinstance(on_block, dict):
        return found
    for event, conf in on_block.items():
        if event in ("workflow_call", "workflow_dispatch", "schedule", "release"):
            continue
        if not isinstance(conf, dict):
            continue
        if "paths" in conf or "paths-ignore" in conf:
            found.append(str(event))
    return found


def scan_workflow_path_filters(repo: Path) -> CheckResult:
    """Fail if security-related workflows use path filters on push/PR (ops#174 / #181).

    Path filters on security jobs create blind spots: code can land on main without
    house-scan when only non-matching paths change (SECURITY_DOGFOOD).
    """
    sid = "baseline.workflow_path_filters"
    wf = repo / ".github" / "workflows"
    if not wf.is_dir():
        return CheckResult(
            scanner_id=sid,
            check_id=sid,
            name="Workflow path-filter guard",
            status="pass",
            compliance_pct=100,
            message="no workflows",
        )
    try:
        import yaml  # type: ignore
    except ImportError:
        yaml = None  # type: ignore

    findings: list[str] = []
    for path in list(wf.rglob("*.yml")) + list(wf.rglob("*.yaml")):
        text = path.read_text(encoding="utf-8", errors="replace")
        if not _SECURITY_WF_MARKERS.search(text):
            continue
        rel = str(path.relative_to(repo))
        events: list[str] = []
        if yaml is not None:
            try:
                data = yaml.safe_load(text)
            except Exception:
                data = None
            if isinstance(data, dict):
                # PyYAML 1.1: unquoted key `on` loads as boolean True
                on_block = data.get("on")
                if on_block is None and True in data:
                    on_block = data.get(True)
                events = _on_events_with_path_filters(on_block)
        if not events:
            # Regex fallback: workflow-level paths under push/pull_request
            if re.search(r"(?m)^\s+(paths|paths-ignore)\s*:", text) and re.search(
                r"(?m)^(on:|\s+(push|pull_request):)", text
            ):
                events = ["path_filter"]
        for ev in events:
            findings.append(f"{rel}:on.{ev} has paths/paths-ignore (security workflow)")

    if findings:
        return CheckResult(
            scanner_id=sid,
            check_id=sid,
            name="Workflow path-filter guard",
            status="fail",
            compliance_pct=0,
            message="path filters on security-related workflows (blind spot risk)",
            findings_count=len(findings),
            evidence_refs=findings,
        )
    return CheckResult(
        scanner_id=sid,
        check_id=sid,
        name="Workflow path-filter guard",
        status="pass",
        compliance_pct=100,
        message="no path filters on security workflows",
    )


BASELINE_SCANNERS: list[Callable[[Path], CheckResult]] = [
    scan_secret_paths,
    scan_secrets_content,
    scan_waiver_schema,
    scan_workflow_softfail,
    scan_workflow_path_filters,
    # gitleaks is opt-in only (--with-gitleaks); not in default suite (Phase C)
]
