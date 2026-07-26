# Consumer CI contract — `house_scan`

**Issue:** [house-security-library#2](https://github.com/BrandonSRutledge/house-security-library/issues/2)  
**Contract version:** `1.0.0`  
**Companion:** `docs/CONSUMER_WIRING.md` · ops `docs/HOUSE_SCANNER_PLATFORM.md`

This document is the **normative** contract between `house-security-library` and consumer repos (ops, house-security-*, fixtures, future game).

---

## 1. Goals

1. Every consumer runs the **same** baseline suite (secret paths, secrets content, waiver schema, workflow soft-fail).
2. Consumers **pin** the suite version so CI does not silently drift.
3. Private cross-repo checkout is optional; **vendored runtime** is a first-class pin strategy.

---

## 2. Inputs

| Input | Required | Description |
|-------|----------|-------------|
| Target repo root | yes | Directory to scan (consumer checkout) |
| `HOUSE_SECURITY_LIBRARY` | yes* | Path to library root **or** vendored bundle root with `scripts/house_scan.sh` |
| Python | 3.11+ | 3.12 in Actions examples; **stdlib only** (no PyYAML/jsonschema required — Phase D) |
| `git` | yes | Path/content scanners use `git ls-files` |
| Network (install) | soft | Default pins have **no** binary tools (Phase C). Optional `--with-gitleaks` may need a PATH binary or re-added pin. |

\*Local may resolve sibling `~/game/house-security-library` via `resolve_library` patterns in consumer `local_ci`.

### Secrets (Actions)

| Secret | When |
|--------|------|
| `HOUSE_SCAN_TOKEN` | Live checkout of private library in Actions (contents:read on library) |
| none | Vendored `third_party/house_scan_runtime` path (ops today) |

Never put tokens in git or issue bodies.

---

## 3. Outputs

| Artifact | Path (default) | Notes |
|----------|----------------|-------|
| Suite report JSON | `reports/house-scan-latest.json` | Machine-readable |
| Compliance table | `security/COMPLIANCE.md` | When markers / suite write |
| README badges | `HOUSE_BADGE` / `HOUSE_COMPLIANCE` markers | Regenerated if present |
| Exit code | process | See §4 |

Do **not** commit secrets or real credential samples in reports.

---

## 4. Exit codes

| Code | Meaning |
|------|---------|
| `0` | Suite pass (all scanners pass or only waived fails per policy) |
| `1` | Suite fail (non-waived finding) or tooling error |
| `2` | Usage / missing library path |

Consumers **must not** set `continue-on-error: true` on house_scan jobs (dogfood / anti-bypass).

---

## 5. Pin strategies (required: pick one)

### A. Vendored runtime (recommended for private consumers)

```text
consumer/third_party/house_scan_runtime/
  BUNDLE_VERSION      # short git sha of library at export
  CONTRACT_VERSION    # this contract (e.g. 1.0.0)
  tools/pins.yaml     # tool versions
  scripts/house_scan.sh
  src/house_scan/...
```

**Refresh:**

```bash
cd ~/game/house-security-library
./scripts/export_runtime_bundle.sh
rsync -a --delete bundle/house_scan_runtime/ \
  ~/game/<consumer>/third_party/house_scan_runtime/
# commit consumer with BUNDLE_VERSION visible in PR
```

**Pin proof:** `BUNDLE_VERSION` file content = library commit short SHA at export time.

### B. Reusable workflow @ commit SHA

```yaml
jobs:
  house-scan:
    uses: BrandonSRutledge/house-security-library/.github/workflows/reusable-house-scan.yml@<full-or-short-sha>
    secrets:
      HOUSE_SCAN_TOKEN: ${{ secrets.HOUSE_SCAN_TOKEN }}
```

**Do not** pin only `@main` for production gates long-term — SHA (or annotated tag) is the pin.

### C. Live sibling (local only)

`HOUSE_SECURITY_LIBRARY=~/game/house-security-library` — not a CI pin; fine for developer machines.

---

## 6. Tool pins

Source of truth: `tools/pins.yaml` in the library (copied into the bundle).

| Tool | Pin field | Default suite |
|------|-----------|---------------|
| *(none)* | `tools: {}` | First-party scanners only (Phase C) |
| gitleaks (optional) | `tools.gitleaks.version` | Only if re-added for `--with-gitleaks` dogfood |

Default install is a no-op. If a binary pin is re-added, installers **must** use pinned versions (no `latest`). Verify with:

```bash
./scripts/verify_consumer_pin.sh /path/to/consumer-or-bundle
# All known consumers vs library export (library#12):
./scripts/check_consumer_pins.sh
# Refresh one consumer:
#   ./scripts/export_runtime_bundle.sh
#   rsync -a --delete bundle/house_scan_runtime/ ~/game/<consumer>/third_party/house_scan_runtime/
```

### Default suite scanners (Phase C)

| Scanner id | Kind |
|------------|------|
| `baseline.secret_paths` | first-party |
| `baseline.secrets_content` | first-party |
| `baseline.waiver_schema` | first-party |
| `baseline.workflow_softfail` | first-party |

`baseline.gitleaks` is **not** in the default suite (opt-in: `house_scan scan --with-gitleaks`).

---

## 7. Minimum consumer CI job shape

```yaml
house-scan:
  runs-on: ubuntu-latest
  timeout-minutes: 15
  steps:
    - uses: actions/checkout@v4
      with: { fetch-depth: 0 }
    - uses: actions/setup-python@v5
      with: { python-version: "3.12" }
    - name: house_scan (vendored pin)
      run: |
        set -euo pipefail
        export HOUSE_SECURITY_LIBRARY="${GITHUB_WORKSPACE}/third_party/house_scan_runtime"
        test -f "${HOUSE_SECURITY_LIBRARY}/BUNDLE_VERSION"
        test -x "${HOUSE_SECURITY_LIBRARY}/scripts/house_scan.sh"
        bash "${HOUSE_SECURITY_LIBRARY}/scripts/consumer_local_ci_fragment.sh" "${GITHUB_WORKSPACE}"
```

Or call the reusable workflow (§5B).

---

## 8. Compatibility

| Contract | Library |
|----------|---------|
| `1.0.0` | Phase 1 suite: baseline scanners, per-scanner waivers, install pins |

Breaking changes bump `CONTRACT_VERSION` and require consumer bundle refresh + issue note on house tracker.

---

## 9. Related

- Wiring how-to: `docs/CONSUMER_WIRING.md`
- Platform design: ops-coordination `docs/HOUSE_SCANNER_PLATFORM.md`
- Export: `scripts/export_runtime_bundle.sh`
- Verify: `scripts/verify_consumer_pin.sh`
