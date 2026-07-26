#!/usr/bin/env bash
# Local CI for agent-skills-public — PUBLIC guards + house_scan contract.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PASS=0
FAIL=0
ok() { echo "OK: $*"; PASS=$((PASS + 1)); }
bad() { echo "FAIL: $*" >&2; FAIL=$((FAIL + 1)); }

echo "=== agent-skills-public local_ci ==="

# PUBLIC classification only
if grep -R --include='CLASSIFICATION.y*ml' -nE 'classification:[[:space:]]*(INTERNAL|SENSITIVE)' skills 2>/dev/null; then
  bad "INTERNAL/SENSITIVE classifications forbidden in public repo"
else
  ok "no INTERNAL/SENSITIVE classifications"
fi

# Every skill has CLASSIFICATION.yaml + non-empty SKILL.md
missing=0
shopt -s nullglob
for d in skills/public/*/; do
  [ -d "$d" ] || continue
  if [ ! -f "${d}CLASSIFICATION.yaml" ] && [ ! -f "${d}CLASSIFICATION.yml" ]; then
    echo "Missing CLASSIFICATION.yaml in $d" >&2
    missing=1
  fi
  if [ ! -f "${d}SKILL.md" ]; then
    echo "Missing SKILL.md in $d" >&2
    missing=1
  elif [ ! -s "${d}SKILL.md" ]; then
    echo "Empty SKILL.md in $d" >&2
    missing=1
  fi
  clf=$(ls "${d}"CLASSIFICATION.y*ml 2>/dev/null | head -1 || true)
  if [ -n "$clf" ] && ! grep -qE 'classification:[[:space:]]*PUBLIC' "$clf"; then
    echo "Expected classification: PUBLIC in $clf" >&2
    missing=1
  fi
done
if [ "$missing" -eq 0 ]; then
  ok "skill classification + SKILL.md"
else
  bad "skill classification + SKILL.md"
fi

# Path denylist
if git ls-files | grep -E '(^|/)\.env$|\.pem$|id_rsa|credentials\.json|secrets\.ya?ml$' ; then
  bad "secret-like paths tracked"
else
  ok "path denylist"
fi

if git ls-files | grep -E '(^|/)skills/sensitive(/|$)|(^|/)private(/|$)' ; then
  bad "sensitive path names in public repo"
else
  ok "no sensitive path names"
fi

# house_scan (CONSUMER_CI_CONTRACT v1 — vendored pin or sibling library)
resolve_house_scan_lib() {
  if [ -n "${HOUSE_SECURITY_LIBRARY:-}" ] && [ -x "${HOUSE_SECURITY_LIBRARY}/scripts/house_scan.sh" ]; then
    echo "${HOUSE_SECURITY_LIBRARY}"
    return 0
  fi
  for c in \
    "${ROOT}/../house-security-library" \
    "${HOME}/game/house-security-library" \
    "${ROOT}/third_party/house_scan_runtime"
  do
    if [ -x "${c}/scripts/house_scan.sh" ]; then
      (cd "$c" && pwd)
      return 0
    fi
  done
  return 1
}
if LIB="$(resolve_house_scan_lib)"; then
  if bash "${LIB}/scripts/consumer_local_ci_fragment.sh" "${ROOT}"; then
    ok house_scan
  else
    bad house_scan
  fi
else
  bad "house_scan runtime not found (third_party/house_scan_runtime)"
fi

echo "pass=$PASS fail=$FAIL"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
echo "RESULT: PASS"
exit 0
