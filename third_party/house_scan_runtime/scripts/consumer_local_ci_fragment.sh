#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="${1:-}"
if [ -z "$REPO_ROOT" ] || [ ! -d "$REPO_ROOT" ]; then
  echo "Usage: consumer_local_ci_fragment.sh <repo_root>" >&2
  exit 2
fi
LIB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONPATH="${LIB_ROOT}/src${PYTHONPATH:+:$PYTHONPATH}"
export PATH="${HOME}/.local/share/house-security-tools/bin:${PATH}"
echo "=== house_scan (bundle=${LIB_ROOT}) ==="
bash "${LIB_ROOT}/scripts/house_scan.sh" install >/dev/null || true
bash "${LIB_ROOT}/scripts/house_scan.sh" scan "${REPO_ROOT}"
