#!/usr/bin/env bash
# Stage: leaked-credential scan.
#
# Two modes, because they answer different questions:
#
#   worktree (default)  "is a secret about to be committed?" Fast, runs on every
#                       push, and the only mode that works before the repository
#                       has any history.
#   history             "is a secret already in the log?" A credential deleted in
#                       a later commit is still fetchable by anyone with a clone,
#                       so a clean HEAD is not remediation. Slower, so it runs on
#                       the scheduled workflow.
#
# There is no severity threshold here. One credential is enough.
#
# Usage: pipeline/secrets.sh [worktree|history]

set -euo pipefail
# shellcheck source=lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

STAGE="secrets"
MODE="${1:-worktree}"
report="${ARTIFACTS_DIR}/secrets.${MODE}.json"

case "${MODE}" in
    worktree)
        args=(detect --source . --no-git)
        ;;
    history)
        [ -d ".git" ] || die "${STAGE}: history mode needs a git repository"
        args=(detect --source .)
        ;;
    *)
        die "unknown mode '${MODE}' (expected: worktree | history)"
        ;;
esac

log "${STAGE}: gitleaks ${VER_GITLEAKS}, mode=${MODE}"

set +e
tool gitleaks "${args[@]}" \
    --config .gitleaks.toml \
    --report-format json \
    --report-path "${report}" \
    --redact \
    --exit-code 1 \
    --no-banner
status=$?
set -e

set +e
python - "${report}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
findings = json.loads(path.read_text(encoding="utf-8")) if path.exists() else []

# The report is redacted: printing a secret into a CI log that more people can
# read than the original file is not an improvement.
for finding in findings:
    location = f"{finding.get('File', '?')}:{finding.get('StartLine', '?')}"
    print(f"  {location}  {finding.get('RuleID', 'unknown-rule')}")

raise SystemExit(1 if findings else 0)
PY
findings_status=$?
set -e

if [ "${status}" -ne 0 ] || { [ "${SECRETS_FAIL_ON_ANY}" = "true" ] && [ "${findings_status}" -ne 0 ]; }; then
    gate_blocked "${STAGE}" "credentials detected - revoke them first, then rewrite history"
    exit 1
fi

ok "${STAGE}: no credentials detected in the ${MODE} scan"
