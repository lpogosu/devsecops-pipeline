#!/usr/bin/env bash
# Stage: static analysis of the source, before anything is built.
#
# Two rulesets run, and the split is deliberate:
#
#   policies/semgrep/    rules written for this repository and checked in, with
#                        no network dependency. They encode decisions specific
#                        to this service: no shell=True, no disabled certificate
#                        verification, no faked build provenance. Registry packs
#                        are useful, but a gate that changes when somebody else
#                        edits a public rule pack is not a gate.
#   p/python, p/secrets  the community packs, pulled only when SEMGREP_REGISTRY=1
#                        so an offline run still produces a verdict instead of a
#                        network error.
#
# Any finding at ERROR severity blocks.

set -euo pipefail
# shellcheck source=lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

STAGE="sast"
report="${ARTIFACTS_DIR}/sast.json"

configs=(--config policies/semgrep)
if [ "${SEMGREP_REGISTRY:-0}" = "1" ]; then
    log "${STAGE}: including the community rule packs (SEMGREP_REGISTRY=1)"
    configs+=(--config p/python --config p/secrets)
fi

log "${STAGE}: scanning app/ and pipeline/ with semgrep ${VER_SEMGREP}"

set +e
tool semgrep scan \
    "${configs[@]}" \
    --severity ERROR \
    --error \
    --metrics off \
    --disable-version-check \
    --quiet \
    --json \
    --output "${report}" \
    app pipeline
status=$?
set -e

[ -f "${report}" ] || die "${STAGE}: semgrep produced no report (exit ${status})"

set +e
python - "${report}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    results = json.load(handle).get("results", [])

for result in results:
    message = result["extra"]["message"].strip().splitlines()[0]
    print(f"  {result['path']}:{result['start']['line']}  {result['check_id']}")
    print(f"      {message}")

print(f"  {len(results)} finding(s) at ERROR severity")
raise SystemExit(1 if results else 0)
PY
findings_status=$?
set -e

if [ "${status}" -ne 0 ] || [ "${findings_status}" -ne 0 ]; then
    gate_blocked "${STAGE}" "static analysis found code that must not ship"
    exit 1
fi

ok "${STAGE}: no ERROR-severity findings (report: ${report})"
