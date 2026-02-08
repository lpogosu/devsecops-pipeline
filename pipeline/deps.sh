#!/usr/bin/env bash
# Stage: dependency vulnerability scan of the lockfile, before a build exists.
#
# This runs against the lockfile rather than the built image on purpose. It is
# the fastest signal in the chain - seconds, no build - and it names the file a
# developer has to edit. The image scan later covers the OS layer and everything
# the lockfile does not describe; the two are not interchangeable.
#
# Usage: pipeline/deps.sh [clean|vulnerable]

set -euo pipefail
# shellcheck source=lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

STAGE="deps"
VARIANT="${1:-clean}"

case "${VARIANT}" in
    clean)      lockfile="app/requirements.txt" ;;
    vulnerable) lockfile="app/requirements-vulnerable.txt" ;;
    *)          die "unknown variant '${VARIANT}' (expected: clean | vulnerable)" ;;
esac

# Trivy recognises a pip lockfile by filename, so the variant is staged under
# the canonical name instead of being renamed in the repository.
staging="${ARTIFACTS_DIR}/deps/${VARIANT}"
rm -rf "${staging}"
mkdir -p "${staging}"
cp "${lockfile}" "${staging}/requirements.txt"

report="${ARTIFACTS_DIR}/deps.${VARIANT}.json"

log "${STAGE}: scanning ${lockfile} at ${FAIL_ON_SEVERITY} with trivy ${VER_TRIVY}"

tool trivy fs \
    --scanners vuln \
    --severity "${FAIL_ON_SEVERITY}" \
    --quiet \
    --format json \
    --output "${report}" \
    "${staging}"

set +e
python - "${report}" "${VARIANT}" <<'PY'
import json
import sys

report_path, variant = sys.argv[1], sys.argv[2]
with open(report_path, encoding="utf-8") as handle:
    document = json.load(handle)

findings = [
    vulnerability
    for result in document.get("Results", [])
    for vulnerability in (result.get("Vulnerabilities") or [])
]

if not findings:
    print(f"  no {variant} dependency findings at the gating severity")
    raise SystemExit(0)

# Group by package: five urllib3 advisories are one upgrade, not five decisions.
by_package: dict[str, list[dict[str, str]]] = {}
for vulnerability in findings:
    by_package.setdefault(vulnerability["PkgName"], []).append(vulnerability)

for package, items in sorted(by_package.items()):
    installed = items[0].get("InstalledVersion", "?")
    fixed = sorted({item["FixedVersion"] for item in items if item.get("FixedVersion")})
    print(f"  {package} {installed}")
    for item in items:
        print(f"      {item['Severity']:<8} {item['VulnerabilityID']}")
    if fixed:
        print(f"      fix: upgrade to {', '.join(fixed)}")

print(f"\n  {len(findings)} finding(s) across {len(by_package)} package(s)")
raise SystemExit(1)
PY
status=$?
set -e

if [ "${status}" -ne 0 ]; then
    gate_blocked "${STAGE}" "vulnerable dependencies pinned in ${lockfile}"
    exit 1
fi

ok "${STAGE}: ${lockfile} is clean at ${FAIL_ON_SEVERITY}"
