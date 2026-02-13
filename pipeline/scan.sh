#!/usr/bin/env bash
# Stage: image vulnerability scan. This is the gate that stops a release.
#
# Two scanners run over the same exported tarball. The comparison at the end is
# the interesting part: it reports how many findings each tool saw that the
# other did not, which is the only honest way to justify running both.
#
# Exceptions come from security/allowlist.yaml and are compiled here into each
# tool's own ignore syntax, so the two cannot drift apart.
#
# Usage: pipeline/scan.sh [clean|vulnerable]

set -euo pipefail
# shellcheck source=lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

STAGE="scan"
VARIANT="${1:-clean}"

archive="$(ensure_image_archive "${VARIANT}")"
trivy_report="${ARTIFACTS_DIR}/scan.${VARIANT}.trivy.json"
grype_report="${ARTIFACTS_DIR}/scan.${VARIANT}.grype.json"
trivy_ignore="${ARTIFACTS_DIR}/trivyignore.yaml"
grype_ignore="${ARTIFACTS_DIR}/grype-ignore.yaml"

log "${STAGE}: compiling accepted findings from security/allowlist.yaml"
python pipeline/allowlist.py validate
python pipeline/allowlist.py render --format trivy --output "${trivy_ignore}"
python pipeline/allowlist.py render --format grype --output "${grype_ignore}"

log "${STAGE}: trivy ${VER_TRIVY} on ${archive}"
trivy_args=(
    image --input "${archive}"
    --scanners vuln
    --severity "${FAIL_ON_SEVERITY}"
    --ignorefile "${trivy_ignore}"
    --quiet --format json --output "${trivy_report}"
    # Exit code stays 0: the verdict is computed once, from both reports, by
    # scan_report.py. Two tools each deciding to fail the build produces two
    # different answers to the same question.
    --exit-code 0
)
if [ "${IGNORE_UNFIXED}" = "true" ]; then trivy_args+=(--ignore-unfixed); fi
tool trivy "${trivy_args[@]}"

log "${STAGE}: grype ${VER_GRYPE} on ${archive}"
grype_args=(
    "docker-archive:${archive}"
    --config "${grype_ignore}"
    --output "json=${grype_report}"
    --quiet
)
if [ "${IGNORE_UNFIXED}" = "true" ]; then grype_args+=(--only-fixed); fi
tool grype "${grype_args[@]}"

# FAIL_ON_SEVERITY is a list ("HIGH,CRITICAL"); scan_report.py takes a floor.
threshold="${FAIL_ON_SEVERITY%%,*}"

report_args=(
    --trivy "${trivy_report}"
    --grype "${grype_report}"
    --threshold "${threshold}"
)
if [ "${IGNORE_UNFIXED}" = "true" ]; then report_args+=(--ignore-unfixed); fi

set +e
python pipeline/scan_report.py "${report_args[@]}"
status=$?
set -e

if [ "${status}" -ne 0 ]; then
    gate_blocked "${STAGE}" "the image has fixable vulnerabilities at or above ${threshold}"
    printf '  Remediate by rebasing on a patched image or upgrading the package.\n' >&2
    printf '  If it is genuinely not exploitable here, add a dated entry to\n' >&2
    printf '  security/allowlist.yaml with an owner and a reason.\n\n' >&2
    exit 1
fi

ok "${STAGE}: no blocking findings at ${threshold} for the ${VARIANT} image"
