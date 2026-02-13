#!/usr/bin/env bash
# Stage: SBOM generation in two formats.
#
# Both are produced because they have different audiences, not because more
# files look thorough:
#
#   SPDX 2.3   the licence and compliance answer. Legal review, export paperwork
#              and most enterprise intake portals speak SPDX.
#   CycloneDX  the security answer. VEX statements and most vulnerability
#              inventories consume CycloneDX.
#
# The SBOM is built from the exported image, not from the source tree, so it
# describes what actually shipped: base-image packages included, build-stage
# packages excluded.
#
# Usage: pipeline/sbom.sh [clean|vulnerable]

set -euo pipefail
# shellcheck source=lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

STAGE="sbom"
VARIANT="${1:-clean}"

archive="$(ensure_image_archive "${VARIANT}")"
spdx="${ARTIFACTS_DIR}/sbom.${VARIANT}.spdx.json"
cdx="${ARTIFACTS_DIR}/sbom.${VARIANT}.cdx.json"

log "${STAGE}: cataloguing ${archive} with syft ${VER_SYFT}"

tool syft scan "docker-archive:${archive}" \
    --quiet \
    -o "spdx-json=${spdx}" \
    -o "cyclonedx-json=${cdx}"

python - "${spdx}" "${cdx}" <<'PY'
import collections
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    spdx = json.load(handle)
with open(sys.argv[2], encoding="utf-8") as handle:
    cdx = json.load(handle)

packages = spdx.get("packages", [])
components = cdx.get("components", [])
kinds = collections.Counter(component.get("type") for component in components)

print(f"  SPDX {spdx.get('spdxVersion', '?')}: {len(packages)} packages")
print(
    f"  CycloneDX {cdx.get('specVersion', '?')}: "
    + ", ".join(f"{count} {kind}" for kind, count in sorted(kinds.items()))
)

# A licence field that says NOASSERTION is not a licence answer, and knowing how
# many of them there are is the difference between an SBOM and a usable SBOM.
unknown = sum(
    1
    for package in packages
    if package.get("licenseConcluded", "NOASSERTION") == "NOASSERTION"
    and package.get("licenseDeclared", "NOASSERTION") == "NOASSERTION"
)
print(f"  packages with no declared licence: {unknown}/{len(packages)}")
PY

ok "${STAGE}: wrote ${spdx} and ${cdx}"
