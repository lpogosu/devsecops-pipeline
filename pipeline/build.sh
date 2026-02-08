#!/usr/bin/env bash
# Stage: build the image with provenance stamped into it.
#
# "Reproducible-ish" is the honest description. A byte-identical rebuild would
# need SOURCE_DATE_EPOCH support end to end and a base image that never moves.
# What this stage does guarantee is the part that matters during an incident:
#
#   * the base image is referenced by digest, so a moved tag cannot swap the
#     bytes underneath;
#   * dependencies come from a hash-verified lockfile;
#   * source, revision and build time are recorded as OCI annotations, so
#     `docker inspect` on a running container answers "which commit is this?"
#     without trusting a wiki page.
#
# Usage: pipeline/build.sh [clean|vulnerable]

set -euo pipefail
# shellcheck source=lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

STAGE="build"
VARIANT="${1:-clean}"
require_docker

dockerfile="$(variant_dockerfile "${VARIANT}")"
tag="$(variant_tag "${VARIANT}")"

# Prefer what CI already knows, fall back to git, fall back to explicit
# emptiness. An empty value is a truthful "this image carries no provenance",
# which the policy layer can reject. A fabricated value is not.
source_url="${OCI_SOURCE:-${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-lpogosu/devsecops-pipeline}}"
if [ -n "${GITHUB_SHA:-}" ]; then
    revision="${GITHUB_SHA}"
elif git rev-parse HEAD >/dev/null 2>&1; then
    revision="$(git rev-parse HEAD)"
else
    revision=""
fi
created="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

log "${STAGE}: building ${tag} from ${dockerfile}"
printf '  source   %s\n  revision %s\n  created  %s\n' \
    "${source_url}" "${revision:-<none>}" "${created}"

# Which builder runs is decided here rather than left to whatever `docker build`
# happens to dispatch to, because the two builders do not produce the same
# thing. BuildKit attaches attestation manifests by default, which turns the
# result into a manifest list that `docker save` consumers cannot all read - and
# the provenance that matters here comes from the OCI labels and the cosign
# attestation, not from the builder's own. So when buildx is present it is used
# explicitly with attestations off; when it is not, the legacy builder has
# nothing to switch off and the flag would be an error.
builder=(build)
if docker buildx version >/dev/null 2>&1; then
    builder=(buildx build --load --provenance=false)
else
    warn "${STAGE}: buildx is unavailable, falling back to the legacy builder"
fi

docker "${builder[@]}" \
    --file "${dockerfile}" \
    --tag "${tag}" \
    --build-arg "OCI_SOURCE=${source_url}" \
    --build-arg "OCI_REVISION=${revision}" \
    --build-arg "OCI_CREATED=${created}" \
    .

# Every later stage reads the tarball rather than the daemon, so refresh it.
archive="$(image_archive "${VARIANT}")"
rm -f "${archive}"
docker save "${tag}" -o "${archive}"

image_id="$(docker image inspect "${tag}" --format '{{.Id}}')"
docker image inspect "${tag}" --format '{{json .Config.Labels}}' \
    > "${ARTIFACTS_DIR}/labels.${VARIANT}.json"

python - "${ARTIFACTS_DIR}/labels.${VARIANT}.json" <<'PY'
import json
import sys

prefix = "org.opencontainers.image."
with open(sys.argv[1], encoding="utf-8") as handle:
    labels = json.load(handle) or {}

for key in sorted(key for key in labels if key.startswith(prefix)):
    print(f"  {key[len(prefix):]:<14} {labels[key] or '<empty>'}")
PY

ok "${STAGE}: ${tag} built (${image_id}), exported to ${archive}"
