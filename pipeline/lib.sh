#!/usr/bin/env bash
# Shared plumbing for the pipeline stages.
#
# Three rules drive the design of this file:
#
#   1. Every stage must be runnable on its own. A stage that only works as part
#      of a 400-line CI job is a stage nobody debugs when it turns red.
#   2. A scanner is third-party code that reads your source tree. It gets a view
#      of the repository and never gets the Docker socket. Images are handed to
#      scanners as an exported tarball instead, so a compromised scanner cannot
#      start containers on the build host.
#   3. Every path in a stage script is repository-relative. Stages run with the
#      repository as the working directory in both execution modes, which keeps
#      the same argument correct on the host and inside a tool container.
#
# Source it, do not execute it.

set -euo pipefail

PIPELINE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${PIPELINE_DIR}/.." && pwd)"
export REPO_ROOT
cd "${REPO_ROOT}"

ARTIFACTS_DIR="artifacts"
CACHE_DIR=".cache"
mkdir -p "${ARTIFACTS_DIR}" "${CACHE_DIR}"

# Tool versions are pinned for the same reason base images are: an unpinned
# scanner silently changes its rule set, and "the build broke and nobody touched
# it" is the worst possible way to find that out.
VER_TRIVY="${VER_TRIVY:-0.74.0}"
VER_SYFT="${VER_SYFT:-v1.51.1}"
VER_GRYPE="${VER_GRYPE:-v0.118.0}"
VER_GITLEAKS="${VER_GITLEAKS:-v8.30.1}"
VER_CONFTEST="${VER_CONFTEST:-v0.69.0}"
VER_SEMGREP="${VER_SEMGREP:-1.145.0}"
VER_KYVERNO="${VER_KYVERNO:-v1.15.2}"
VER_COSIGN="${VER_COSIGN:-v2.6.1}"
VER_SHELLCHECK="${VER_SHELLCHECK:-v0.11.0}"

# Demo registry. Cosign stores signatures next to the image in a registry, so a
# local demo needs one. Containers reach it by service name over a user-defined
# network; the host reaches the same registry on a published port.
DEMO_NETWORK="${DEMO_NETWORK:-dsp-net}"
DEMO_REGISTRY_NAME="${DEMO_REGISTRY_NAME:-dsp-registry}"
REGISTRY_HOST="${REGISTRY_HOST:-localhost:5000}"
REGISTRY_INTERNAL="${REGISTRY_INTERNAL:-${DEMO_REGISTRY_NAME}:5000}"
IMAGE_REPO="${IMAGE_REPO:-devsecops-demo}"

# shellcheck source=../security/gates.env
. "${REPO_ROOT}/security/gates.env"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_RESET=$'\033[0m'; C_RED=$'\033[31m'; C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'; C_BOLD=$'\033[1m'
else
    C_RESET=''; C_RED=''; C_GREEN=''; C_YELLOW=''; C_BOLD=''
fi

log()  { printf '%s==>%s %s\n' "${C_BOLD}" "${C_RESET}" "$*"; }
ok()   { printf '%s  PASS%s %s\n' "${C_GREEN}" "${C_RESET}" "$*"; }
warn() { printf '%s  WARN%s %s\n' "${C_YELLOW}" "${C_RESET}" "$*" >&2; }
fail() { printf '%s  FAIL%s %s\n' "${C_RED}" "${C_RESET}" "$*" >&2; }

die() { fail "$*"; exit 1; }

# Report a closed gate in a shape a human reads first and a log aggregator can
# still grep for.
gate_blocked() {
    local stage="$1" reason="$2"
    printf '\n%s  BUILD BLOCKED%s  stage=%s  reason=%s\n\n' \
        "${C_RED}${C_BOLD}" "${C_RESET}" "${stage}" "${reason}" >&2
}

# Git Bash rewrites arguments that look like POSIX paths into Windows paths.
# That is right for host paths and wrong for container-side ones (`/work` would
# become `W:\`), so conversion is disabled for docker invocations only. Setting
# it globally would break the Windows Python interpreter, which needs the
# rewritten form. On Linux the variables are inert.
docker() {
    MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' command docker "$@"
}

require_docker() {
    command -v docker >/dev/null 2>&1 || die "docker is required but not on PATH"
    docker info >/dev/null 2>&1 || die "docker daemon is not reachable"
}

# Run a pinned tool. A native binary wins when one is installed (which is what
# CI does, via pinned setup actions); otherwise the pinned container image runs,
# so a laptop with nothing but Docker produces identical results.
tool() {
    local key="$1"; shift
    local native image
    local -a opts=()
    # Most tool images accept any mount point; semgrep refuses to run unless the
    # code volume is where it expects it.
    local mount_at=/work
    # Most images set the tool as their entrypoint. The ones that do not need
    # the binary named explicitly.
    local -a entry=()

    case "${key}" in
        trivy)
            native=trivy; image="aquasec/trivy:${VER_TRIVY}"
            mkdir -p "${CACHE_DIR}/trivy"
            opts=(-v "${REPO_ROOT}/${CACHE_DIR}/trivy:/root/.cache/trivy") ;;
        syft)
            native=syft; image="anchore/syft:${VER_SYFT}" ;;
        grype)
            native=grype; image="anchore/grype:${VER_GRYPE}"
            mkdir -p "${CACHE_DIR}/grype"
            opts=(-v "${REPO_ROOT}/${CACHE_DIR}/grype:/root/.cache/grype"
                  -e GRYPE_DB_CACHE_DIR=/root/.cache/grype) ;;
        gitleaks)
            native=gitleaks; image="zricethezav/gitleaks:${VER_GITLEAKS}" ;;
        conftest)
            native=conftest; image="openpolicyagent/conftest:${VER_CONFTEST}" ;;
        semgrep)
            native=semgrep; image="semgrep/semgrep:${VER_SEMGREP}"
            mount_at=/src; entry=(semgrep) ;;
        kyverno)
            native=kyverno; image="ghcr.io/kyverno/kyverno-cli:${VER_KYVERNO}" ;;
        cosign)
            native=cosign; image="ghcr.io/sigstore/cosign/cosign:${VER_COSIGN}"
            opts=(--network "${DEMO_NETWORK}" -e COSIGN_PASSWORD) ;;
        shellcheck)
            native=shellcheck; image="koalaman/shellcheck:${VER_SHELLCHECK}" ;;
        *)
            die "unknown tool '${key}'" ;;
    esac

    if [ "${FORCE_CONTAINER_TOOLS:-0}" != "1" ] && command -v "${native}" >/dev/null 2>&1; then
        "${native}" "$@"
        return
    fi

    require_docker
    docker run --rm \
        -v "${REPO_ROOT}:${mount_at}" \
        -w "${mount_at}" \
        "${opts[@]}" \
        "${image}" "${entry[@]}" "$@"
}

# Dockerfile and tag for a build variant. `vulnerable` exists purely so the
# gates can be shown rejecting something.
variant_dockerfile() {
    case "${1}" in
        clean)      printf 'app/Dockerfile\n' ;;
        vulnerable) printf 'app/Dockerfile.vulnerable\n' ;;
        *)          die "unknown variant '${1}' (expected: clean | vulnerable)" ;;
    esac
}

variant_tag() {
    case "${1}" in
        clean|vulnerable) printf '%s:%s\n' "${IMAGE_REPO}" "${1}" ;;
        *)                die "unknown variant '${1}' (expected: clean | vulnerable)" ;;
    esac
}

image_archive() {
    printf '%s/%s.tar\n' "${ARTIFACTS_DIR}" "${1}"
}

# Export the image once per stage chain, so every scanner afterwards reads a
# file instead of talking to the daemon.
ensure_image_archive() {
    local variant="$1" archive tag
    archive="$(image_archive "${variant}")"
    tag="$(variant_tag "${variant}")"

    if [ ! -f "${archive}" ]; then
        require_docker
        docker image inspect "${tag}" >/dev/null 2>&1 \
            || die "image ${tag} not found - run 'pipeline/build.sh ${variant}' first"
        log "exporting ${tag} to ${archive}"
        docker save "${tag}" -o "${archive}"
    fi
    printf '%s\n' "${archive}"
}
