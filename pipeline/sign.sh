#!/usr/bin/env bash
# Stage: sign the image, attest its SBOM, and prove both verify.
#
# Signing modes
# -------------
# keyless (CI)  - cosign gets a short-lived certificate from Fulcio bound to the
#                 workflow's OIDC identity and records the signature in the Rekor
#                 transparency log. Nothing long-lived exists to steal, and the
#                 certificate states *which workflow of which repository* built
#                 the artifact, which a bare key can never say. Selected
#                 automatically when GitHub's OIDC token is present.
# key (local)   - an ephemeral key pair under artifacts/keys/, with the
#                 transparency log switched off because a throwaway local
#                 registry has nothing worth publishing. This mode exists so the
#                 chain is reproducible offline. It is not how a release is signed.
#
# Signatures live next to the image in a registry, so the local demo runs one.
# Containers reach it by service name on a user-defined network and the host
# reaches it on a published port; everything is addressed by digest, so both
# views point at the same bytes.
#
# Usage: pipeline/sign.sh sign|verify [clean|vulnerable]

set -euo pipefail
# shellcheck source=lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

STAGE="sign"
ACTION="${1:-sign}"
VARIANT="${2:-clean}"
KEY_DIR="${ARTIFACTS_DIR}/keys"
DIGEST_FILE="${ARTIFACTS_DIR}/digest.${VARIANT}"
OIDC_ISSUER="https://token.actions.githubusercontent.com"
OIDC_IDENTITY_REGEXP="${OIDC_IDENTITY_REGEXP:-^https://github.com/lpogosu/devsecops-pipeline/}"

keyless_available() {
    [ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] && [ -n "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]
}

# Point REGISTRY_HOST at a real registry (ghcr.io/<owner>, say) and the demo
# scaffolding disappears: no local registry, no plain-HTTP flags.
uses_demo_registry() {
    case "${REGISTRY_HOST}" in
        localhost:*|127.0.0.1:*) return 0 ;;
        *) return 1 ;;
    esac
}

start_registry() {
    require_docker
    if ! uses_demo_registry; then
        return 0
    fi
    docker network inspect "${DEMO_NETWORK}" >/dev/null 2>&1 \
        || docker network create "${DEMO_NETWORK}" >/dev/null

    if [ "$(docker inspect -f '{{.State.Running}}' "${DEMO_REGISTRY_NAME}" 2>/dev/null)" != "true" ]; then
        docker rm -f "${DEMO_REGISTRY_NAME}" >/dev/null 2>&1 || true
        log "starting throwaway registry ${DEMO_REGISTRY_NAME} on ${REGISTRY_HOST}"
        docker run --detach --name "${DEMO_REGISTRY_NAME}" \
            --network "${DEMO_NETWORK}" \
            --publish "${REGISTRY_HOST##*:}:5000" \
            registry:2 >/dev/null
    fi

    # Poll instead of guessing a sleep duration.
    local attempt
    for attempt in $(seq 1 20); do
        if curl --silent --fail --max-time 2 "http://${REGISTRY_HOST}/v2/" >/dev/null 2>&1; then
            return 0
        fi
        if [ "${attempt}" -eq 20 ]; then
            die "registry ${REGISTRY_HOST} did not become ready"
        fi
    done
}

# Push the variant and record the manifest digest the registry accepted. That
# digest, not the tag, is the artifact identity everything downstream refers to:
# it is what gets signed, what the attestation is attached to, and what the
# admission policy pins.
#
# It is read back from RepoDigests after the push rather than recomputed
# locally, because that is the registry's own answer. RepoDigests can hold
# entries for several repositories at once, so the one for the repository just
# pushed to is selected explicitly instead of taking the first.
push_variant() {
    local tag remote digest
    tag="$(variant_tag "${VARIANT}")"
    remote="${REGISTRY_HOST}/${IMAGE_REPO}:${VARIANT}"

    docker image inspect "${tag}" >/dev/null 2>&1 \
        || die "image ${tag} not found - run 'pipeline/build.sh ${VARIANT}' first"

    log "pushing ${tag} to ${remote}"
    docker tag "${tag}" "${remote}"
    docker push --quiet "${remote}" >/dev/null

    digest="$(docker image inspect "${remote}" --format '{{range .RepoDigests}}{{println .}}{{end}}' \
        | grep "^${REGISTRY_HOST}/${IMAGE_REPO}@" \
        | head -n 1 | cut -d'@' -f2)"
    [ -n "${digest}" ] || die "could not determine the manifest digest of ${remote} after pushing"

    printf '%s\n' "${digest}" > "${DIGEST_FILE}"
}

ensure_key() {
    if [ -f "${KEY_DIR}/cosign.key" ] && [ -f "${KEY_DIR}/cosign.pub" ]; then
        return
    fi
    mkdir -p "${KEY_DIR}"
    log "generating an ephemeral demo key pair in ${KEY_DIR}"
    docker run --rm -v "${REPO_ROOT}/${KEY_DIR}:/keys" -w /keys \
        -e COSIGN_PASSWORD \
        "ghcr.io/sigstore/cosign/cosign:${VER_COSIGN}" generate-key-pair >/dev/null
}

# Talking plain HTTP and skipping TLS verification is acceptable for a registry
# that lives for the duration of a demo and unacceptable for any other, so the
# flags are derived from which registry is in use rather than hard-coded.
local_registry_flags=()
if uses_demo_registry; then
    local_registry_flags=(--allow-http-registry --allow-insecure-registry)
fi

# How cosign addresses the image. Containers on the demo network resolve the
# throwaway registry by service name; a real registry answers to the same name
# everywhere.
signing_ref() {
    local digest registry
    digest="$(cat "${DIGEST_FILE}")"
    if uses_demo_registry; then
        registry="${REGISTRY_INTERNAL}"
    else
        registry="${REGISTRY_HOST}"
    fi
    printf '%s/%s@%s\n' "${registry}" "${IMAGE_REPO}" "${digest}"
}

do_sign() {
    local ref digest sbom
    sbom="${ARTIFACTS_DIR}/sbom.${VARIANT}.spdx.json"
    [ -f "${sbom}" ] \
        || die "SBOM ${sbom} missing - run 'pipeline/sbom.sh ${VARIANT}' first"

    start_registry
    push_variant
    digest="$(cat "${DIGEST_FILE}")"
    ref="$(signing_ref)"

    if keyless_available; then
        log "${STAGE}: keyless signing ${ref} (Fulcio certificate, Rekor entry)"
        tool cosign sign --yes "${ref}"
        log "${STAGE}: attesting the SPDX SBOM"
        tool cosign attest --yes --type spdxjson --predicate "${sbom}" "${ref}"
    else
        export COSIGN_PASSWORD="${COSIGN_PASSWORD:-demo}"
        ensure_key
        log "${STAGE}: no OIDC token available, signing ${ref} with the local demo key"
        tool cosign sign --yes \
            --key "${KEY_DIR}/cosign.key" \
            "${local_registry_flags[@]}" --tlog-upload=false \
            "${ref}"
        log "${STAGE}: attesting the SPDX SBOM"
        tool cosign attest --yes \
            --key "${KEY_DIR}/cosign.key" \
            --type spdxjson --predicate "${sbom}" \
            "${local_registry_flags[@]}" --tlog-upload=false \
            "${ref}"
    fi

    ok "${STAGE}: signed and attested ${IMAGE_REPO}@${digest}"
}

do_verify() {
    local ref digest
    [ -f "${DIGEST_FILE}" ] \
        || die "no digest recorded - run 'pipeline/sign.sh sign ${VARIANT}' first"
    digest="$(cat "${DIGEST_FILE}")"
    ref="$(signing_ref)"
    start_registry

    if keyless_available; then
        log "${STAGE}: verifying ${ref} against the workflow identity"
        tool cosign verify \
            --certificate-identity-regexp "${OIDC_IDENTITY_REGEXP}" \
            --certificate-oidc-issuer "${OIDC_ISSUER}" \
            "${ref}" >/dev/null
        log "${STAGE}: verifying the SBOM attestation"
        tool cosign verify-attestation --type spdxjson \
            --certificate-identity-regexp "${OIDC_IDENTITY_REGEXP}" \
            --certificate-oidc-issuer "${OIDC_ISSUER}" \
            "${ref}" >/dev/null
    else
        export COSIGN_PASSWORD="${COSIGN_PASSWORD:-demo}"
        [ -f "${KEY_DIR}/cosign.pub" ] \
            || die "public key missing - run 'pipeline/sign.sh sign ${VARIANT}' first"
        log "${STAGE}: verifying ${ref} against ${KEY_DIR}/cosign.pub"
        tool cosign verify \
            --key "${KEY_DIR}/cosign.pub" \
            "${local_registry_flags[@]}" --insecure-ignore-tlog=true \
            "${ref}" >/dev/null
        log "${STAGE}: verifying the SBOM attestation"
        tool cosign verify-attestation --type spdxjson \
            --key "${KEY_DIR}/cosign.pub" \
            "${local_registry_flags[@]}" --insecure-ignore-tlog=true \
            "${ref}" >/dev/null
    fi

    ok "${STAGE}: signature and SBOM attestation verify for ${IMAGE_REPO}@${digest}"
}

case "${ACTION}" in
    sign)   do_sign ;;
    verify) do_verify ;;
    *)      die "unknown action '${ACTION}' (expected: sign | verify)" ;;
esac
