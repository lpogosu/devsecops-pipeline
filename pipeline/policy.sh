#!/usr/bin/env bash
# Stage: policy as code.
#
# Three things happen here, in this order:
#
#   1. `conftest verify` runs the Rego unit tests. A policy whose own tests are
#      broken must not be allowed to judge anything.
#   2. The Dockerfile and the Kubernetes manifests are evaluated against those
#      policies.
#   3. A known-bad manifest is evaluated and the run fails if it is *accepted*.
#      Without that check, a policy that silently stopped matching would look
#      exactly like a policy that is passing.
#
# The Kyverno ClusterPolicies are validated separately: the same controls have
# to hold at admission time, because CI only sees what goes through CI.
#
# Usage: pipeline/policy.sh [clean|vulnerable]

set -euo pipefail
# shellcheck source=lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

STAGE="policy"
VARIANT="${1:-clean}"
dockerfile="$(variant_dockerfile "${VARIANT}")"
failures=0

log "${STAGE}: running policy unit tests (conftest ${VER_CONFTEST})"
tool conftest verify --policy policies/dockerfile
tool conftest verify --policy policies/kubernetes

log "${STAGE}: evaluating ${dockerfile}"
if ! tool conftest test --policy policies/dockerfile --parser dockerfile "${dockerfile}"; then
    failures=$((failures + 1))
fi

log "${STAGE}: evaluating deploy/k8s"
if ! tool conftest test --policy policies/kubernetes deploy/k8s; then
    failures=$((failures + 1))
fi

# Meta-check: the policy must still reject the fixture it was written against.
log "${STAGE}: confirming the policy still rejects the known-bad manifest"
if tool conftest test --policy policies/kubernetes \
        policies/kubernetes/testdata/insecure-deployment.yaml >/dev/null 2>&1; then
    fail "${STAGE}: the known-bad manifest was ACCEPTED - the policy has stopped working"
    failures=$((failures + 1))
else
    ok "${STAGE}: known-bad manifest correctly rejected"
fi

log "${STAGE}: validating Kyverno admission policies (kyverno ${VER_KYVERNO})"
if ! tool kyverno test policies/kyverno; then
    failures=$((failures + 1))
fi

if [ "${failures}" -gt 0 ]; then
    gate_blocked "${STAGE}" "${failures} policy check(s) failed"
    exit 1
fi

ok "${STAGE}: Dockerfile, manifests and admission policies satisfy policy"
