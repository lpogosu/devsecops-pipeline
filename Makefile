SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

PY ?= python3
PIPELINE := pipeline

# Every tool version lives in pipeline/lib.sh. The one exception is pip-tools,
# which is only used by `make lock` and never by a gate.
PIPTOOLS_IMAGE := python:3.13-slim

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[1m%-14s\033[0m %s\n", $$1, $$2}'

# --- the two demos ---------------------------------------------------------

.PHONY: demo-pass
demo-pass: ## Full chain on the clean image: every gate must pass
	@printf '\n=== clean image: the pipeline must go green ===\n\n'
	$(PIPELINE)/sast.sh
	$(PIPELINE)/deps.sh clean
	$(PIPELINE)/secrets.sh worktree
	$(PIPELINE)/policy.sh clean
	$(PIPELINE)/build.sh clean
	$(PIPELINE)/sbom.sh clean
	$(PIPELINE)/scan.sh clean
	$(PIPELINE)/sign.sh sign clean
	$(PIPELINE)/sign.sh verify clean
	@printf '\n\033[32mreleasable\033[0m: scanned, signed, attested and verified\n\n'

.PHONY: demo-fail
demo-fail: ## Same chain on the vulnerable image: the gates must stop it
	@printf '\n=== vulnerable image: the pipeline must go red ===\n\n'
	@$(PIPELINE)/build.sh vulnerable
	@echo
	@if $(PIPELINE)/deps.sh vulnerable; then \
		echo 'the dependency gate ACCEPTED a lockfile with known CVEs'; exit 1; \
	fi
	@echo
	@if $(PIPELINE)/policy.sh vulnerable; then \
		echo 'the policy gate ACCEPTED a Dockerfile that runs as root'; exit 1; \
	fi
	@echo
	@$(PIPELINE)/sbom.sh vulnerable
	@echo
	@if $(PIPELINE)/scan.sh vulnerable; then \
		echo 'the image scan ACCEPTED an image with fixable CRITICAL findings'; exit 1; \
	fi
	@printf '\n\033[32mgates working\033[0m: three independent controls rejected the build\n'
	@printf 'the image was never pushed, never signed and cannot pass admission\n\n'

# --- individual stages -----------------------------------------------------

.PHONY: build
build: ## Build the clean image with OCI provenance labels
	$(PIPELINE)/build.sh clean

.PHONY: sbom
sbom: ## Generate SPDX and CycloneDX SBOMs for the clean image
	$(PIPELINE)/sbom.sh clean

.PHONY: scan
scan: ## Scan the clean image with Trivy and Grype
	$(PIPELINE)/scan.sh clean

.PHONY: sign
sign: ## Sign the image and attest its SBOM
	$(PIPELINE)/sign.sh sign clean

.PHONY: verify
verify: ## Verify the signature and the SBOM attestation
	$(PIPELINE)/sign.sh verify clean

.PHONY: sast
sast: ## Static analysis of the source
	$(PIPELINE)/sast.sh

.PHONY: secrets
secrets: ## Scan the working tree for credentials
	$(PIPELINE)/secrets.sh worktree

# --- checks ----------------------------------------------------------------

.PHONY: policy-test
policy-test: ## Run the Rego and Kyverno policy suites
	$(PIPELINE)/policy.sh clean

.PHONY: lint
lint: ## Lint shell and Python
	$(PIPELINE)/lint.sh
	$(PY) -m ruff check .
	$(PY) -m ruff format --check .
	$(PY) -m mypy

.PHONY: test
test: ## Run the Python test suite
	$(PY) -m pytest

.PHONY: ci
ci: lint test policy-test ## Everything CI runs that needs no image build

# --- housekeeping ----------------------------------------------------------

.PHONY: lock
lock: ## Recompile app/requirements.txt from app/requirements.in
	docker run --rm -v "$(CURDIR):/work" -w /work $(PIPTOOLS_IMAGE) sh -c \
		"pip install --quiet --root-user-action=ignore pip-tools==7.4.1 && \
		 pip-compile --quiet --no-header --strip-extras --generate-hashes --allow-unsafe \
		   --output-file=app/requirements.txt app/requirements.in"

.PHONY: clean
clean: ## Remove build output and stop the demo registry
	rm -rf artifacts .cache .pytest_cache .mypy_cache .ruff_cache
	-docker rm -f dsp-registry >/dev/null 2>&1
	-docker network rm dsp-net >/dev/null 2>&1
	-docker image rm devsecops-demo:clean devsecops-demo:vulnerable >/dev/null 2>&1
