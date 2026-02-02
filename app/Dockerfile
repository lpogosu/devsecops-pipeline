# Clean variant: the image the pipeline is expected to pass end to end.
#
# Every property here exists because a policy in policies/ or a scanner gate in
# pipeline/ checks it. Change one and the corresponding gate turns red.

# Digest-pinned: a tag can be re-pointed at new content, a digest cannot, so the
# build is reproducible and the SBOM keeps describing the bytes that were scanned.
#
# The digest is python:3.13-slim. It is 3.13 rather than 3.12 because the 3.12
# line still carries CPython advisories whose fixes were only released for 3.13
# and later - the scan gate found them, and rebasing is the fix. Pinning by
# digest means this line has to be revisited deliberately, which is the point:
# an unpinned base would have "fixed" it silently and could regress the same way.
FROM python@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285 AS build

WORKDIR /build

# --require-hashes turns the lockfile into an integrity check: a tampered or
# substituted wheel on the index fails the build instead of shipping.
COPY app/requirements.txt ./requirements.txt
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --require-hashes --requirement requirements.txt \
 && /opt/venv/bin/pip uninstall --yes pip setuptools wheel

FROM python@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285

# Provenance is passed in by pipeline/build.sh and surfaces twice: as OCI
# annotations on the image and as the payload of GET /version at runtime.
ARG OCI_SOURCE=""
ARG OCI_REVISION=""
ARG OCI_CREATED=""

LABEL org.opencontainers.image.title="release-metadata" \
      org.opencontainers.image.description="Demo service carrying build provenance for the supply-chain pipeline" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="${OCI_SOURCE}" \
      org.opencontainers.image.revision="${OCI_REVISION}" \
      org.opencontainers.image.created="${OCI_CREATED}" \
      org.opencontainers.image.base.name="docker.io/library/python:3.13-slim"

ENV OCI_SOURCE="${OCI_SOURCE}" \
    OCI_REVISION="${OCI_REVISION}" \
    OCI_CREATED="${OCI_CREATED}" \
    PATH="/opt/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Fixed uid so Kubernetes runAsUser/runAsNonRoot can be asserted numerically.
#
# pip and setuptools are removed in the same layer. A runtime image has no
# reason to be able to install packages, and they are not free: the scan gate
# was blocking on setuptools and on the msgpack copy that pip vendors, neither
# of which this service imports. Deleting the installer removed both findings
# and one of the more convenient post-exploitation tools in the image.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin appuser \
 && /usr/local/bin/python -m pip uninstall --yes pip setuptools wheel

COPY --from=build /opt/venv /opt/venv
COPY --chown=root:root app/main.py /srv/app/main.py

WORKDIR /srv
USER 10001

EXPOSE 8000

# urllib rather than curl: no extra package, no extra CVE surface.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz').read()"]

ENTRYPOINT ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
