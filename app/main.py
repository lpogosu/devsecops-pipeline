"""Minimal demo service used as the payload of the supply-chain pipeline.

The service intentionally does almost nothing. Its only interesting property is
that it reports the same provenance values that the build stage stamps into the
image as OCI annotations, so a reviewer can compare `docker inspect` output with
a live `/version` response and see that the running container is the artifact
that was actually built, signed and attested.
"""

from __future__ import annotations

import os
from typing import Final

from fastapi import FastAPI
from pydantic import BaseModel

# Populated by `docker build --build-arg` in pipeline/build.sh. Empty values are
# expected when the module runs outside a container (tests, local uvicorn).
SOURCE: Final[str] = os.environ.get("OCI_SOURCE", "")
REVISION: Final[str] = os.environ.get("OCI_REVISION", "")
CREATED: Final[str] = os.environ.get("OCI_CREATED", "")

app = FastAPI(title="release-metadata", version="1.0.0", docs_url=None, redoc_url=None)


class Health(BaseModel):
    status: str


class Provenance(BaseModel):
    """Mirrors the org.opencontainers.image.* labels of the running image."""

    source: str
    revision: str
    created: str


@app.get("/healthz", response_model=Health)
def healthz() -> Health:
    return Health(status="ok")


@app.get("/version", response_model=Provenance)
def version() -> Provenance:
    return Provenance(source=SOURCE, revision=REVISION, created=CREATED)
