"""Behaviour tests for the demo service.

The service is tiny, so the tests cover the one thing that carries meaning: the
provenance endpoint must report what the image was actually built with, and must
say nothing at all when the build did not stamp it.
"""

from __future__ import annotations

import importlib
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

PROVENANCE_VARS = ("OCI_SOURCE", "OCI_REVISION", "OCI_CREATED")

STAMPED = {
    "OCI_SOURCE": "https://github.com/lpogosu/devsecops-pipeline",
    "OCI_REVISION": "0f1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c",
    "OCI_CREATED": "2026-01-24T20:15:00Z",
}


def _client(monkeypatch: pytest.MonkeyPatch, env: dict[str, str]) -> TestClient:
    """Reload the module so its module-level constants re-read the environment."""
    import app.main

    for name in PROVENANCE_VARS:
        if name in env:
            monkeypatch.setenv(name, env[name])
        else:
            monkeypatch.delenv(name, raising=False)
    return TestClient(importlib.reload(app.main).app)


@pytest.fixture
def stamped(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    yield _client(monkeypatch, STAMPED)


@pytest.fixture
def unstamped(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    yield _client(monkeypatch, {})


def test_healthz_reports_ok(unstamped: TestClient) -> None:
    response = unstamped.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_version_returns_build_provenance(stamped: TestClient) -> None:
    payload = stamped.get("/version").json()
    assert payload["revision"] == STAMPED["OCI_REVISION"]
    assert payload["source"].endswith("/devsecops-pipeline")
    assert payload["created"] == STAMPED["OCI_CREATED"]


def test_version_is_empty_rather_than_guessed_without_build_args(
    unstamped: TestClient,
) -> None:
    """An unstamped image must admit it has no provenance instead of inventing one."""
    assert unstamped.get("/version").json() == {"source": "", "revision": "", "created": ""}


def test_interactive_docs_are_disabled(unstamped: TestClient) -> None:
    """Swagger UI loads scripts from a CDN and widens the attack surface for nothing."""
    assert unstamped.get("/docs").status_code == 404
