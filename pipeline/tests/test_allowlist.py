"""Tests for the accepted-findings allowlist.

The rules being tested are the ones that decide whether an allowlist stays an
engineering artefact or turns into a mute button, so most of these cases are
about rejecting entries a tired reviewer would wave through.
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest
import yaml

from pipeline import allowlist

GOOD_REASON = (
    "The package ships in the base image and is never imported at runtime, "
    "so no request path can reach the vulnerable parser."
)


def write(tmp_path: Path, entries: list[dict[str, object]], version: int = 1) -> Path:
    path = tmp_path / "allowlist.yaml"
    path.write_text(
        yaml.safe_dump({"version": version, "entries": entries}, sort_keys=False),
        encoding="utf-8",
    )
    return path


def entry(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": "CVE-2022-40897",
        "scope": "image",
        "packages": ["setuptools"],
        "reason": GOOD_REASON,
        "owner": "lpogosu",
        "granted": dt.date(2026, 2, 11),
        "expires": dt.date(2026, 5, 12),
        "ticket": "SEC-104",
    }
    base.update(overrides)
    return base


def test_repository_allowlist_is_valid() -> None:
    """The checked-in allowlist must satisfy its own rules at all times."""
    entries = allowlist.load(Path(__file__).resolve().parents[2] / "security" / "allowlist.yaml")
    assert entries
    assert all(e.window_days <= allowlist.MAX_WINDOW_DAYS for e in entries)


def test_valid_entry_round_trips(tmp_path: Path) -> None:
    entries = allowlist.load(write(tmp_path, [entry()]))
    assert len(entries) == 1
    assert entries[0].identifier == "CVE-2022-40897"
    assert entries[0].window_days == 90


@pytest.mark.parametrize("field", ["id", "scope", "reason", "owner", "granted", "expires"])
def test_missing_required_field_is_rejected(tmp_path: Path, field: str) -> None:
    incomplete = entry()
    del incomplete[field]
    with pytest.raises(allowlist.AllowlistError, match=field):
        allowlist.load(write(tmp_path, [incomplete]))


def test_window_longer_than_ninety_days_is_rejected(tmp_path: Path) -> None:
    too_long = entry(granted=dt.date(2026, 1, 1), expires=dt.date(2026, 12, 31))
    with pytest.raises(allowlist.AllowlistError, match="exception window"):
        allowlist.load(write(tmp_path, [too_long]))


def test_expiry_before_grant_is_rejected(tmp_path: Path) -> None:
    backwards = entry(granted=dt.date(2026, 5, 12), expires=dt.date(2026, 2, 11))
    with pytest.raises(allowlist.AllowlistError, match="not after granted"):
        allowlist.load(write(tmp_path, [backwards]))


@pytest.mark.parametrize("reason", ["false positive", "Not applicable.", "n/a"])
def test_content_free_justification_is_rejected(tmp_path: Path, reason: str) -> None:
    with pytest.raises(allowlist.AllowlistError):
        allowlist.load(write(tmp_path, [entry(reason=reason)]))


def test_short_justification_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(allowlist.AllowlistError, match="at least"):
        allowlist.load(write(tmp_path, [entry(reason="Mitigated by the WAF.")]))


def test_unknown_scope_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(allowlist.AllowlistError, match="scope"):
        allowlist.load(write(tmp_path, [entry(scope="everything")]))


def test_quoted_date_is_rejected(tmp_path: Path) -> None:
    """A quoted date silently becomes a string and would never compare correctly."""
    path = tmp_path / "allowlist.yaml"
    path.write_text(
        "version: 1\n"
        "entries:\n"
        "  - id: CVE-2022-40897\n"
        "    scope: image\n"
        f"    reason: {GOOD_REASON}\n"
        "    owner: lpogosu\n"
        '    granted: "2026-02-11"\n'
        "    expires: 2026-05-12\n",
        encoding="utf-8",
    )
    with pytest.raises(allowlist.AllowlistError, match="YYYY-MM-DD"):
        allowlist.load(path)


def test_duplicate_entry_for_the_same_scope_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(allowlist.AllowlistError, match="duplicated"):
        allowlist.load(write(tmp_path, [entry(), entry(ticket="SEC-200")]))


def test_same_id_in_different_scopes_is_allowed(tmp_path: Path) -> None:
    entries = allowlist.load(write(tmp_path, [entry(), entry(scope="deps")]))
    assert {e.scope for e in entries} == {"image", "deps"}


def test_unsupported_schema_version_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(allowlist.AllowlistError, match="schema version"):
        allowlist.load(write(tmp_path, [entry()], version=2))


def test_entry_suppresses_before_expiry_and_stops_after(tmp_path: Path) -> None:
    entries = allowlist.load(write(tmp_path, [entry()]))
    assert allowlist.active(entries, dt.date(2026, 5, 12))
    assert not allowlist.lapsed(entries, dt.date(2026, 5, 12))
    assert not allowlist.active(entries, dt.date(2026, 5, 13))
    assert allowlist.lapsed(entries, dt.date(2026, 5, 13))


def test_lapsed_entries_are_not_rendered_into_scanner_configs(tmp_path: Path) -> None:
    """Expiry has to remove the suppression, not merely warn about it."""
    entries = allowlist.load(write(tmp_path, [entry()]))
    after = dt.date(2026, 6, 1)

    trivy = yaml.safe_load(allowlist.render_trivy(entries, after))
    grype = yaml.safe_load(allowlist.render_grype(entries, after))

    assert trivy["vulnerabilities"] == []
    assert grype["ignore"] == []


def test_active_entry_reaches_both_scanner_configs(tmp_path: Path) -> None:
    entries = allowlist.load(write(tmp_path, [entry()]))
    during = dt.date(2026, 3, 1)

    trivy = yaml.safe_load(allowlist.render_trivy(entries, during))
    grype = yaml.safe_load(allowlist.render_grype(entries, during))

    assert trivy["vulnerabilities"][0]["id"] == "CVE-2022-40897"
    # Trivy rejects a bare date and aborts the scan, so the rendered value has
    # to be RFC 3339. A regression here disables the whole image scan, not just
    # one suppression.
    assert trivy["vulnerabilities"][0]["expired_at"] == "2026-05-12T23:59:59Z"
    assert grype["ignore"] == [
        {"vulnerability": "CVE-2022-40897", "package": {"name": "setuptools"}}
    ]


def test_deps_scope_does_not_leak_into_the_image_scanner_config(tmp_path: Path) -> None:
    """A suppression granted for a lockfile finding must not silence the image."""
    entries = allowlist.load(write(tmp_path, [entry(scope="deps")]))
    rendered = yaml.safe_load(allowlist.render_trivy(entries, dt.date(2026, 3, 1)))
    assert rendered["vulnerabilities"] == []


def test_validate_reports_lapsed_entries_without_failing(tmp_path: Path) -> None:
    path = write(tmp_path, [entry()])
    assert allowlist.main(["--file", str(path), "--today", "2026-06-01", "validate"]) == 0


def test_strict_validate_fails_on_lapsed_entries(tmp_path: Path) -> None:
    path = write(tmp_path, [entry()])
    exit_code = allowlist.main(
        ["--file", str(path), "--today", "2026-06-01", "validate", "--strict"]
    )
    assert exit_code == 1


def test_invalid_allowlist_fails_even_without_strict(tmp_path: Path) -> None:
    path = write(tmp_path, [entry(reason="nope")])
    assert allowlist.main(["--file", str(path), "validate"]) == 2
