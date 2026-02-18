"""Tests for the two-scanner report normaliser.

The interesting behaviour is not parsing JSON, it is the gate: which findings
count, how the two tools are reconciled, and what the exit code says. Those are
the parts that decide whether a release ships.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from pipeline import scan_report
from pipeline.scan_report import Finding


def trivy_document(*rows: dict[str, str]) -> dict[str, Any]:
    return {
        "Results": [
            {
                "Target": "image (debian 12)",
                "Type": "debian",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": row["id"],
                        "PkgName": row["package"],
                        "InstalledVersion": row.get("version", "1.0"),
                        "Severity": row.get("severity", "HIGH"),
                        **({"FixedVersion": row["fixed"]} if row.get("fixed") else {}),
                    }
                    for row in rows
                ],
            }
        ]
    }


def grype_document(*rows: dict[str, str]) -> dict[str, Any]:
    return {
        "matches": [
            {
                "vulnerability": {
                    "id": row["id"],
                    "severity": row.get("severity", "High"),
                    "fix": {
                        "versions": [row["fixed"]] if row.get("fixed") else [],
                        "state": "fixed" if row.get("fixed") else "not-fixed",
                    },
                },
                "artifact": {"name": row["package"], "version": row.get("version", "1.0")},
            }
            for row in rows
        ]
    }


def test_trivy_and_grype_parse_to_the_same_shape() -> None:
    row = {"id": "CVE-2025-0001", "package": "openssl", "version": "3.0.1", "fixed": "3.0.2"}
    trivy = scan_report.parse_trivy(trivy_document(row))
    grype = scan_report.parse_grype(grype_document(row))

    assert [f.key for f in trivy] == [f.key for f in grype]
    assert trivy[0].severity == grype[0].severity == "HIGH"


def test_grype_severity_capitalisation_is_normalised() -> None:
    findings = scan_report.parse_grype(
        grype_document({"id": "CVE-2025-0001", "package": "zlib", "severity": "Critical"})
    )
    assert findings[0].severity == "CRITICAL"


def test_threshold_excludes_lower_severities() -> None:
    findings = scan_report.parse_trivy(
        trivy_document(
            {"id": "CVE-2025-0001", "package": "a", "severity": "CRITICAL"},
            {"id": "CVE-2025-0002", "package": "b", "severity": "HIGH"},
            {"id": "CVE-2025-0003", "package": "c", "severity": "MEDIUM"},
            {"id": "CVE-2025-0004", "package": "d", "severity": "LOW"},
        )
    )
    kept = {f.identifier for f in scan_report.at_or_above(findings, "HIGH")}
    assert kept == {"CVE-2025-0001", "CVE-2025-0002"}


def test_unknown_severity_never_blocks() -> None:
    findings = scan_report.parse_trivy(
        trivy_document({"id": "CVE-2025-0009", "package": "a", "severity": "UNKNOWN"})
    )
    assert scan_report.at_or_above(findings, "HIGH") == []


def test_only_fixable_drops_findings_with_no_released_fix() -> None:
    findings = scan_report.parse_trivy(
        trivy_document(
            {"id": "CVE-2025-0001", "package": "a", "fixed": "1.1"},
            {"id": "CVE-2025-0002", "package": "b"},
        )
    )
    assert [f.identifier for f in scan_report.only_fixable(findings)] == ["CVE-2025-0001"]


def test_duplicate_advisory_keeps_the_highest_severity() -> None:
    findings = scan_report.parse_trivy(
        trivy_document(
            {"id": "CVE-2025-0001", "package": "openssl", "severity": "HIGH"},
            {"id": "CVE-2025-0001", "package": "openssl", "severity": "CRITICAL"},
        )
    )
    merged = scan_report.dedupe(findings)
    assert len(merged) == 1
    assert next(iter(merged.values())).severity == "CRITICAL"


def test_same_advisory_on_two_packages_is_two_findings() -> None:
    """krb5 advisories hit several packages at once; each needs its own upgrade."""
    findings = scan_report.parse_trivy(
        trivy_document(
            {"id": "CVE-2026-40355", "package": "libkrb5-3"},
            {"id": "CVE-2026-40355", "package": "libk5crypto3"},
        )
    )
    assert len(scan_report.dedupe(findings)) == 2


def test_comparison_separates_shared_from_scanner_specific_findings() -> None:
    trivy = scan_report.parse_trivy(
        trivy_document(
            {"id": "CVE-2025-0001", "package": "openssl"},
            {"id": "CVE-2025-0002", "package": "perl"},
        )
    )
    grype = scan_report.parse_grype(
        grype_document(
            {"id": "CVE-2025-0001", "package": "openssl"},
            {"id": "CVE-2025-0003", "package": "busybox"},
        )
    )
    comparison = scan_report.compare(trivy, grype)

    assert [f.identifier for f in comparison.both] == ["CVE-2025-0001"]
    assert [f.identifier for f in comparison.trivy_only] == ["CVE-2025-0002"]
    assert [f.identifier for f in comparison.grype_only] == ["CVE-2025-0003"]
    assert len(comparison.union) == 3


def test_version_differences_do_not_create_false_disagreement() -> None:
    """Trivy and Grype normalise distro versions differently; that is not a finding."""
    trivy = scan_report.parse_trivy(
        trivy_document({"id": "CVE-2025-0001", "package": "openssl", "version": "3.0.1-1"})
    )
    grype = scan_report.parse_grype(
        grype_document({"id": "CVE-2025-0001", "package": "openssl", "version": "3.0.1"})
    )
    comparison = scan_report.compare(trivy, grype)

    assert len(comparison.both) == 1
    assert not comparison.trivy_only
    assert not comparison.grype_only


def test_package_name_casing_does_not_create_false_disagreement() -> None:
    """Trivy reports `pyyaml`, Grype reports `PyYAML`; that is one finding."""
    trivy = scan_report.parse_trivy(trivy_document({"id": "CVE-2020-14343", "package": "pyyaml"}))
    grype = scan_report.parse_grype(grype_document({"id": "CVE-2020-14343", "package": "PyYAML"}))
    comparison = scan_report.compare(trivy, grype)

    assert len(comparison.both) == 1
    assert not comparison.trivy_only
    assert not comparison.grype_only


def test_union_is_ordered_by_severity() -> None:
    trivy = scan_report.parse_trivy(
        trivy_document(
            {"id": "CVE-2025-0002", "package": "b", "severity": "HIGH"},
            {"id": "CVE-2025-0001", "package": "a", "severity": "CRITICAL"},
        )
    )
    ordered = scan_report.compare(trivy, []).union
    assert [f.severity for f in ordered] == ["CRITICAL", "HIGH"]


def _write(path: Path, document: dict[str, Any]) -> Path:
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_cli_blocks_when_either_scanner_finds_something(tmp_path: Path) -> None:
    trivy = _write(tmp_path / "trivy.json", trivy_document())
    grype = _write(
        tmp_path / "grype.json",
        grype_document({"id": "CVE-2025-0003", "package": "busybox", "fixed": "1.36"}),
    )
    exit_code = scan_report.main(
        ["--trivy", str(trivy), "--grype", str(grype), "--threshold", "HIGH"]
    )
    assert exit_code == 1


def test_cli_passes_when_the_only_findings_have_no_fix(tmp_path: Path) -> None:
    unfixed = {"id": "CVE-2025-0004", "package": "perl", "severity": "HIGH"}
    trivy = _write(tmp_path / "trivy.json", trivy_document(unfixed))
    grype = _write(tmp_path / "grype.json", grype_document(unfixed))

    assert (
        scan_report.main(
            [
                "--trivy",
                str(trivy),
                "--grype",
                str(grype),
                "--threshold",
                "HIGH",
                "--ignore-unfixed",
            ]
        )
        == 0
    )
    assert (
        scan_report.main(["--trivy", str(trivy), "--grype", str(grype), "--threshold", "HIGH"]) == 1
    )


def test_missing_report_is_an_error_rather_than_a_silent_pass(tmp_path: Path) -> None:
    """A scanner that failed to run must never look like a scanner that found nothing."""
    grype = _write(tmp_path / "grype.json", grype_document())
    with pytest.raises(FileNotFoundError):
        scan_report.load(tmp_path / "absent.json", "trivy")
    assert scan_report.load(grype, "grype") == []


def test_finding_ordering_is_stable_for_equal_severities() -> None:
    first = Finding(4, "CVE-2025-0001", "a", "1.0", "HIGH", "")
    second = Finding(4, "CVE-2025-0002", "a", "1.0", "HIGH", "")
    assert sorted([second, first]) == [first, second]
