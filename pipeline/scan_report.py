"""Normalise Trivy and Grype output into one comparable set of findings.

The point of running two scanners is not redundancy, it is disagreement. Trivy
and Grype resolve packages differently and pull from partly different advisory
sources, so each finds things the other misses. That is only useful if the two
reports can be compared, which means normalising them to the same shape first:
a finding is (advisory id, package, installed version, severity).

The module also decides what blocks. Severity thresholds and the unfixed-finding
policy live in security/gates.env; this file applies them and explains the
verdict in terms a developer can act on.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

SEVERITY_ORDER: Final[tuple[str, ...]] = (
    "UNKNOWN",
    "NEGLIGIBLE",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
)


@dataclass(frozen=True, order=True)
class Finding:
    severity_rank: int
    identifier: str
    package: str
    version: str
    severity: str
    fixed_in: str

    @property
    def key(self) -> tuple[str, str]:
        """Identity used when comparing scanners: advisory plus package.

        Installed version is excluded deliberately - the two tools sometimes
        report the same package with differently normalised versions (an epoch,
        a distro suffix), and treating that as a disagreement would drown the
        real ones. The package name is lowercased for the same reason: Trivy
        says `pyyaml`, Grype says `PyYAML`, and counting that as two findings
        would inflate the disagreement this report exists to measure.

        What it deliberately does not do is map GHSA identifiers onto their CVE
        equivalents. That mapping needs an advisory database, and guessing it
        would silently merge two findings that are not the same.
        """
        return (self.identifier, self.package.lower())


def _rank(severity: str) -> int:
    normalised = severity.upper()
    return SEVERITY_ORDER.index(normalised) if normalised in SEVERITY_ORDER else 0


def _make(identifier: str, package: str, version: str, severity: str, fixed_in: str) -> Finding:
    return Finding(
        severity_rank=_rank(severity),
        identifier=identifier,
        package=package,
        version=version,
        severity=severity.upper(),
        fixed_in=fixed_in,
    )


def parse_trivy(document: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for result in document.get("Results") or []:
        for vulnerability in result.get("Vulnerabilities") or []:
            findings.append(
                _make(
                    identifier=vulnerability.get("VulnerabilityID", ""),
                    package=vulnerability.get("PkgName", ""),
                    version=vulnerability.get("InstalledVersion", ""),
                    severity=vulnerability.get("Severity", "UNKNOWN"),
                    fixed_in=vulnerability.get("FixedVersion", ""),
                )
            )
    return findings


def parse_grype(document: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for match in document.get("matches") or []:
        vulnerability = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        fix = vulnerability.get("fix") or {}
        versions = fix.get("versions") or []
        findings.append(
            _make(
                identifier=vulnerability.get("id", ""),
                package=artifact.get("name", ""),
                version=artifact.get("version", ""),
                severity=vulnerability.get("severity", "Unknown"),
                fixed_in=", ".join(versions),
            )
        )
    return findings


def load(path: Path, parser: str) -> list[Finding]:
    if not path.exists():
        raise FileNotFoundError(f"{parser} report not found: {path}")
    document = json.loads(path.read_text(encoding="utf-8"))
    return parse_trivy(document) if parser == "trivy" else parse_grype(document)


def at_or_above(findings: list[Finding], threshold: str) -> list[Finding]:
    minimum = _rank(threshold)
    return [finding for finding in findings if finding.severity_rank >= minimum]


def only_fixable(findings: list[Finding]) -> list[Finding]:
    return [finding for finding in findings if finding.fixed_in]


def dedupe(findings: list[Finding]) -> dict[tuple[str, str], Finding]:
    """Keep the highest-severity record per (advisory, package)."""
    merged: dict[tuple[str, str], Finding] = {}
    for finding in findings:
        current = merged.get(finding.key)
        if current is None or finding.severity_rank > current.severity_rank:
            merged[finding.key] = finding
    return merged


@dataclass(frozen=True)
class Comparison:
    both: list[Finding]
    trivy_only: list[Finding]
    grype_only: list[Finding]

    @property
    def union(self) -> list[Finding]:
        return sorted(self.both + self.trivy_only + self.grype_only, reverse=True)


def compare(trivy: list[Finding], grype: list[Finding]) -> Comparison:
    left, right = dedupe(trivy), dedupe(grype)
    shared = left.keys() & right.keys()
    return Comparison(
        both=sorted((left[key] for key in shared), reverse=True),
        trivy_only=sorted((left[key] for key in left.keys() - shared), reverse=True),
        grype_only=sorted((right[key] for key in right.keys() - shared), reverse=True),
    )


def _print_findings(title: str, findings: list[Finding], limit: int) -> None:
    if not findings:
        return
    print(f"  {title} ({len(findings)}):")
    for finding in findings[:limit]:
        fix = f"fix {finding.fixed_in}" if finding.fixed_in else "no fix released"
        print(
            f"    {finding.severity:<8} {finding.identifier:<20} "
            f"{finding.package} {finding.version}  [{fix}]"
        )
    if len(findings) > limit:
        print(f"    ... {len(findings) - limit} more")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, prog="scan-report")
    parser.add_argument("--trivy", type=Path, required=True)
    parser.add_argument("--grype", type=Path, required=True)
    parser.add_argument("--threshold", default="HIGH")
    parser.add_argument(
        "--ignore-unfixed",
        action="store_true",
        help="do not block on findings that have no released fix",
    )
    parser.add_argument("--limit", type=int, default=15)
    args = parser.parse_args(argv)

    trivy = load(args.trivy, "trivy")
    grype = load(args.grype, "grype")

    gating_trivy = at_or_above(trivy, args.threshold)
    gating_grype = at_or_above(grype, args.threshold)
    if args.ignore_unfixed:
        gating_trivy = only_fixable(gating_trivy)
        gating_grype = only_fixable(gating_grype)

    comparison = compare(gating_trivy, gating_grype)
    blocking = comparison.union

    print(
        f"  trivy {len(dedupe(gating_trivy))} | grype {len(dedupe(gating_grype))} | "
        f"union {len(blocking)} at >= {args.threshold.upper()}"
        + (" (fixable only)" if args.ignore_unfixed else "")
    )
    print(
        f"  agreement: {len(comparison.both)} shared, "
        f"{len(comparison.trivy_only)} trivy-only, {len(comparison.grype_only)} grype-only"
    )

    _print_findings("blocking", blocking, args.limit)
    return 1 if blocking else 0


if __name__ == "__main__":
    raise SystemExit(main())
