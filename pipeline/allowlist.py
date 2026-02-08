"""Validate the accepted-findings allowlist and render scanner ignore files.

Trivy and Grype both have their own exception syntax. Keeping two hand-written
ignore files in sync is how exceptions drift apart and how a finding ends up
suppressed in one scanner and not the other. So security/allowlist.yaml is the
only file a human edits, and this module compiles it into whatever each scanner
wants to read.

The rules it enforces are the ones that keep an allowlist from rotting:
a justification that says something, a named owner, and a bounded window
measured from the day the exception was granted.
"""

from __future__ import annotations

import argparse
import datetime as dt
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import yaml

MAX_WINDOW_DAYS: Final[int] = 90
VALID_SCOPES: Final[frozenset[str]] = frozenset({"image", "deps", "secrets"})
MIN_REASON_CHARS: Final[int] = 60

# Phrases that look like a justification but carry no information. Rejecting
# them is the difference between an allowlist and a mute button.
EMPTY_JUSTIFICATIONS: Final[tuple[str, ...]] = (
    "false positive",
    "not applicable",
    "n/a",
    "wontfix",
    "accepted risk",
    "not exploitable",
)


class AllowlistError(Exception):
    """Raised when the allowlist is structurally invalid and must not be used."""


@dataclass(frozen=True)
class Entry:
    identifier: str
    scope: str
    packages: tuple[str, ...]
    reason: str
    owner: str
    granted: dt.date
    expires: dt.date
    ticket: str

    @property
    def window_days(self) -> int:
        return (self.expires - self.granted).days

    def lapsed_on(self, today: dt.date) -> bool:
        return today > self.expires


def _require(raw: dict[str, object], key: str, position: int) -> object:
    if key not in raw or raw[key] in (None, "", []):
        raise AllowlistError(f"entry #{position}: missing required field '{key}'")
    return raw[key]


def _as_date(value: object, key: str, position: int) -> dt.date:
    if isinstance(value, dt.datetime):
        return value.date()
    if isinstance(value, dt.date):
        return value
    raise AllowlistError(
        f"entry #{position}: '{key}' must be an unquoted YYYY-MM-DD date, got {value!r}"
    )


def _parse_entry(raw: dict[str, object], position: int) -> Entry:
    identifier = str(_require(raw, "id", position))
    scope = str(_require(raw, "scope", position))
    if scope not in VALID_SCOPES:
        raise AllowlistError(f"{identifier}: scope '{scope}' is not one of {sorted(VALID_SCOPES)}")

    reason = " ".join(str(_require(raw, "reason", position)).split())
    if len(reason) < MIN_REASON_CHARS:
        raise AllowlistError(
            f"{identifier}: reason is {len(reason)} chars, "
            f"at least {MIN_REASON_CHARS} are required to describe why it is safe"
        )
    if reason.strip().rstrip(".").lower() in EMPTY_JUSTIFICATIONS:
        raise AllowlistError(f"{identifier}: reason '{reason}' explains nothing")

    granted = _as_date(_require(raw, "granted", position), "granted", position)
    expires = _as_date(_require(raw, "expires", position), "expires", position)
    if expires <= granted:
        raise AllowlistError(f"{identifier}: expires {expires} is not after granted {granted}")

    window = (expires - granted).days
    if window > MAX_WINDOW_DAYS:
        raise AllowlistError(
            f"{identifier}: exception window is {window} days, the maximum is {MAX_WINDOW_DAYS}"
        )

    declared_packages = raw.get("packages") or []
    if not isinstance(declared_packages, list):
        raise AllowlistError(f"{identifier}: 'packages' must be a list of package names")
    packages = tuple(str(package) for package in declared_packages)
    return Entry(
        identifier=identifier,
        scope=scope,
        packages=packages,
        reason=reason,
        owner=str(_require(raw, "owner", position)),
        granted=granted,
        expires=expires,
        ticket=str(raw.get("ticket", "")),
    )


def load(path: Path) -> list[Entry]:
    """Parse and validate the allowlist, raising on anything structurally wrong."""
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise AllowlistError(f"{path}: expected a mapping at the top level")
    if document.get("version") != 1:
        raise AllowlistError(f"{path}: unsupported schema version {document.get('version')!r}")

    raw_entries = document.get("entries") or []
    if not isinstance(raw_entries, list):
        raise AllowlistError(f"{path}: 'entries' must be a list")

    entries = [_parse_entry(raw, position) for position, raw in enumerate(raw_entries, start=1)]

    seen: dict[tuple[str, str], int] = {}
    for position, entry in enumerate(entries, start=1):
        key = (entry.identifier, entry.scope)
        if key in seen:
            raise AllowlistError(
                f"{entry.identifier}: duplicated for scope '{entry.scope}' "
                f"(entries #{seen[key]} and #{position})"
            )
        seen[key] = position
    return entries


def active(entries: list[Entry], today: dt.date, scope: str | None = None) -> list[Entry]:
    """Entries that still suppress today, optionally narrowed to one scope."""
    return [e for e in entries if not e.lapsed_on(today) and (scope is None or e.scope == scope)]


def lapsed(entries: list[Entry], today: dt.date) -> list[Entry]:
    return [e for e in entries if e.lapsed_on(today)]


def render_trivy(entries: list[Entry], today: dt.date) -> str:
    """Trivy's YAML ignore format, which understands expiry natively."""
    payload: dict[str, list[dict[str, Any]]] = {"vulnerabilities": []}
    for entry in active(entries, today, scope="image"):
        payload["vulnerabilities"].append(
            {
                "id": entry.identifier,
                "statement": f"{entry.reason} (owner: {entry.owner}, ticket: {entry.ticket})",
                # Trivy parses this as RFC 3339, not as a bare date, and fails
                # the whole run if it cannot. End of day, so the entry is
                # active through its expiry date exactly as `lapsed_on` reads it.
                "expired_at": f"{entry.expires.isoformat()}T23:59:59Z",
            }
        )
    header = (
        "# Generated from security/allowlist.yaml by pipeline/allowlist.py.\n"
        "# Do not edit: changes belong in the allowlist, which enforces the rules.\n"
    )
    return header + yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)


def render_grype(entries: list[Entry], today: dt.date) -> str:
    """Grype config with `ignore` rules; Grype has no expiry field of its own,
    which is precisely why the expiry has to be enforced before rendering."""
    rules: list[dict[str, Any]] = []
    for entry in active(entries, today, scope="image"):
        if entry.packages:
            rules.extend(
                {"vulnerability": entry.identifier, "package": {"name": package}}
                for package in entry.packages
            )
        else:
            rules.append({"vulnerability": entry.identifier})
    header = (
        "# Generated from security/allowlist.yaml by pipeline/allowlist.py.\n"
        "# Do not edit: changes belong in the allowlist, which enforces the rules.\n"
    )
    return header + yaml.safe_dump({"ignore": rules}, sort_keys=False, allow_unicode=True)


def _cmd_validate(entries: list[Entry], today: dt.date, strict: bool) -> int:
    stale = lapsed(entries, today)
    live = active(entries, today)
    print(f"allowlist: {len(entries)} entries, {len(live)} active, {len(stale)} lapsed")
    for entry in live:
        print(
            f"  active  {entry.identifier:<18} scope={entry.scope:<7} "
            f"owner={entry.owner:<10} expires={entry.expires} "
            f"({(entry.expires - today).days}d left)"
        )
    for entry in stale:
        print(
            f"  LAPSED  {entry.identifier:<18} scope={entry.scope:<7} "
            f"owner={entry.owner:<10} expired={entry.expires} "
            f"({(today - entry.expires).days}d ago) - no longer suppressing",
            file=sys.stderr,
        )
    if stale and strict:
        print(
            f"error: {len(stale)} lapsed exception(s) need renewal or removal",
            file=sys.stderr,
        )
        return 1
    return 0


def _cmd_render(entries: list[Entry], today: dt.date, fmt: str, output: Path | None) -> int:
    text = render_trivy(entries, today) if fmt == "trivy" else render_grype(entries, today)
    if output is None:
        sys.stdout.write(text)
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
        print(f"wrote {output}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, prog="allowlist")
    parser.add_argument(
        "--file",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "security" / "allowlist.yaml",
        help="path to the allowlist (default: security/allowlist.yaml)",
    )
    parser.add_argument(
        "--today",
        type=dt.date.fromisoformat,
        default=dt.date.today(),
        help="evaluate expiry against this date instead of today (YYYY-MM-DD)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate", help="check the allowlist and report expiry status")
    validate.add_argument(
        "--strict",
        action="store_true",
        help="also fail when an exception has lapsed (used by the scheduled CI run)",
    )

    render = sub.add_parser("render", help="compile the allowlist into a scanner ignore file")
    render.add_argument("--format", choices=("trivy", "grype"), required=True)
    render.add_argument("--output", type=Path, default=None)

    args = parser.parse_args(argv)

    try:
        entries = load(args.file)
    except (AllowlistError, yaml.YAMLError) as exc:
        print(f"allowlist is invalid: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError:
        print(f"allowlist not found: {args.file}", file=sys.stderr)
        return 2

    if args.command == "validate":
        return _cmd_validate(entries, args.today, strict=args.strict)
    return _cmd_render(entries, args.today, args.format, args.output)


if __name__ == "__main__":
    raise SystemExit(main())
