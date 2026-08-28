#!/usr/bin/env python3

"""Convert the reviewed OpenAI allowlist snapshot to routing rules."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

if __package__:
    from .rule_utils import DomainRule, normalize_hostname
else:
    from rule_utils import DomainRule, normalize_hostname


class OfficialDomainError(ValueError):
    """Raised when manually maintained official-domain policy is invalid."""


@dataclass(frozen=True)
class ConversionStats:
    source_entries: int
    duplicate_entries: int
    excluded_entries: int
    final_rules: int


def parse_source_line(raw_line: str, line_number: int) -> DomainRule | None:
    content = raw_line.split("#", 1)[0].strip()
    if not content:
        return None

    lowered = content.lower()
    if lowered.startswith("*."):
        if lowered.count("*") != 1:
            raise OfficialDomainError(
                f"line {line_number}: malformed wildcard hostname: {content}"
            )
        hostname = normalize_hostname(lowered[2:])
        if hostname is None:
            raise OfficialDomainError(
                f"line {line_number}: invalid wildcard hostname: {content}"
            )
        return DomainRule("DOMAIN-WILDCARD", f"*.{hostname}")

    if "*" in lowered:
        raise OfficialDomainError(
            f"line {line_number}: malformed wildcard hostname: {content}"
        )

    hostname = normalize_hostname(lowered)
    if hostname is None:
        raise OfficialDomainError(
            f"line {line_number}: invalid hostname: {content}"
        )
    return DomainRule("DOMAIN", hostname)


def parse_file(source: Path, description: str) -> tuple[set[DomainRule], int]:
    rules: set[DomainRule] = set()
    entry_count = 0

    with source.open("r", encoding="utf-8-sig") as input_file:
        for line_number, raw_line in enumerate(input_file, start=1):
            rule = parse_source_line(raw_line, line_number)
            if rule is None:
                continue
            entry_count += 1
            rules.add(rule)

    if not rules:
        raise OfficialDomainError(f"{description} contains no valid entries")

    return rules, entry_count


def convert_file(
    source: Path,
    output: Path,
    exclude_file: Path | None = None,
) -> ConversionStats:
    rules, source_entries = parse_file(source, "official domain source")
    exclusions: set[DomainRule] = set()

    if exclude_file is not None:
        exclusions, _ = parse_file(exclude_file, "official domain exclusion source")
        unknown_exclusions = exclusions - rules
        if unknown_exclusions:
            rendered = ", ".join(
                sorted(rule.render() for rule in unknown_exclusions)
            )
            raise OfficialDomainError(
                "official domain exclusions are not present in the source snapshot: "
                f"{rendered}"
            )

    filtered_rules = rules - exclusions
    if not filtered_rules:
        raise OfficialDomainError("official domain routing subset contains no entries")

    rendered = sorted(rule.render() for rule in filtered_rules)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="\n") as output_file:
        for rule in rendered:
            output_file.write(rule + "\n")

    stats = ConversionStats(
        source_entries=source_entries,
        duplicate_entries=source_entries - len(rules),
        excluded_entries=len(exclusions),
        final_rules=len(rendered),
    )
    print(f"Generated: {output}")
    print(f"Source entries: {stats.source_entries}")
    print(f"Duplicate entries removed: {stats.duplicate_entries}")
    print(f"Excluded entries: {stats.excluded_entries}")
    print(f"Final rules: {stats.final_rules}")
    return stats


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert the reviewed OpenAI domain snapshot to Shadowrocket rules."
    )
    parser.add_argument("source", type=Path, help="reviewed domain snapshot")
    parser.add_argument("output", type=Path, help="generated ruleset")
    parser.add_argument(
        "--exclude-file",
        type=Path,
        help="reviewed source entries excluded from the routing ruleset",
    )
    args = parser.parse_args()

    if not args.source.is_file():
        parser.error(f"Source file does not exist: {args.source}")
    if args.exclude_file is not None and not args.exclude_file.is_file():
        parser.error(f"Exclusion file does not exist: {args.exclude_file}")

    convert_file(args.source, args.output, args.exclude_file)


if __name__ == "__main__":
    main()
