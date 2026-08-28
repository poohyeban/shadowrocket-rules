#!/usr/bin/env python3

"""Convert the repository-owned OpenAI allowlist snapshot to rules."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

if __package__:
    from .rule_utils import DomainRule, normalize_hostname
else:
    from rule_utils import DomainRule, normalize_hostname


class OfficialDomainError(ValueError):
    """Raised when the manually maintained source contains an invalid line."""


@dataclass(frozen=True)
class ConversionStats:
    source_entries: int
    duplicate_entries: int
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


def convert_file(source: Path, output: Path) -> ConversionStats:
    rules: set[DomainRule] = set()
    source_entries = 0

    with source.open("r", encoding="utf-8-sig") as input_file:
        for line_number, raw_line in enumerate(input_file, start=1):
            rule = parse_source_line(raw_line, line_number)
            if rule is None:
                continue
            source_entries += 1
            rules.add(rule)

    if not rules:
        raise OfficialDomainError("official domain source contains no valid entries")

    rendered = sorted(rule.render() for rule in rules)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="\n") as output_file:
        for rule in rendered:
            output_file.write(rule + "\n")

    stats = ConversionStats(
        source_entries=source_entries,
        duplicate_entries=source_entries - len(rendered),
        final_rules=len(rendered),
    )
    print(f"Generated: {output}")
    print(f"Source entries: {stats.source_entries}")
    print(f"Duplicate entries removed: {stats.duplicate_entries}")
    print(f"Final rules: {stats.final_rules}")
    return stats


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert the reviewed OpenAI domain snapshot to Shadowrocket rules."
    )
    parser.add_argument("source", type=Path, help="reviewed domain snapshot")
    parser.add_argument("output", type=Path, help="generated ruleset")
    args = parser.parse_args()

    if not args.source.is_file():
        parser.error(f"Source file does not exist: {args.source}")

    convert_file(args.source, args.output)


if __name__ == "__main__":
    main()
