#!/usr/bin/env python3

from __future__ import annotations

import argparse
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

if __package__:
    from .rule_utils import (
        MAX_REGEX_EXPANSIONS,
        DomainRule,
        UnsafeRegexError,
        expand_safe_hostname_regex,
        normalize_hostname,
        normalize_keyword,
    )
else:
    from rule_utils import (
        MAX_REGEX_EXPANSIONS,
        DomainRule,
        UnsafeRegexError,
        expand_safe_hostname_regex,
        normalize_hostname,
        normalize_keyword,
    )


RULE_MAP = {
    "domain": "DOMAIN-SUFFIX",
    "full": "DOMAIN",
    "keyword": "DOMAIN-KEYWORD",
}
MAX_WARNING_EXAMPLES = 20


@dataclass
class ConversionStats:
    total_lines: int = 0
    input_rules: int = 0
    ignored_lines: int = 0
    converted: Counter = field(default_factory=Counter)
    regex_safe_rules: int = 0
    regex_expanded_domains: int = 0
    regex_skipped: int = 0
    duplicate_rules: int = 0
    warning_reasons: Counter = field(default_factory=Counter)
    warning_examples: list[tuple[int, str, str]] = field(default_factory=list)
    final_rules: int = 0

    def warn(self, line_number: int, reason: str, line: str) -> None:
        self.warning_reasons[reason] += 1
        if len(self.warning_examples) < MAX_WARNING_EXAMPLES:
            self.warning_examples.append((line_number, reason, line.rstrip("\n")))


def _strip_v2fly_metadata(line: str) -> str:
    # Release exports use :@attr while source data uses whitespace before
    # @attributes and &affiliations.  Neither is part of the routing value.
    if ":@" in line:
        line = line.split(":@", 1)[0]
    for marker in (" @", " &"):
        if marker in line:
            line = line.split(marker, 1)[0]
    if "#" in line:
        line = line.split("#", 1)[0]
    return line.strip()


def convert_rule(
    raw_line: str,
    line_number: int,
    stats: ConversionStats,
    max_regex_expansions: int = MAX_REGEX_EXPANSIONS,
) -> list[DomainRule]:
    stripped = raw_line.strip()
    if not stripped or stripped.startswith("#"):
        stats.ignored_lines += 1
        return []

    stats.input_rules += 1
    line = _strip_v2fly_metadata(stripped)
    if not line:
        stats.warn(line_number, "empty-after-metadata", raw_line)
        return []

    if ":" not in line:
        rule_type = "domain"
        value = line
    else:
        rule_type, value = line.split(":", 1)
        rule_type = rule_type.lower().strip()
        value = value.strip()

    if not value:
        stats.warn(line_number, "empty-rule-value", raw_line)
        return []

    if rule_type == "regexp":
        try:
            hostnames = expand_safe_hostname_regex(value, max_regex_expansions)
        except UnsafeRegexError as error:
            stats.regex_skipped += 1
            stats.warn(line_number, f"unsafe-regexp: {error}", raw_line)
            return []

        stats.regex_safe_rules += 1
        stats.regex_expanded_domains += len(hostnames)
        stats.converted["DOMAIN"] += len(hostnames)
        return [DomainRule("DOMAIN", hostname) for hostname in hostnames]

    shadowrocket_type = RULE_MAP.get(rule_type)
    if shadowrocket_type is None:
        stats.warn(line_number, f"unknown-rule-type: {rule_type}", raw_line)
        return []

    if rule_type == "keyword":
        normalized = normalize_keyword(value)
    else:
        normalized = normalize_hostname(value)
    if normalized is None:
        stats.warn(line_number, f"invalid-{rule_type}-value", raw_line)
        return []

    stats.converted[shadowrocket_type] += 1
    return [DomainRule(shadowrocket_type, normalized)]


def _write_unsupported(path: Path, stats: ConversionStats) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as output:
        for line_number, reason, line in stats.warning_examples:
            output.write(f"{line_number}\t{reason}\t{line}\n")


def _print_report(stats: ConversionStats, output: Path) -> None:
    print(f"Generated: {output}")
    print(f"Input lines: {stats.total_lines}")
    print(f"Input rules: {stats.input_rules}")
    print("Converted:")
    for kind in ("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD"):
        print(f"  {kind}: {stats.converted[kind]}")
    print("Regex:")
    print(f"  safely expanded rules: {stats.regex_safe_rules}")
    print(f"  emitted DOMAIN rules: {stats.regex_expanded_domains}")
    print(f"  skipped unsafe: {stats.regex_skipped}")
    print(f"Ignored comment/empty lines: {stats.ignored_lines}")
    print(f"Duplicate output rules removed: {stats.duplicate_rules}")
    print(f"Final rules: {stats.final_rules}")

    if stats.warning_reasons:
        print("Warning summary:", file=sys.stderr)
        for reason, count in sorted(stats.warning_reasons.items()):
            print(f"  {reason}: {count}", file=sys.stderr)
        for line_number, reason, line in stats.warning_examples:
            print(
                f"Warning: line {line_number}: {reason}: {line}",
                file=sys.stderr,
            )


def convert_file(
    source: Path,
    output: Path,
    unsupported_output: Path | None = None,
    max_regex_expansions: int = MAX_REGEX_EXPANSIONS,
) -> ConversionStats:
    stats = ConversionStats()
    rules: set[DomainRule] = set()
    converted_count = 0

    with source.open("r", encoding="utf-8-sig") as input_file:
        for line_number, line in enumerate(input_file, start=1):
            stats.total_lines += 1
            converted = convert_rule(
                line,
                line_number,
                stats,
                max_regex_expansions=max_regex_expansions,
            )
            converted_count += len(converted)
            rules.update(converted)

    sorted_rules = sorted(rules, key=lambda rule: rule.render())
    stats.duplicate_rules = converted_count - len(sorted_rules)
    stats.final_rules = len(sorted_rules)

    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="\n") as output_file:
        for rule in sorted_rules:
            output_file.write(rule.render() + "\n")

    if unsupported_output is not None:
        _write_unsupported(unsupported_output, stats)
    _print_report(stats, output)
    return stats


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Safely convert v2fly domain rules to Shadowrocket RULE-SET format."
    )
    parser.add_argument("source", type=Path, help="v2fly plaintext domain list")
    parser.add_argument("output", type=Path, help="generated Shadowrocket ruleset")
    parser.add_argument(
        "--unsupported-output",
        type=Path,
        help="optional build-only diagnostic file for skipped rules",
    )
    parser.add_argument(
        "--max-regex-expansions",
        type=int,
        default=MAX_REGEX_EXPANSIONS,
        help=f"maximum exact expansion count (default: {MAX_REGEX_EXPANSIONS})",
    )
    args = parser.parse_args()

    if not args.source.is_file():
        parser.error(f"Source file does not exist: {args.source}")
    if args.max_regex_expansions < 1:
        parser.error("--max-regex-expansions must be positive")

    convert_file(
        args.source,
        args.output,
        unsupported_output=args.unsupported_output,
        max_regex_expansions=args.max_regex_expansions,
    )


if __name__ == "__main__":
    main()
