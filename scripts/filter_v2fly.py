#!/usr/bin/env python3

"""Filter v2fly domain-list rules by source attributes.

This module deliberately leaves rule conversion and normalization to
``convert.py``.  Retained rules are written in their original text form.
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path


_ATTRIBUTE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
_RELEASE_ATTRIBUTE_SUFFIX_RE = re.compile(
    r"(?::@[A-Za-z0-9][A-Za-z0-9_-]*)+$"
)
_RELEASE_ATTRIBUTE_RE = re.compile(r":@([A-Za-z0-9][A-Za-z0-9_-]*)")


@dataclass(frozen=True)
class ParsedLine:
    kind: str
    attributes: frozenset[str] = frozenset()


@dataclass
class FilterStats:
    total_lines: int = 0
    rule_lines: int = 0
    kept_rules: int = 0
    filtered_rules: int = 0
    passthrough_lines: int = 0
    metadata_lines: int = 0


def _validate_attribute_name(attribute: str) -> str:
    if _ATTRIBUTE_NAME_RE.fullmatch(attribute) is None:
        raise argparse.ArgumentTypeError(
            "attribute must contain only letters, digits, underscores, or hyphens"
        )
    return attribute


def parse_v2fly_line(raw_line: str) -> ParsedLine:
    """Classify a line and return attributes from metadata positions only."""

    content = raw_line.split("#", 1)[0].strip()
    if not content:
        return ParsedLine("passthrough")

    first_token = content.split(maxsplit=1)[0]
    if first_token.startswith(("@", "&")):
        return ParsedLine("metadata")

    attributes: set[str] = set()

    # Source data writes attributes as separate whitespace-delimited tokens.
    for token in content.split()[1:]:
        if token.startswith("@") and _ATTRIBUTE_NAME_RE.fullmatch(token[1:]):
            attributes.add(token[1:])

    # Release exports append one or more :@attribute suffixes to the rule.
    release_suffix = _RELEASE_ATTRIBUTE_SUFFIX_RE.search(first_token)
    if release_suffix is not None:
        attributes.update(
            _RELEASE_ATTRIBUTE_RE.findall(release_suffix.group(0))
        )

    return ParsedLine("rule", frozenset(attributes))


def _write_line(output_file, raw_line: str) -> None:
    output_file.write(raw_line.rstrip("\r\n") + "\n")


def filter_file(
    source: Path,
    output: Path,
    *,
    include_attribute: str | None = None,
    exclude_attribute: str | None = None,
) -> FilterStats:
    """Write a deterministic attribute-filtered view of a v2fly source file."""

    if include_attribute is not None and exclude_attribute is not None:
        raise ValueError("include_attribute and exclude_attribute are mutually exclusive")

    stats = FilterStats()
    output.parent.mkdir(parents=True, exist_ok=True)

    with source.open("r", encoding="utf-8-sig") as input_file, output.open(
        "w", encoding="utf-8", newline="\n"
    ) as output_file:
        for raw_line in input_file:
            stats.total_lines += 1
            parsed = parse_v2fly_line(raw_line)

            if parsed.kind == "passthrough":
                stats.passthrough_lines += 1
                _write_line(output_file, raw_line)
                continue

            if parsed.kind == "metadata":
                stats.metadata_lines += 1
                continue

            stats.rule_lines += 1
            keep = True
            if include_attribute is not None:
                keep = include_attribute in parsed.attributes
            elif exclude_attribute is not None:
                keep = exclude_attribute not in parsed.attributes

            if keep:
                stats.kept_rules += 1
                _write_line(output_file, raw_line)
            else:
                stats.filtered_rules += 1

    return stats


def _print_report(stats: FilterStats, output: Path) -> None:
    print(f"Generated: {output}")
    print(f"Input lines: {stats.total_lines}")
    print(f"Input rules: {stats.rule_lines}")
    print(f"Kept rules: {stats.kept_rules}")
    print(f"Filtered rules: {stats.filtered_rules}")
    print(f"Preserved comment/empty lines: {stats.passthrough_lines}")
    print(f"Dropped standalone metadata lines: {stats.metadata_lines}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Filter v2fly domain rules by source attribute."
    )
    parser.add_argument("source", type=Path, help="v2fly plaintext domain list")
    parser.add_argument("output", type=Path, help="filtered v2fly plaintext output")
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--include-attribute",
        type=_validate_attribute_name,
        help="retain only rules carrying this attribute",
    )
    group.add_argument(
        "--exclude-attribute",
        type=_validate_attribute_name,
        help="retain only rules not carrying this attribute",
    )
    args = parser.parse_args()

    if not args.source.is_file():
        parser.error(f"Source file does not exist: {args.source}")

    stats = filter_file(
        args.source,
        args.output,
        include_attribute=args.include_attribute,
        exclude_attribute=args.exclude_attribute,
    )
    _print_report(stats, args.output)


if __name__ == "__main__":
    main()
