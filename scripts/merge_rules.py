#!/usr/bin/env python3

"""Deterministically merge and validate generated Shadowrocket rulesets."""

from __future__ import annotations

import argparse
import ipaddress
from pathlib import Path

if __package__:
    from .rule_utils import normalize_hostname, normalize_keyword
else:
    from rule_utils import normalize_hostname, normalize_keyword


DOMAIN_TYPES = frozenset(
    {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-WILDCARD", "DOMAIN-KEYWORD"}
)
IP_TYPES = frozenset({"IP-CIDR", "IP-CIDR6"})
SUPPORTED_TYPES = DOMAIN_TYPES | IP_TYPES


class RuleValidationError(ValueError):
    """Raised when a generated source ruleset contains an invalid rule."""


def validate_rule(line: str, source: Path, line_number: int) -> None:
    fields = line.split(",")
    kind = fields[0]
    if kind not in SUPPORTED_TYPES:
        raise RuleValidationError(
            f"{source}:{line_number}: unsupported rule type: {kind}"
        )

    if kind in DOMAIN_TYPES:
        if len(fields) != 2:
            raise RuleValidationError(
                f"{source}:{line_number}: domain rule must have two fields"
            )
        value = fields[1]
        if kind == "DOMAIN-WILDCARD":
            if not value.startswith("*.") or value.count("*") != 1:
                normalized = None
            else:
                hostname = normalize_hostname(value[2:])
                normalized = f"*.{hostname}" if hostname is not None else None
        elif kind == "DOMAIN-KEYWORD":
            normalized = normalize_keyword(value)
        else:
            normalized = normalize_hostname(value)
        if normalized is None or normalized != value:
            raise RuleValidationError(
                f"{source}:{line_number}: non-canonical domain value: {value}"
            )
        return

    if len(fields) not in {2, 3}:
        raise RuleValidationError(
            f"{source}:{line_number}: IP rule has an invalid field count"
        )
    if len(fields) == 3 and fields[2] != "no-resolve":
        raise RuleValidationError(
            f"{source}:{line_number}: unsupported IP rule modifier: {fields[2]}"
        )
    value = fields[1]
    if "/" not in value:
        raise RuleValidationError(
            f"{source}:{line_number}: IP rule value is not CIDR notation: {value}"
        )
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as error:
        raise RuleValidationError(
            f"{source}:{line_number}: invalid IP network: {value}"
        ) from error
    expected_version = 4 if kind == "IP-CIDR" else 6
    if network.version != expected_version or str(network) != value:
        raise RuleValidationError(
            f"{source}:{line_number}: non-canonical or mismatched IP network: {value}"
        )


def read_rules(source: Path) -> set[str]:
    rules: set[str] = set()
    with source.open("r", encoding="utf-8-sig") as input_file:
        for line_number, raw_line in enumerate(input_file, start=1):
            line = raw_line.rstrip("\r\n")
            if not line:
                continue
            if line != line.strip():
                raise RuleValidationError(
                    f"{source}:{line_number}: leading or trailing whitespace"
                )
            validate_rule(line, source, line_number)
            rules.add(line)
    if not rules:
        raise RuleValidationError(f"ruleset is empty: {source}")
    return rules


def merge_files(sources: list[Path], output: Path) -> int:
    rules: set[str] = set()
    for source in sources:
        source_rules = read_rules(source)
        rules.update(source_rules)

    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="\n") as output_file:
        for rule in sorted(rules):
            output_file.write(rule + "\n")

    print(f"Generated: {output}")
    print(f"Source files: {len(sources)}")
    print(f"Final rules: {len(rules)}")
    return len(rules)


def _partition_pair(
    rules: set[str], *, expect_no_resolve: bool
) -> tuple[set[str], set[str]]:
    domains: set[str] = set()
    ip_rules: set[str] = set()
    for rule in rules:
        fields = rule.split(",")
        if fields[0] in DOMAIN_TYPES:
            domains.add(rule)
            continue

        has_no_resolve = len(fields) == 3
        if has_no_resolve != expect_no_resolve:
            expectation = "must" if expect_no_resolve else "must not"
            raise RuleValidationError(
                f"IP rule {expectation} use no-resolve: {rule}"
            )
        ip_rules.add(",".join(fields[:2]))
    return domains, ip_rules


def validate_pair(regular: Path, no_resolve: Path) -> tuple[int, int]:
    regular_domains, regular_ips = _partition_pair(
        read_rules(regular), expect_no_resolve=False
    )
    no_resolve_domains, no_resolve_ips = _partition_pair(
        read_rules(no_resolve), expect_no_resolve=True
    )
    if regular_domains != no_resolve_domains:
        raise RuleValidationError("regular and no-resolve domain rule sets differ")
    if regular_ips != no_resolve_ips:
        raise RuleValidationError("regular and no-resolve IP rule sets differ")

    print("Regular/no-resolve consistency: OK")
    print(f"Domain rules: {len(regular_domains)}")
    print(f"IP rules: {len(regular_ips)}")
    return len(regular_domains), len(regular_ips)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Merge or validate generated Shadowrocket rulesets."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    merge_parser = subparsers.add_parser("merge", help="merge source rulesets")
    merge_parser.add_argument("output", type=Path)
    merge_parser.add_argument("sources", type=Path, nargs="+")

    pair_parser = subparsers.add_parser(
        "validate-pair", help="validate regular/no-resolve equivalence"
    )
    pair_parser.add_argument("regular", type=Path)
    pair_parser.add_argument("no_resolve", type=Path)
    args = parser.parse_args()

    if args.command == "merge":
        missing = [source for source in args.sources if not source.is_file()]
        if missing:
            parser.error(f"Source file does not exist: {missing[0]}")
        merge_files(args.sources, args.output)
    else:
        for source in (args.regular, args.no_resolve):
            if not source.is_file():
                parser.error(f"Ruleset does not exist: {source}")
        validate_pair(args.regular, args.no_resolve)


if __name__ == "__main__":
    main()
