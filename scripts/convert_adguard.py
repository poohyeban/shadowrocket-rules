#!/usr/bin/env python3

"""Conservatively convert AdGuard DNS rules to Shadowrocket domain rules."""

from __future__ import annotations

import argparse
import ipaddress
import re
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
        longest_fixed_hostname_suffix,
        normalize_hostname,
        rules_intersect,
    )
else:
    from rule_utils import (
        MAX_REGEX_EXPANSIONS,
        DomainRule,
        UnsafeRegexError,
        expand_safe_hostname_regex,
        longest_fixed_hostname_suffix,
        normalize_hostname,
        rules_intersect,
    )


MAX_WARNING_EXAMPLES = 30
_COSMETIC_MARKERS = ("##", "#@#", "#$#", "#%#", "#?#", "#$?#")
_BLOCKING_HOSTS_ADDRESSES = {
    ipaddress.ip_address("0.0.0.0"),
    ipaddress.ip_address("::"),
    ipaddress.ip_address("::1"),
}
_LOOPBACK_V4 = ipaddress.ip_network("127.0.0.0/8")


class UnsafeExceptionError(RuntimeError):
    """Raised instead of publishing a list that could violate an exception."""


@dataclass
class AdGuardStats:
    total_lines: int = 0
    input_rules: int = 0
    ignored_comments_empty: int = 0
    ignored_cosmetic: int = 0
    converted: Counter = field(default_factory=Counter)
    regex_safe_rules: int = 0
    regex_expanded_domains: int = 0
    regex_skipped_unsafe: int = 0
    exceptions_parsed: int = 0
    exceptions_applied: int = 0
    exceptions_conservative_envelopes: int = 0
    exceptions_unsupported_safe: int = 0
    exception_conflicting_blocks_removed: int = 0
    modifiers_supported: Counter = field(default_factory=Counter)
    modifiers_skipped: Counter = field(default_factory=Counter)
    badfilter_targets_applied: int = 0
    duplicate_rules: int = 0
    final_rules: int = 0
    warning_reasons: Counter = field(default_factory=Counter)
    warning_examples: list[tuple[int, str, str]] = field(default_factory=list)
    unsupported_records: list[tuple[int, str, str]] = field(default_factory=list)

    def warn(self, line_number: int, reason: str, line: str) -> None:
        record = (line_number, reason, line.rstrip("\n"))
        self.warning_reasons[reason] += 1
        self.unsupported_records.append(record)
        if len(self.warning_examples) < MAX_WARNING_EXAMPLES:
            self.warning_examples.append(record)


def _is_cosmetic(line: str) -> bool:
    return any(marker in line for marker in _COSMETIC_MARKERS)


def _find_unescaped(value: str, character: str, start: int = 0) -> int:
    escaped = False
    for index in range(start, len(value)):
        current = value[index]
        if escaped:
            escaped = False
            continue
        if current == "\\":
            escaped = True
            continue
        if current == character:
            return index
    return -1


def _split_modifiers(body: str) -> tuple[str, list[str]]:
    """Split modifiers without confusing a regex end anchor with ``$``."""

    if body.startswith("/"):
        closing = -1
        search_from = 1
        while True:
            candidate = _find_unescaped(body, "/", search_from)
            if candidate == -1:
                break
            closing = candidate
            search_from = candidate + 1
        if closing == -1:
            return body, []
        remainder = body[closing + 1 :]
        if not remainder:
            return body, []
        if remainder.startswith("$"):
            return body[: closing + 1], [
                item.strip() for item in remainder[1:].split(",") if item.strip()
            ]
        return body, []

    marker = _find_unescaped(body, "$")
    if marker == -1:
        return body, []
    return body[:marker], [
        item.strip() for item in body[marker + 1 :].split(",") if item.strip()
    ]


def _modifier_name(modifier: str) -> str:
    return modifier.lstrip("~").split("=", 1)[0].lower()


def _rebuild_rule(exception: bool, pattern: str, modifiers: list[str]) -> str:
    prefix = "@@" if exception else ""
    suffix = "$" + ",".join(modifiers) if modifiers else ""
    return prefix + pattern + suffix


def _collect_badfilter_targets(
    lines: list[str],
    stats: AdGuardStats,
) -> set[str]:
    targets: set[str] = set()
    for line in lines:
        stripped = line.strip()
        if (
            not stripped
            or stripped.startswith(("!", "#"))
            or _is_cosmetic(stripped)
        ):
            continue
        exception = stripped.startswith("@@")
        body = stripped[2:] if exception else stripped
        pattern, modifiers = _split_modifiers(body)
        names = [_modifier_name(modifier) for modifier in modifiers]
        if "badfilter" not in names:
            continue
        if names.count("badfilter") != 1:
            continue
        remaining = [
            modifier
            for modifier in modifiers
            if _modifier_name(modifier) != "badfilter"
        ]
        targets.add(_rebuild_rule(exception, pattern, remaining))
        stats.modifiers_supported["badfilter"] += 1
    return targets


def _parse_hosts_line(line: str) -> tuple[bool, list[str], str | None]:
    content = line.split("#", 1)[0].strip()
    fields = content.split()
    if len(fields) < 2:
        return False, [], None
    try:
        address = ipaddress.ip_address(fields[0])
    except ValueError:
        return False, [], None

    is_blocking = address in _BLOCKING_HOSTS_ADDRESSES or (
        address.version == 4 and address in _LOOPBACK_V4
    )
    if not is_blocking:
        return True, [], "hosts-address-is-not-unambiguously-blocking"

    hostnames: list[str] = []
    for field in fields[1:]:
        hostname = normalize_hostname(field)
        if hostname is None:
            return True, [], "invalid-hosts-hostname"
        hostnames.append(hostname)
    return True, hostnames, None


def _parse_basic_hostname_pattern(pattern: str) -> DomainRule | None:
    suffix_match = re.fullmatch(r"\|\|([^*?^|]+)\^(?:\|)?", pattern)
    if suffix_match:
        hostname = normalize_hostname(suffix_match.group(1))
        if hostname is not None:
            return DomainRule("DOMAIN-SUFFIX", hostname)

    exact_match = re.fullmatch(r"\|([^*?^|]+)(?:\^)?\|", pattern)
    if exact_match:
        hostname = normalize_hostname(exact_match.group(1))
        if hostname is not None:
            return DomainRule("DOMAIN", hostname)

    hostname = normalize_hostname(pattern)
    if hostname is not None:
        return DomainRule("DOMAIN", hostname)
    return None


def _unwrap_regex(pattern: str) -> str | None:
    if len(pattern) >= 2 and pattern.startswith("/") and pattern.endswith("/"):
        return pattern[1:-1]
    return None


def _regex_requires_non_hostname_character(pattern: str) -> bool:
    """Prove a regex cannot match a hostname via a required top-level '#'."""

    depth = 0
    in_class = False
    escaped = False
    top_level_alternation = False
    required_hash = False

    for index, current in enumerate(pattern):
        if escaped:
            escaped = False
            continue
        if current == "\\":
            escaped = True
            continue
        if in_class:
            if current == "]":
                in_class = False
            continue
        if current == "[":
            in_class = True
            continue
        if current == "(":
            depth += 1
            continue
        if current == ")":
            depth = max(0, depth - 1)
            continue
        if current == "|" and depth == 0:
            top_level_alternation = True
        if current == "#" and depth == 0:
            following = pattern[index + 1 : index + 2]
            if following not in {"?", "*"}:
                required_hash = True

    return required_hash and not top_level_alternation


def _safe_exception_envelope(pattern: str) -> DomainRule | None:
    # An end-anchored wildcard/partial exception can be covered by removing all
    # blocks intersecting its longest fixed hostname suffix.  This is broader
    # than the original exception, but it cannot create a false-positive block.
    if not (pattern.endswith("^") or pattern.endswith("^|") or pattern.endswith("|")):
        return None
    suffix = longest_fixed_hostname_suffix(pattern)
    if suffix is None:
        return None
    return DomainRule("DOMAIN-SUFFIX", suffix)


def _parse_regex_rule(
    regex: str,
    line_number: int,
    raw_line: str,
    stats: AdGuardStats,
    max_regex_expansions: int,
) -> list[DomainRule]:
    try:
        hostnames = expand_safe_hostname_regex(regex, max_regex_expansions)
    except UnsafeRegexError as error:
        stats.regex_skipped_unsafe += 1
        stats.warn(line_number, f"unsafe-regexp: {error}", raw_line)
        return []

    stats.regex_safe_rules += 1
    stats.regex_expanded_domains += len(hostnames)
    stats.converted["DOMAIN"] += len(hostnames)
    return [DomainRule("DOMAIN", hostname) for hostname in hostnames]


def _write_unsupported(path: Path, stats: AdGuardStats) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as output:
        for line_number, reason, line in stats.unsupported_records:
            output.write(f"{line_number}\t{reason}\t{line}\n")


def _print_report(stats: AdGuardStats, output: Path) -> None:
    print(f"Generated: {output}")
    print(f"Input lines: {stats.total_lines}")
    print(f"Input rules: {stats.input_rules}")
    print("Converted before exception resolution:")
    for kind in ("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD"):
        print(f"  {kind}: {stats.converted[kind]}")
    print("Regex:")
    print(f"  safely expanded rules: {stats.regex_safe_rules}")
    print(f"  emitted DOMAIN rules: {stats.regex_expanded_domains}")
    print(f"  skipped unsafe: {stats.regex_skipped_unsafe}")
    print("Exceptions:")
    print(f"  parsed: {stats.exceptions_parsed}")
    print(f"  applied: {stats.exceptions_applied}")
    print(f"  conservative suffix envelopes: {stats.exceptions_conservative_envelopes}")
    print(f"  unsupported but proven irrelevant to hostnames: {stats.exceptions_unsupported_safe}")
    print(f"  conflicting block rules removed: {stats.exception_conflicting_blocks_removed}")
    print("Modifiers:")
    if stats.modifiers_supported:
        for name, count in sorted(stats.modifiers_supported.items()):
            print(f"  supported {name}: {count}")
    else:
        print("  supported: 0")
    if stats.modifiers_skipped:
        for name, count in sorted(stats.modifiers_skipped.items()):
            print(f"  unsupported/skipped {name}: {count}")
    else:
        print("  unsupported/skipped: 0")
    print(f"  badfilter targets applied: {stats.badfilter_targets_applied}")
    print(f"Ignored cosmetic/non-DNS rules: {stats.ignored_cosmetic}")
    print(f"Ignored comment/empty lines: {stats.ignored_comments_empty}")
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
) -> AdGuardStats:
    with source.open("r", encoding="utf-8-sig") as input_file:
        lines = input_file.readlines()

    stats = AdGuardStats(total_lines=len(lines))
    disabled_targets = _collect_badfilter_targets(lines, stats)
    block_rules: set[DomainRule] = set()
    exception_rules: set[DomainRule] = set()
    converted_count = 0
    fatal_exceptions: list[tuple[int, str]] = []

    for line_number, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith(("!", "#")):
            stats.ignored_comments_empty += 1
            continue
        stats.input_rules += 1

        if _is_cosmetic(stripped):
            stats.ignored_cosmetic += 1
            continue

        exception = stripped.startswith("@@")
        body = stripped[2:] if exception else stripped
        pattern, modifiers = _split_modifiers(body)
        modifier_names = [_modifier_name(modifier) for modifier in modifiers]

        if "badfilter" in modifier_names:
            continue
        if stripped in disabled_targets:
            stats.badfilter_targets_applied += 1
            continue
        if modifiers:
            for name in modifier_names:
                stats.modifiers_skipped[name] += 1
            stats.warn(
                line_number,
                "modifier-changes-or-conditions-hostname-semantics",
                raw_line,
            )
            if exception:
                fatal_exceptions.append((line_number, stripped))
            continue

        is_hosts, hostnames, hosts_error = _parse_hosts_line(pattern)
        if is_hosts:
            if hosts_error is not None:
                stats.warn(line_number, hosts_error, raw_line)
                continue
            converted = [DomainRule("DOMAIN", hostname) for hostname in hostnames]
            if exception:
                exception_rules.update(converted)
                stats.exceptions_parsed += 1
            else:
                block_rules.update(converted)
                converted_count += len(converted)
                stats.converted["DOMAIN"] += len(converted)
            continue

        regex = _unwrap_regex(pattern)
        if regex is not None:
            if exception:
                try:
                    expanded = expand_safe_hostname_regex(regex, max_regex_expansions)
                except UnsafeRegexError as error:
                    if _regex_requires_non_hostname_character(regex):
                        stats.exceptions_unsupported_safe += 1
                        stats.warn(
                            line_number,
                            f"exception-regexp-cannot-match-hostname: {error}",
                            raw_line,
                        )
                    else:
                        stats.warn(
                            line_number,
                            f"unsafe-exception-regexp: {error}",
                            raw_line,
                        )
                        fatal_exceptions.append((line_number, stripped))
                    continue
                parsed = {DomainRule("DOMAIN", hostname) for hostname in expanded}
                exception_rules.update(parsed)
                stats.exceptions_parsed += 1
                stats.regex_safe_rules += 1
                stats.regex_expanded_domains += len(parsed)
            else:
                converted = _parse_regex_rule(
                    regex,
                    line_number,
                    raw_line,
                    stats,
                    max_regex_expansions,
                )
                block_rules.update(converted)
                converted_count += len(converted)
            continue

        basic_rule = _parse_basic_hostname_pattern(pattern)
        if basic_rule is not None:
            if exception:
                exception_rules.add(basic_rule)
                stats.exceptions_parsed += 1
            else:
                block_rules.add(basic_rule)
                converted_count += 1
                stats.converted[basic_rule.kind] += 1
            continue

        if exception:
            envelope = _safe_exception_envelope(pattern)
            if envelope is not None:
                exception_rules.add(envelope)
                stats.exceptions_parsed += 1
                stats.exceptions_conservative_envelopes += 1
                stats.warn(
                    line_number,
                    f"exception-conservatively-covered-by-{envelope.value}",
                    raw_line,
                )
            else:
                stats.warn(line_number, "unsupported-exception-pattern", raw_line)
                fatal_exceptions.append((line_number, stripped))
            continue

        stats.warn(line_number, "unsupported-adguard-pattern", raw_line)

    if fatal_exceptions:
        details = ", ".join(str(line_number) for line_number, _ in fatal_exceptions[:10])
        raise UnsafeExceptionError(
            "Cannot safely model one or more AdGuard exceptions; refusing to "
            f"publish. Lines: {details}"
        )

    retained_rules: set[DomainRule] = set()
    applied_exceptions: set[DomainRule] = set()
    for block in block_rules:
        conflicts = {
            exception
            for exception in exception_rules
            if rules_intersect(block, exception)
        }
        if conflicts:
            applied_exceptions.update(conflicts)
            stats.exception_conflicting_blocks_removed += 1
        else:
            retained_rules.add(block)

    stats.exceptions_applied = len(applied_exceptions)
    stats.duplicate_rules = converted_count - len(block_rules)
    stats.final_rules = len(retained_rules)

    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="\n") as output_file:
        for rule in sorted(retained_rules, key=lambda item: item.render()):
            output_file.write(rule.render() + "\n")

    if unsupported_output is not None:
        _write_unsupported(unsupported_output, stats)
    _print_report(stats, output)
    return stats


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Safely convert AdGuard DNS Filter to Shadowrocket rules."
    )
    parser.add_argument("source", type=Path, help="AdGuard DNS filter.txt")
    parser.add_argument("output", type=Path, help="generated Ad-Domain.list")
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
