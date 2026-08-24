#!/usr/bin/env python3

"""Shared, conservative helpers for Shadowrocket domain rule generation.

The regex expander intentionally accepts only a small, finite subset.  A regex
is converted only when the parser can enumerate its complete hostname language
without approximation.  Unsupported constructs are rejected rather than
translated to a broader wildcard rule.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass


MAX_REGEX_EXPANSIONS = 1000
MAX_HOSTNAME_LENGTH = 253
MAX_LABEL_LENGTH = 63

_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_KEYWORD_RE = re.compile(r"^[a-z0-9.-]+$")
_SAFE_LITERAL_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")
_SAFE_CLASS_CHARS = _SAFE_LITERAL_CHARS | {"."}


class UnsafeRegexError(ValueError):
    """Raised when a regex cannot be proven finite and hostname-only."""


class ExpansionLimitError(UnsafeRegexError):
    """Raised when exact finite expansion would exceed the configured cap."""


@dataclass(frozen=True, order=True)
class DomainRule:
    kind: str
    value: str

    def render(self) -> str:
        return f"{self.kind},{self.value}"


def normalize_hostname(value: str) -> str | None:
    """Return a canonical ASCII hostname, or ``None`` when it is invalid.

    Unicode input is deliberately not rewritten with an IDNA codec.  Punycode
    is accepted as ordinary ASCII, while an implicit Unicode-to-IDNA rewrite is
    avoided because it would add another set of normalization semantics.
    """

    value = value.strip().lower()
    if not value or len(value) > MAX_HOSTNAME_LENGTH:
        return None

    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        return None

    if value.endswith(".") or ".." in value:
        return None

    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        return None

    labels = value.split(".")
    if any(
        not label
        or len(label) > MAX_LABEL_LENGTH
        or _LABEL_RE.fullmatch(label) is None
        for label in labels
    ):
        return None

    return value


def normalize_keyword(value: str) -> str | None:
    value = value.strip().lower()
    if not value or len(value) > MAX_HOSTNAME_LENGTH:
        return None
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        return None
    if _KEYWORD_RE.fullmatch(value) is None:
        return None
    return value


def is_subdomain_or_equal(hostname: str, suffix: str) -> bool:
    return hostname == suffix or hostname.endswith("." + suffix)


def rules_intersect(block: DomainRule, exception: DomainRule) -> bool:
    """Whether a supported block and exception hostname set overlap."""

    if block.kind == "DOMAIN":
        if exception.kind == "DOMAIN":
            return block.value == exception.value
        if exception.kind == "DOMAIN-SUFFIX":
            return is_subdomain_or_equal(block.value, exception.value)
    elif block.kind == "DOMAIN-SUFFIX":
        if exception.kind == "DOMAIN":
            return is_subdomain_or_equal(exception.value, block.value)
        if exception.kind == "DOMAIN-SUFFIX":
            return is_subdomain_or_equal(
                block.value, exception.value
            ) or is_subdomain_or_equal(exception.value, block.value)
    return False


class _FiniteRegexParser:
    def __init__(self, pattern: str, max_expansions: int):
        self.pattern = pattern
        self.max_expansions = max_expansions
        self.index = 0

    def parse(self) -> set[str]:
        values = self._parse_expression(stop=None)
        if self.index != len(self.pattern):
            raise UnsafeRegexError("unexpected trailing regex syntax")
        return values

    def _check(self, values: set[str]) -> set[str]:
        if len(values) > self.max_expansions:
            raise ExpansionLimitError(
                f"expansion count exceeds {self.max_expansions}"
            )
        if any(len(value) > MAX_HOSTNAME_LENGTH for value in values):
            raise UnsafeRegexError("expanded hostname exceeds length limit")
        return values

    def _union(self, left: set[str], right: set[str]) -> set[str]:
        return self._check(left | right)

    def _concat(self, left: set[str], right: set[str]) -> set[str]:
        if len(left) * len(right) > self.max_expansions:
            raise ExpansionLimitError(
                f"expansion count exceeds {self.max_expansions}"
            )
        return self._check({a + b for a in left for b in right})

    def _parse_expression(self, stop: str | None) -> set[str]:
        result = self._parse_sequence(stop)
        while self.index < len(self.pattern) and self.pattern[self.index] == "|":
            self.index += 1
            result = self._union(result, self._parse_sequence(stop))
        return result

    def _parse_sequence(self, stop: str | None) -> set[str]:
        result = {""}
        while self.index < len(self.pattern):
            current = self.pattern[self.index]
            if current == "|" or (stop is not None and current == stop):
                break
            atom = self._parse_atom()
            atom = self._apply_quantifier(atom)
            result = self._concat(result, atom)
        return result

    def _parse_atom(self) -> set[str]:
        if self.index >= len(self.pattern):
            raise UnsafeRegexError("unexpected end of regex")

        current = self.pattern[self.index]
        if current == "(":
            if self.pattern.startswith("(?:", self.index):
                raise UnsafeRegexError("non-capturing groups are not in Go RE2 syntax")
            self.index += 1
            value = self._parse_expression(stop=")")
            if self.index >= len(self.pattern) or self.pattern[self.index] != ")":
                raise UnsafeRegexError("unclosed group")
            self.index += 1
            return value

        if current == "[":
            return self._parse_character_class()

        if current == "\\":
            return self._parse_escape(in_class=False)

        if current == ".":
            raise UnsafeRegexError("dot wildcard has an unbounded alphabet")

        if current in ")*+?{}^$":
            raise UnsafeRegexError(f"unsupported or misplaced token: {current}")

        if current not in _SAFE_LITERAL_CHARS:
            raise UnsafeRegexError(f"non-hostname literal is unsupported: {current!r}")

        self.index += 1
        return {current}

    def _parse_escape(self, in_class: bool) -> set[str]:
        self.index += 1
        if self.index >= len(self.pattern):
            raise UnsafeRegexError("dangling escape")

        escaped = self.pattern[self.index]
        self.index += 1
        if escaped == "d":
            return set("0123456789")
        if escaped == ".":
            return {"."}
        if in_class and escaped == "-":
            return {"-"}
        if escaped in _SAFE_LITERAL_CHARS:
            return {escaped}
        raise UnsafeRegexError(f"unsupported escape: \\{escaped}")

    def _parse_character_class(self) -> set[str]:
        self.index += 1
        if self.index >= len(self.pattern):
            raise UnsafeRegexError("unclosed character class")
        if self.pattern[self.index] == "^":
            raise UnsafeRegexError("negated character class is not finite-safe")

        values: set[str] = set()
        saw_item = False
        while self.index < len(self.pattern) and self.pattern[self.index] != "]":
            start_values = self._parse_class_item()
            saw_item = True

            if (
                len(start_values) == 1
                and self.index < len(self.pattern)
                and self.pattern[self.index] == "-"
                and self.index + 1 < len(self.pattern)
                and self.pattern[self.index + 1] != "]"
            ):
                self.index += 1
                end_values = self._parse_class_item()
                if len(end_values) != 1:
                    raise UnsafeRegexError("range endpoint is not a literal")
                start = next(iter(start_values))
                end = next(iter(end_values))
                if ord(start) > ord(end):
                    raise UnsafeRegexError("reversed character range")
                expanded = {chr(code) for code in range(ord(start), ord(end) + 1)}
                if not expanded <= _SAFE_CLASS_CHARS:
                    raise UnsafeRegexError("character range includes unsafe characters")
                values.update(expanded)
            else:
                values.update(start_values)

            self._check(values)

        if self.index >= len(self.pattern) or self.pattern[self.index] != "]":
            raise UnsafeRegexError("unclosed character class")
        if not saw_item:
            raise UnsafeRegexError("empty character class")
        self.index += 1
        return self._check(values)

    def _parse_class_item(self) -> set[str]:
        current = self.pattern[self.index]
        if current == "\\":
            values = self._parse_escape(in_class=True)
        else:
            self.index += 1
            values = {current}
        if not values <= _SAFE_CLASS_CHARS:
            raise UnsafeRegexError("character class contains unsafe characters")
        return values

    def _apply_quantifier(self, atom: set[str]) -> set[str]:
        if self.index >= len(self.pattern):
            return atom

        current = self.pattern[self.index]
        if current in "*+":
            raise UnsafeRegexError("unbounded quantifier is unsupported")
        if current == "?":
            self.index += 1
            return self._union({""}, atom)
        if current != "{":
            return atom

        closing = self.pattern.find("}", self.index + 1)
        if closing == -1:
            raise UnsafeRegexError("unclosed bounded quantifier")
        spec = self.pattern[self.index + 1 : closing]
        self.index = closing + 1

        if re.fullmatch(r"\d+", spec):
            minimum = maximum = int(spec)
        else:
            match = re.fullmatch(r"(\d+),(\d+)", spec)
            if match is None:
                raise UnsafeRegexError("quantifier must have a finite upper bound")
            minimum, maximum = map(int, match.groups())

        if minimum > maximum:
            raise UnsafeRegexError("quantifier lower bound exceeds upper bound")
        if maximum > MAX_HOSTNAME_LENGTH:
            raise UnsafeRegexError("quantifier exceeds hostname length limit")

        repeated: set[str] = set()
        current_values = {""}
        for count in range(maximum + 1):
            if count >= minimum:
                repeated = self._union(repeated, current_values)
            if count < maximum:
                current_values = self._concat(current_values, atom)
        return repeated


def expand_safe_hostname_regex(
    pattern: str,
    max_expansions: int = MAX_REGEX_EXPANSIONS,
) -> list[str]:
    """Exactly expand a finite, fully anchored hostname regex.

    The accepted grammar is deliberately smaller than Go RE2: lowercase ASCII
    hostname literals, escaped dots, finite character classes, capturing-group
    alternation, ``?``, and finite ``{m}``/``{m,n}`` quantifiers.  This is not a
    best-effort regex translator.
    """

    if max_expansions < 1:
        raise ValueError("max_expansions must be positive")
    if not pattern.startswith("^") or not pattern.endswith("$"):
        raise UnsafeRegexError("regex must be anchored with both ^ and $")

    body = pattern[1:-1]
    if not body:
        raise UnsafeRegexError("empty regex")

    expanded = _FiniteRegexParser(body, max_expansions).parse()
    normalized: set[str] = set()
    for value in sorted(expanded):
        hostname = normalize_hostname(value)
        if hostname is None:
            raise UnsafeRegexError(
                f"finite expansion contains a non-hostname value: {value!r}"
            )
        normalized.add(hostname)

    if len(normalized) != len(expanded):
        raise UnsafeRegexError("normalization would change regex distinctions")
    return sorted(normalized)


def longest_fixed_hostname_suffix(pattern: str) -> str | None:
    """Return a conservative suffix envelope for a wildcard exception.

    Any block intersecting this suffix can be removed to guarantee that a
    wildcard exception is not accidentally rejected.  The result may be wider
    than the exception, which only causes safe under-blocking.
    """

    tail = re.split(r"[*?]", pattern)[-1]
    tail = tail.replace("\\.", ".")
    tail = re.sub(r"[\^|]+$", "", tail)
    tail = tail.strip(".")
    if not tail:
        return None

    labels = tail.split(".")
    for index in range(len(labels)):
        candidate = normalize_hostname(".".join(labels[index:]))
        if candidate is not None:
            return candidate
    return None
