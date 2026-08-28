from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from scripts.merge_rules import (
    RuleValidationError,
    merge_files,
    validate_pair,
)


REPOSITORY = Path(__file__).resolve().parents[1]
BUILD = REPOSITORY / "build"


class MergeRulesTests(unittest.TestCase):
    def write(self, root: Path, name: str, content: str) -> Path:
        path = root / name
        with path.open("w", encoding="utf-8", newline="\n") as output_file:
            output_file.write(content)
        return path

    def test_exact_deduplication_and_deterministic_order(self):
        BUILD.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=BUILD) as directory:
            root = Path(directory)
            first = self.write(
                root,
                "first.list",
                "DOMAIN-SUFFIX,openai.com\nDOMAIN,chat.openai.com\n",
            )
            second = self.write(
                root,
                "second.list",
                "DOMAIN-WILDCARD,*.openai.com\nDOMAIN,chat.openai.com\n",
            )
            output = root / "output.list"
            with contextlib.redirect_stdout(io.StringIO()):
                count = merge_files([first, second], output)
            self.assertEqual(count, 3)
            self.assertEqual(
                output.read_text(encoding="utf-8"),
                "DOMAIN,chat.openai.com\n"
                "DOMAIN-SUFFIX,openai.com\n"
                "DOMAIN-WILDCARD,*.openai.com\n",
            )

    def test_all_supported_rule_types_are_accepted(self):
        content = (
            "DOMAIN,chat.openai.com\n"
            "DOMAIN-SUFFIX,openai.com\n"
            "DOMAIN-WILDCARD,*.openai.com\n"
            "DOMAIN-KEYWORD,openai\n"
            "IP-CIDR,192.0.2.0/24\n"
            "IP-CIDR6,2001:db8::/32\n"
        )
        BUILD.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=BUILD) as directory:
            root = Path(directory)
            source = self.write(root, "source.list", content)
            output = root / "output.list"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(merge_files([source], output), 6)

    def test_unsupported_rule_type_fails_closed(self):
        BUILD.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=BUILD) as directory:
            root = Path(directory)
            source = self.write(root, "source.list", "URL-REGEX,example\n")
            with self.assertRaises(RuleValidationError):
                merge_files([source], root / "output.list")

    def test_regular_no_resolve_pair_is_equivalent(self):
        BUILD.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=BUILD) as directory:
            root = Path(directory)
            regular = self.write(
                root,
                "regular.list",
                "DOMAIN-SUFFIX,openai.com\n"
                "IP-CIDR,192.0.2.0/24\n"
                "IP-CIDR6,2001:db8::/32\n",
            )
            no_resolve = self.write(
                root,
                "no-resolve.list",
                "DOMAIN-SUFFIX,openai.com\n"
                "IP-CIDR,192.0.2.0/24,no-resolve\n"
                "IP-CIDR6,2001:db8::/32,no-resolve\n",
            )
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(validate_pair(regular, no_resolve), (1, 2))

    def test_china_style_sources_merge_into_consistent_aggregates(self):
        BUILD.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=BUILD) as directory:
            root = Path(directory)
            domains = self.write(
                root,
                "China-v2fly-Domain.list",
                "DOMAIN,exact.example\nDOMAIN-SUFFIX,example.cn\n",
            )
            geoip = self.write(
                root,
                "China-GeoIP.list",
                "IP-CIDR,192.0.2.0/24\nIP-CIDR6,2001:db8::/32\n",
            )
            geoip_no_resolve = self.write(
                root,
                "China-GeoIP-NoResolve.list",
                "IP-CIDR,192.0.2.0/24,no-resolve\n"
                "IP-CIDR6,2001:db8::/32,no-resolve\n",
            )
            regular = root / "China.list"
            no_resolve = root / "China-NoResolve.list"

            with contextlib.redirect_stdout(io.StringIO()):
                merge_files([domains, geoip], regular)
                merge_files([domains, geoip_no_resolve], no_resolve)
                self.assertEqual(validate_pair(regular, no_resolve), (2, 2))

            self.assertIn(
                "DOMAIN-SUFFIX,example.cn\n",
                regular.read_text(encoding="utf-8"),
            )
            self.assertIn(
                "IP-CIDR,192.0.2.0/24,no-resolve\n",
                no_resolve.read_text(encoding="utf-8"),
            )

    def test_no_resolve_modifier_policy_is_enforced(self):
        BUILD.mkdir(exist_ok=True)
        cases = (
            (
                "IP-CIDR,192.0.2.0/24,no-resolve\n",
                "IP-CIDR,192.0.2.0/24,no-resolve\n",
            ),
            (
                "IP-CIDR,192.0.2.0/24\n",
                "IP-CIDR,192.0.2.0/24\n",
            ),
        )
        for regular_text, no_resolve_text in cases:
            with self.subTest(case=(regular_text, no_resolve_text)), tempfile.TemporaryDirectory(
                dir=BUILD
            ) as directory:
                root = Path(directory)
                regular = self.write(root, "regular.list", regular_text)
                no_resolve = self.write(root, "no-resolve.list", no_resolve_text)
                with self.assertRaises(RuleValidationError):
                    validate_pair(regular, no_resolve)

    def test_domain_and_ip_set_mismatches_fail(self):
        BUILD.mkdir(exist_ok=True)
        cases = (
            (
                "DOMAIN,chat.openai.com\n",
                "DOMAIN,api.openai.com\n",
            ),
            (
                "IP-CIDR,192.0.2.0/24\n",
                "IP-CIDR,198.51.100.0/24,no-resolve\n",
            ),
        )
        for regular_text, no_resolve_text in cases:
            with self.subTest(case=(regular_text, no_resolve_text)), tempfile.TemporaryDirectory(
                dir=BUILD
            ) as directory:
                root = Path(directory)
                regular = self.write(root, "regular.list", regular_text)
                no_resolve = self.write(root, "no-resolve.list", no_resolve_text)
                with self.assertRaises(RuleValidationError):
                    validate_pair(regular, no_resolve)


if __name__ == "__main__":
    unittest.main()
