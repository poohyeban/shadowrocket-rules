from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from scripts.convert_adguard import UnsafeExceptionError, convert_file


REPOSITORY = Path(__file__).resolve().parents[1]
BUILD = REPOSITORY / "build"


class AdGuardConversionTests(unittest.TestCase):
    def convert(self, content: str):
        BUILD.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=BUILD) as directory:
            root = Path(directory)
            source = root / "filter.txt"
            output = root / "output.list"
            with source.open("w", encoding="utf-8", newline="\n") as source_file:
                source_file.write(content)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                stats = convert_file(source, output)
            return output.read_bytes(), stats

    def test_suffix_rule(self):
        output, _ = self.convert("||example.com^\n")
        self.assertEqual(output, b"DOMAIN-SUFFIX,example.com\n")

    def test_domain_only_rule_is_exact(self):
        output, _ = self.convert("example.com\n")
        self.assertEqual(output, b"DOMAIN,example.com\n")

    def test_suffix_exception_removes_ancestor_block(self):
        output, stats = self.convert("||example.com^\n@@||safe.example.com^\n")
        self.assertEqual(output, b"")
        self.assertEqual(stats.exception_conflicting_blocks_removed, 1)

    def test_exact_exception_removes_intersecting_block(self):
        output, _ = self.convert(
            "||ads.example.com^\n||other.example^\n@@|ads.example.com^|\n"
        )
        self.assertEqual(output, b"DOMAIN-SUFFIX,other.example\n")

    def test_wildcard_exception_uses_conservative_suffix_envelope(self):
        output, stats = self.convert(
            "||tracker.example.com^\n@@||api-v*.example.com^|\n"
        )
        self.assertEqual(output, b"")
        self.assertEqual(stats.exceptions_conservative_envelopes, 1)

    def test_blocking_hosts_style_is_exact(self):
        output, _ = self.convert("0.0.0.0 example.com alias.example\n")
        self.assertEqual(
            output,
            b"DOMAIN,alias.example\nDOMAIN,example.com\n",
        )

    def test_nonblocking_hosts_address_is_skipped(self):
        output, stats = self.convert("192.0.2.1 example.com\n")
        self.assertEqual(output, b"")
        self.assertEqual(stats.warning_reasons["hosts-address-is-not-unambiguously-blocking"], 1)

    def test_cosmetic_rule_is_ignored(self):
        output, stats = self.convert("example.com##.advertisement\n")
        self.assertEqual(output, b"")
        self.assertEqual(stats.ignored_cosmetic, 1)

    def test_important_modifier_is_not_ignored(self):
        output, stats = self.convert("||example.com^$important\n")
        self.assertEqual(output, b"")
        self.assertEqual(stats.modifiers_skipped["important"], 1)

    def test_context_modifier_is_not_made_unconditional(self):
        output, stats = self.convert("||example.com^$client=phone\n")
        self.assertEqual(output, b"")
        self.assertEqual(stats.modifiers_skipped["client"], 1)

    def test_badfilter_disables_matching_basic_rule(self):
        output, stats = self.convert("||example.com^\n||example.com^$badfilter\n")
        self.assertEqual(output, b"")
        self.assertEqual(stats.badfilter_targets_applied, 1)

    def test_safe_regex_is_finitely_expanded(self):
        output, stats = self.convert(r"/^(foo|bar)\.example\.com$/" + "\n")
        self.assertEqual(
            output,
            b"DOMAIN,bar.example.com\nDOMAIN,foo.example.com\n",
        )
        self.assertEqual(stats.regex_safe_rules, 1)

    def test_unsafe_regex_is_skipped_not_widened(self):
        output, stats = self.convert(r"/^example\d+\.com$/" + "\n")
        self.assertEqual(output, b"")
        self.assertEqual(stats.regex_skipped_unsafe, 1)

    def test_unmodelled_hostname_exception_fails_closed(self):
        BUILD.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=BUILD) as directory:
            root = Path(directory)
            source = root / "filter.txt"
            output = root / "output.list"
            source.write_text("||foo.example^\n@@/foo.*/\n", encoding="utf-8")
            with self.assertRaises(UnsafeExceptionError):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    convert_file(source, output)

    def test_exception_regex_requiring_hash_cannot_match_hostname(self):
        output, stats = self.convert("||example.com^\n@@/foo#bar/\n")
        self.assertEqual(output, b"DOMAIN-SUFFIX,example.com\n")
        self.assertEqual(stats.exceptions_unsupported_safe, 1)

    def test_partial_and_url_patterns_are_not_guessed(self):
        output, stats = self.convert("://ads.example.com^\n.example.com^\n")
        self.assertEqual(output, b"")
        self.assertEqual(stats.warning_reasons["unsupported-adguard-pattern"], 2)

    def test_malformed_and_ipv6_text_are_not_domains(self):
        output, stats = self.convert("bad_.example\n2001:db8::1\n")
        self.assertEqual(output, b"")
        self.assertGreaterEqual(sum(stats.warning_reasons.values()), 2)

    def test_deterministic_deduplicated_output(self):
        content = "||b.example^\n||a.example^\n||b.example^\n"
        first, first_stats = self.convert(content)
        second, _ = self.convert(content)
        self.assertEqual(first, second)
        self.assertEqual(
            first,
            b"DOMAIN-SUFFIX,a.example\nDOMAIN-SUFFIX,b.example\n",
        )
        self.assertEqual(first_stats.duplicate_rules, 1)


if __name__ == "__main__":
    unittest.main()
