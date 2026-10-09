from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from scripts.convert import convert_file


REPOSITORY = Path(__file__).resolve().parents[1]
BUILD = REPOSITORY / "build"


class V2FlyConversionTests(unittest.TestCase):
    def convert(self, content: str):
        BUILD.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=BUILD) as directory:
            root = Path(directory)
            source = root / "source.txt"
            output = root / "output.list"
            with source.open("w", encoding="utf-8", newline="\n") as source_file:
                source_file.write(content)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                stats = convert_file(source, output)
            return output.read_bytes(), stats

    def test_domain_full_and_keyword(self):
        output, _ = self.convert(
            "domain:example.com\nfull:www.example.com\nkeyword:tracker\nplain.example\n"
        )
        self.assertEqual(
            output.decode(),
            "DOMAIN,www.example.com\n"
            "DOMAIN-KEYWORD,tracker\n"
            "DOMAIN-SUFFIX,example.com\n"
            "DOMAIN-SUFFIX,plain.example\n",
        )

    def test_finite_regex_expands_to_domain_rules(self):
        output, stats = self.convert(r"regexp:^(foo|bar)\.example\.com$" + "\n")
        self.assertEqual(
            output.decode(),
            "DOMAIN,bar.example.com\nDOMAIN,foo.example.com\n",
        )
        self.assertEqual(stats.regex_safe_rules, 1)
        self.assertEqual(stats.regex_expanded_domains, 2)

    def test_v2fly_release_attributes_are_removed(self):
        output, _ = self.convert("domain:example.com:@cn\nfull:www.example.com @ads\n")
        self.assertEqual(
            output.decode(),
            "DOMAIN,www.example.com\nDOMAIN-SUFFIX,example.com\n",
        )

    def test_unsafe_regex_is_skipped_with_reason(self):
        output, stats = self.convert(r"regexp:^example\d+\.com$" + "\n")
        self.assertEqual(output, b"")
        self.assertEqual(stats.regex_skipped, 1)
        self.assertTrue(any(reason.startswith("unsafe-regexp") for reason in stats.warning_reasons))

    def test_openai_unbounded_regex_is_skipped_without_approximation(self):
        regexp = r"regexp:^chatgpt-async-webps-prod-\S+-\d+\.webpubsub\.azure\.com$"
        BUILD.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=BUILD) as directory:
            root = Path(directory)
            source = root / "source.txt"
            output = root / "output.list"
            diagnostic = root / "unsupported.txt"
            source.write_text(regexp + "\n", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                stats = convert_file(source, output, unsupported_output=diagnostic)

            rendered = output.read_text(encoding="utf-8")
            self.assertEqual(rendered, "")
            self.assertNotIn("DOMAIN-WILDCARD", rendered)
            self.assertNotIn("URL-REGEX", rendered)
            self.assertNotIn("chatgpt-async-webps-prod-*-*", rendered)
            self.assertEqual(stats.regex_skipped, 1)
            self.assertTrue(
                any(reason.startswith("unsafe-regexp") for reason in stats.warning_reasons)
            )
            diagnostic_text = diagnostic.read_text(encoding="utf-8")
            self.assertIn("unsafe-regexp", diagnostic_text)
            self.assertIn(regexp, diagnostic_text)

    def test_deduplication_and_sort_are_deterministic(self):
        content = "domain:b.example\ndomain:a.example\ndomain:b.example\n"
        first, first_stats = self.convert(content)
        second, _ = self.convert(content)
        self.assertEqual(first, second)
        self.assertEqual(first_stats.duplicate_rules, 1)
        self.assertEqual(
            first.decode(),
            "DOMAIN-SUFFIX,a.example\nDOMAIN-SUFFIX,b.example\n",
        )

    def test_malformed_and_ipv6_looking_values_are_not_emitted(self):
        output, stats = self.convert("domain:\ndomain:2001:db8::1\nfull:bad_.example\n")
        self.assertEqual(output, b"")
        self.assertEqual(sum(stats.warning_reasons.values()), 3)

    def test_output_uses_lf_and_has_no_timestamp(self):
        output, _ = self.convert("domain:example.com\n")
        self.assertEqual(output, b"DOMAIN-SUFFIX,example.com\n")
        self.assertNotIn(b"Generated at", output)

    def test_strict_conversion_does_not_replace_output_on_invalid_input(self):
        for content in ("example.com\ninclude:another", "example.com\nfull:bad/path", "# empty"):
            with self.subTest(content=content), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source, output = root / "source", root / "rules"
                source.write_text(content)
                output.write_text("previous content\n")
                with self.assertRaises(ValueError):
                    convert_file(source, output, strict=True)
                self.assertEqual(output.read_text(), "previous content\n")

    def test_all_unsupported_rules_are_recorded_beyond_console_sample(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output, diagnostic = root / "source", root / "rules", root / "diagnostic"
            source.write_text("example.com\n" + r"regexp:^.+\.example$" + "\n")
            source.write_text(source.read_text() + (r"regexp:^.+\.example$" + "\n") * 29)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                stats = convert_file(source, output, diagnostic, strict=True)
            self.assertEqual(len(stats.warning_examples), 20)
            self.assertEqual(len(diagnostic.read_text().splitlines()), 30)


if __name__ == "__main__":
    unittest.main()
