from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from scripts.convert_openai_official_domains import (
    OfficialDomainError,
    convert_file,
    parse_file,
)


REPOSITORY = Path(__file__).resolve().parents[1]
BUILD = REPOSITORY / "build"
OFFICIAL_SOURCE = REPOSITORY / "data" / "OpenAI" / "official-domains.txt"
OFFICIAL_EXCLUSIONS = (
    REPOSITORY / "data" / "OpenAI" / "official-domains-excluded.txt"
)


class OfficialDomainConversionTests(unittest.TestCase):
    def convert(self, content: str, exclusions: str | None = None):
        BUILD.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=BUILD) as directory:
            root = Path(directory)
            source = root / "official.txt"
            exclude_file = root / "excluded.txt"
            output = root / "official.list"
            with source.open("w", encoding="utf-8", newline="\n") as source_file:
                source_file.write(content)
            if exclusions is not None:
                with exclude_file.open(
                    "w", encoding="utf-8", newline="\n"
                ) as exclusion_output:
                    exclusion_output.write(exclusions)
            with contextlib.redirect_stdout(io.StringIO()):
                stats = convert_file(
                    source,
                    output,
                    exclude_file if exclusions is not None else None,
                )
            return output.read_bytes(), stats

    def test_comments_exact_domains_and_wildcards(self):
        output, stats = self.convert(
            "# reviewed snapshot\n\nAndroid.Chat.OpenAI.com\n*.Intercom.IO\n"
        )
        self.assertEqual(
            output,
            b"DOMAIN,android.chat.openai.com\n"
            b"DOMAIN-WILDCARD,*.intercom.io\n",
        )
        self.assertEqual(stats.source_entries, 2)
        self.assertNotIn(b"reviewed", output)

    def test_invalid_hostname_fails_closed(self):
        for value in (
            "bad_.example",
            "https://openai.com",
            "openai.com/path",
            "192.0.2.1",
        ):
            with self.subTest(value=value):
                with self.assertRaises(OfficialDomainError):
                    self.convert(value + "\n")

    def test_malformed_wildcard_fails_closed(self):
        for value in ("*openai.com", "foo.*.openai.com", "**.openai.com", "*."):
            with self.subTest(value=value):
                with self.assertRaises(OfficialDomainError):
                    self.convert(value + "\n")

    def test_deduplication_and_sort_are_deterministic(self):
        content = "b.example\n*.z.example\na.example\nB.EXAMPLE\n"
        first, stats = self.convert(content)
        second, _ = self.convert(content)
        self.assertEqual(first, second)
        self.assertEqual(
            first,
            b"DOMAIN,a.example\n"
            b"DOMAIN,b.example\n"
            b"DOMAIN-WILDCARD,*.z.example\n",
        )
        self.assertEqual(stats.duplicate_entries, 1)

    def test_output_is_utf8_lf_without_timestamp(self):
        output, _ = self.convert("example.com\r\n")
        self.assertEqual(output, b"DOMAIN,example.com\n")
        self.assertNotIn(b"Generated", output)
        self.assertNotIn(b"2026", output)

    def test_exclusion_removes_only_the_exact_source_entry(self):
        output, stats = self.convert(
            "*.openai.com\nchallenges.cloudflare.com\nchat.openai.com\n",
            "challenges.cloudflare.com\n",
        )
        self.assertEqual(
            output,
            b"DOMAIN,chat.openai.com\n"
            b"DOMAIN-WILDCARD,*.openai.com\n",
        )
        self.assertEqual(stats.excluded_entries, 1)
        self.assertEqual(stats.final_rules, 2)

    def test_completely_empty_exclusion_file_excludes_nothing(self):
        output, stats = self.convert(
            "openai.com\nchatgpt.com\n",
            "",
        )
        self.assertEqual(
            output,
            b"DOMAIN,chatgpt.com\nDOMAIN,openai.com\n",
        )
        self.assertEqual(stats.source_entries, 2)
        self.assertEqual(stats.excluded_entries, 0)
        self.assertEqual(stats.final_rules, 2)

    def test_comments_only_exclusion_file_excludes_nothing(self):
        output, stats = self.convert(
            "openai.com\nchatgpt.com\n",
            "# No exclusions currently.\n\n"
            "# Keep this file for reviewed routing policy.\n",
        )
        self.assertEqual(
            output,
            b"DOMAIN,chatgpt.com\nDOMAIN,openai.com\n",
        )
        self.assertEqual(stats.excluded_entries, 0)
        self.assertEqual(stats.final_rules, 2)

    def test_blank_lines_only_exclusion_file_excludes_nothing(self):
        output, stats = self.convert(
            "openai.com\nchatgpt.com\n",
            "\n\n   \n",
        )
        self.assertEqual(
            output,
            b"DOMAIN,chatgpt.com\nDOMAIN,openai.com\n",
        )
        self.assertEqual(stats.excluded_entries, 0)
        self.assertEqual(stats.final_rules, 2)

    def test_official_source_still_may_not_be_empty(self):
        for content in ("", "\n\n", "# comment only\n"):
            with self.subTest(content=content):
                with self.assertRaises(OfficialDomainError):
                    self.convert(content)

    def test_exclusion_does_not_expand_or_infer_suffix_matches(self):
        output, _ = self.convert(
            "*.intercom.io\nfoo.intercom.io\n",
            "*.intercom.io\n",
        )
        self.assertEqual(output, b"DOMAIN,foo.intercom.io\n")

    def test_exclusion_must_be_a_subset_of_the_official_source(self):
        with self.assertRaisesRegex(
            OfficialDomainError,
            "exclusions are not present in the source snapshot",
        ):
            self.convert("openai.com\n", "foo.example.com\n")

    def test_exclusion_comments_and_blank_lines_are_allowed(self):
        output, _ = self.convert(
            "openai.com\nchat.openai.com\n",
            "# policy exclusion\n\nchat.openai.com # reviewed\n",
        )
        self.assertEqual(output, b"DOMAIN,openai.com\n")

    def test_exclusion_matching_is_case_insensitive_after_normalization(self):
        output, _ = self.convert(
            "OpenAI.com\nChat.OpenAI.com\n",
            "CHAT.OPENAI.COM\n",
        )
        self.assertEqual(output, b"DOMAIN,openai.com\n")

    def test_malformed_exclusion_hostname_fails_closed(self):
        for value in (
            "https://openai.com",
            "openai.com/path",
            "192.0.2.1",
            "foo.*.openai.com",
        ):
            with self.subTest(value=value):
                with self.assertRaises(OfficialDomainError):
                    self.convert("openai.com\n", value + "\n")

    def test_repository_snapshot_contains_exactly_29_entries(self):
        BUILD.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=BUILD) as directory:
            output = Path(directory) / "official.list"
            with contextlib.redirect_stdout(io.StringIO()):
                stats = convert_file(OFFICIAL_SOURCE, output)
            self.assertEqual(stats.source_entries, 29)
            self.assertEqual(stats.final_rules, 29)
            self.assertEqual(len(output.read_text(encoding="utf-8").splitlines()), 29)

    def test_repository_exclusions_and_filtered_generation_match(self):
        source_rules, source_entries = parse_file(
            OFFICIAL_SOURCE, "official domain source"
        )
        excluded_rules, excluded_entries = parse_file(
            OFFICIAL_EXCLUSIONS, "official domain exclusion source"
        )

        self.assertEqual(source_entries, 29)
        self.assertEqual(excluded_entries, 16)
        self.assertTrue(excluded_rules <= source_rules)

        BUILD.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=BUILD) as directory:
            output = Path(directory) / "official.list"
            with contextlib.redirect_stdout(io.StringIO()):
                stats = convert_file(
                    OFFICIAL_SOURCE,
                    output,
                    OFFICIAL_EXCLUSIONS,
                )

            expected = sorted(rule.render() for rule in source_rules - excluded_rules)
            actual = output.read_text(encoding="utf-8").splitlines()
            self.assertEqual(actual, expected)
            self.assertEqual(stats.excluded_entries, 16)
            self.assertEqual(stats.final_rules, 13)
            self.assertEqual(len(actual), 13)


if __name__ == "__main__":
    unittest.main()
