from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from scripts.convert_openai_official_domains import (
    OfficialDomainError,
    convert_file,
)


REPOSITORY = Path(__file__).resolve().parents[1]
BUILD = REPOSITORY / "build"
OFFICIAL_SOURCE = REPOSITORY / "data" / "OpenAI" / "official-domains.txt"


class OfficialDomainConversionTests(unittest.TestCase):
    def convert(self, content: str):
        BUILD.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=BUILD) as directory:
            root = Path(directory)
            source = root / "official.txt"
            output = root / "official.list"
            with source.open("w", encoding="utf-8", newline="\n") as source_file:
                source_file.write(content)
            with contextlib.redirect_stdout(io.StringIO()):
                stats = convert_file(source, output)
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

    def test_repository_snapshot_contains_exactly_29_entries(self):
        BUILD.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=BUILD) as directory:
            output = Path(directory) / "official.list"
            with contextlib.redirect_stdout(io.StringIO()):
                stats = convert_file(OFFICIAL_SOURCE, output)
            self.assertEqual(stats.source_entries, 29)
            self.assertEqual(stats.final_rules, 29)
            self.assertEqual(len(output.read_text(encoding="utf-8").splitlines()), 29)


if __name__ == "__main__":
    unittest.main()
