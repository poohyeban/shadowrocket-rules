from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.filter_v2fly import filter_file, parse_v2fly_line


REPOSITORY = Path(__file__).resolve().parents[1]
BUILD = REPOSITORY / "build"
SCRIPT = REPOSITORY / "scripts" / "filter_v2fly.py"


class V2FlyAttributeFilterTests(unittest.TestCase):
    def filter(
        self,
        content: str,
        *,
        include_attribute: str | None = None,
        exclude_attribute: str | None = None,
    ):
        BUILD.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=BUILD) as directory:
            root = Path(directory)
            source = root / "source.txt"
            output = root / "output.txt"
            with source.open("w", encoding="utf-8", newline="\n") as source_file:
                source_file.write(content)
            stats = filter_file(
                source,
                output,
                include_attribute=include_attribute,
                exclude_attribute=exclude_attribute,
            )
            return output.read_bytes(), stats

    def test_no_filter_preserves_rules(self):
        output, stats = self.filter("domain:example.com\nfull:www.example.com @ads\n")
        self.assertEqual(
            output,
            b"domain:example.com\nfull:www.example.com @ads\n",
        )
        self.assertEqual(stats.kept_rules, 2)

    def test_exclude_attribute_removes_only_matching_rules(self):
        output, _ = self.filter(
            "domain:example.com\nfull:ads.example.com @ads\n",
            exclude_attribute="ads",
        )
        self.assertEqual(output, b"domain:example.com\n")

    def test_include_attribute_retains_only_matching_rules(self):
        output, _ = self.filter(
            "domain:example.com\nfull:ads.example.com @ads\n",
            include_attribute="ads",
        )
        self.assertEqual(output, b"full:ads.example.com @ads\n")

    def test_multiple_attributes_are_recognized(self):
        output, _ = self.filter(
            "full:example.com @foo @ads\n",
            include_attribute="ads",
        )
        self.assertEqual(output, b"full:example.com @foo @ads\n")

    def test_non_matching_attribute_is_not_misclassified(self):
        output, _ = self.filter(
            "full:example.com @foo\n",
            include_attribute="ads",
        )
        self.assertEqual(output, b"")

    def test_comments_and_blank_lines_are_preserved(self):
        output, stats = self.filter(
            "# heading\n\nfull:example.com @ads # inline\n",
            exclude_attribute="ads",
        )
        self.assertEqual(output, b"# heading\n\n")
        self.assertEqual(stats.passthrough_lines, 2)

    def test_rule_type_does_not_affect_attribute_detection(self):
        for rule_type in ("domain", "full", "keyword", "regexp"):
            with self.subTest(rule_type=rule_type):
                line = f"{rule_type}:example @ads\n"
                parsed = parse_v2fly_line(line)
                self.assertEqual(parsed.attributes, frozenset({"ads"}))

    def test_regexp_text_is_not_modified_or_searched_as_metadata(self):
        regexp = r"regexp:^foo@ads\.(example|test)$"
        output, _ = self.filter(regexp + "\n", exclude_attribute="ads")
        self.assertEqual(output.decode(), regexp + "\n")
        self.assertEqual(parse_v2fly_line(regexp).attributes, frozenset())

    def test_release_style_attributes_are_supported(self):
        line = "example.com:@foo:@ads\n"
        output, _ = self.filter(line, include_attribute="ads")
        self.assertEqual(output, line.encode())
        self.assertEqual(parse_v2fly_line(line).attributes, frozenset({"foo", "ads"}))

    def test_standalone_metadata_is_not_treated_as_a_rule(self):
        output, stats = self.filter(
            "@attributes\n&affiliations\ndomain:example.com &affiliations\n"
        )
        self.assertEqual(output, b"domain:example.com &affiliations\n")
        self.assertEqual(stats.metadata_lines, 2)

    def test_include_and_exclude_cli_options_conflict(self):
        BUILD.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=BUILD) as directory:
            root = Path(directory)
            source = root / "source.txt"
            output = root / "output.txt"
            source.write_text("domain:example.com\n", encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    str(source),
                    str(output),
                    "--include-attribute",
                    "ads",
                    "--exclude-attribute",
                    "ads",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("not allowed with argument", result.stderr)

    def test_output_is_deterministic_lf_utf8(self):
        content = "# 注释\r\ndomain:example.com\r\n"
        first, _ = self.filter(content)
        second, _ = self.filter(content)
        self.assertEqual(first, second)
        self.assertEqual(first, "# 注释\ndomain:example.com\n".encode())


if __name__ == "__main__":
    unittest.main()
