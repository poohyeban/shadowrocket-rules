from __future__ import annotations

import contextlib
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.convert import convert_file
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

    def test_source_attribute_matching_is_case_insensitive(self):
        line = "full:example.com @ADS @Foo123\n"
        for attribute in ("ads", "ADS"):
            with self.subTest(attribute=attribute):
                output, _ = self.filter(line, include_attribute=attribute)
                self.assertEqual(output, line.encode())
        self.assertEqual(
            parse_v2fly_line(line).attributes,
            frozenset({"ads", "foo123"}),
        )

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
        line = "example.com:@ADS,@!CN\n"
        output, _ = self.filter(line, include_attribute="ads")
        self.assertEqual(output, line.encode())
        self.assertEqual(
            parse_v2fly_line(line).attributes,
            frozenset({"ads", "!cn"}),
        )

    def test_bang_attribute_is_supported(self):
        line = "domain:example.com @!CN\n"
        output, _ = self.filter(line, include_attribute="!cn")
        self.assertEqual(output, line.encode())
        self.assertEqual(parse_v2fly_line(line).attributes, frozenset({"!cn"}))

    def test_selective_include_attribute_syntax_is_recognized(self):
        line = "include:another-file @-ATTR @-!CN\n"
        self.assertEqual(
            parse_v2fly_line(line).attributes,
            frozenset({"-attr", "-!cn"}),
        )

    def test_cli_accepts_v2fly_special_attribute_names(self):
        BUILD.mkdir(exist_ok=True)
        cases = (
            ("!cn", "domain:example.com @!cn\n"),
            ("-attr2", "include:another-file @-attr2\n"),
        )
        for attribute, content in cases:
            with self.subTest(attribute=attribute), tempfile.TemporaryDirectory(
                dir=BUILD
            ) as directory:
                root = Path(directory)
                source = root / "source.txt"
                output = root / "output.txt"
                source.write_text(content, encoding="utf-8")
                result = subprocess.run(
                    [
                        sys.executable,
                        str(SCRIPT),
                        str(source),
                        str(output),
                        f"--include-attribute={attribute}",
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(output.read_text(encoding="utf-8"), content)

    def test_cli_attribute_matching_is_case_insensitive(self):
        BUILD.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=BUILD) as directory:
            root = Path(directory)
            source = root / "source.txt"
            included = root / "included.txt"
            excluded = root / "excluded.txt"
            source.write_text(
                "domain:plain.example\nfull:ads.example @ADS\n",
                encoding="utf-8",
            )

            include_result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    str(source),
                    str(included),
                    "--include-attribute",
                    "ADS",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            exclude_result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    str(source),
                    str(excluded),
                    "--exclude-attribute",
                    "ADS",
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(include_result.returncode, 0, include_result.stderr)
            self.assertEqual(exclude_result.returncode, 0, exclude_result.stderr)
            self.assertEqual(
                included.read_text(encoding="utf-8"),
                "full:ads.example @ADS\n",
            )
            self.assertEqual(
                excluded.read_text(encoding="utf-8"),
                "domain:plain.example\n",
            )

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

    def test_ads_subset_may_convert_to_empty_when_every_rule_is_unsupported(self):
        BUILD.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=BUILD) as directory:
            root = Path(directory)
            source = root / "source.txt"
            filtered = root / "ads.txt"
            output = root / "ads.list"
            diagnostic = root / "unsupported.txt"
            regexp = r"regexp:^example\S+\.com$ @ads"
            source.write_text(regexp + "\n", encoding="utf-8")

            filter_stats = filter_file(
                source,
                filtered,
                include_attribute="ads",
            )
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
                io.StringIO()
            ):
                convert_stats = convert_file(
                    filtered,
                    output,
                    unsupported_output=diagnostic,
                )

            self.assertEqual(filter_stats.kept_rules, 1)
            self.assertEqual(convert_stats.regex_skipped, 1)
            self.assertEqual(output.read_bytes(), b"")
            self.assertIn("unsafe-regexp", diagnostic.read_text(encoding="utf-8"))

    def test_output_is_deterministic_lf_utf8(self):
        content = "# 注释\r\ndomain:example.com\r\n"
        first, _ = self.filter(content)
        second, _ = self.filter(content)
        self.assertEqual(first, second)
        self.assertEqual(first, "# 注释\ndomain:example.com\n".encode())


if __name__ == "__main__":
    unittest.main()
