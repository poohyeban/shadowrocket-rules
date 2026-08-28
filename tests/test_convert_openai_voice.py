from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from scripts.convert_openai_voice import (
    VoiceDataError,
    convert_file,
    load_voice_data,
    parse_voice_payload,
)


REPOSITORY = Path(__file__).resolve().parents[1]
BUILD = REPOSITORY / "build"


def payload(prefixes):
    return {
        "creationTime": "2026-08-28T00:00:00+00:00",
        "prefixes": prefixes,
    }


class VoiceConversionTests(unittest.TestCase):
    def test_valid_ipv4_ipv6_are_canonicalized_and_sorted(self):
        data = parse_voice_payload(
            payload(
                [
                    {"ipv6Prefix": "2001:db8:1::1/48"},
                    {"ipv4Prefix": "198.51.100.9/24"},
                    {"ipv4Prefix": "192.0.2.0/24"},
                ]
            )
        )
        self.assertEqual(
            [str(network) for network in data.ipv4_networks],
            ["192.0.2.0/24", "198.51.100.0/24"],
        )
        self.assertEqual(
            [str(network) for network in data.ipv6_networks],
            ["2001:db8:1::/48"],
        )

    def test_duplicate_prefixes_are_removed(self):
        data = parse_voice_payload(
            payload(
                [
                    {"ipv4Prefix": "192.0.2.1/24"},
                    {"ipv4Prefix": "192.0.2.0/24"},
                ]
            )
        )
        self.assertEqual(len(data.ipv4_networks), 1)
        self.assertEqual(data.duplicate_prefixes, 1)

    def test_malformed_cidr_fails_closed(self):
        for value in ("not-a-network", "192.0.2.1", "999.0.0.0/24"):
            with self.subTest(value=value):
                with self.assertRaises(VoiceDataError):
                    parse_voice_payload(payload([{"ipv4Prefix": value}]))

    def test_malformed_json_fails_closed(self):
        BUILD.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=BUILD) as directory:
            source = Path(directory) / "voice.json"
            source.write_text('{"prefixes": [', encoding="utf-8")
            with self.assertRaises(VoiceDataError):
                load_voice_data(source)

    def test_missing_non_array_and_empty_prefixes_fail_closed(self):
        cases = (
            {"creationTime": "2026-08-28T00:00:00+00:00"},
            payload("192.0.2.0/24"),
            payload([]),
        )
        for case in cases:
            with self.subTest(case=case):
                with self.assertRaises(VoiceDataError):
                    parse_voice_payload(case)

    def test_wrong_prefix_schema_or_version_fails_closed(self):
        cases = (
            payload(["192.0.2.0/24"]),
            payload([{"prefix": "192.0.2.0/24"}]),
            payload([{"ipv4Prefix": "2001:db8::/32"}]),
            payload([{"ipv4Prefix": "192.0.2.0/24", "region": "test"}]),
        )
        for case in cases:
            with self.subTest(case=case):
                with self.assertRaises(VoiceDataError):
                    parse_voice_payload(case)

    def test_creation_time_must_be_valid_and_timezone_aware(self):
        for value in (None, "", "not-a-time", "2026-08-28T00:00:00"):
            case = payload([{"ipv4Prefix": "192.0.2.0/24"}])
            case["creationTime"] = value
            with self.subTest(value=value):
                with self.assertRaises(VoiceDataError):
                    parse_voice_payload(case)

    def test_regular_and_no_resolve_outputs(self):
        BUILD.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=BUILD) as directory:
            root = Path(directory)
            source = root / "voice.json"
            regular = root / "voice.list"
            no_resolve = root / "voice-no-resolve.list"
            source.write_text(
                json.dumps(
                    payload(
                        [
                            {"ipv6Prefix": "2001:db8::/32"},
                            {"ipv4Prefix": "192.0.2.0/24"},
                        ]
                    )
                ),
                encoding="utf-8",
            )
            with contextlib.redirect_stdout(io.StringIO()):
                data = convert_file(source, regular, no_resolve)
            self.assertEqual(data.creation_time, "2026-08-28T00:00:00+00:00")
            self.assertEqual(
                regular.read_bytes(),
                b"IP-CIDR,192.0.2.0/24\nIP-CIDR6,2001:db8::/32\n",
            )
            self.assertEqual(
                no_resolve.read_bytes(),
                b"IP-CIDR,192.0.2.0/24,no-resolve\n"
                b"IP-CIDR6,2001:db8::/32,no-resolve\n",
            )
            self.assertNotIn(b"creationTime", regular.read_bytes())


if __name__ == "__main__":
    unittest.main()
