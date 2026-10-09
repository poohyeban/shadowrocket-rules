import contextlib
import io
import json
import tempfile
import unittest
import ipaddress
from unittest.mock import patch
from pathlib import Path

from scripts.build_claude import SOURCES, TARGET_ASNS, build
from scripts.convert_asn import collect_asn_networks
from scripts.merge_rules import validate_pair
from scripts.source_utils import pinned_inputs, sha


class ClaudeBuildTests(unittest.TestCase):
    def prepare(self, root, content):
        cache = root / "build/claude"
        cache.mkdir(parents=True)
        data = content.encode()
        (cache / "anthropic").write_bytes(data)
        repo, path = SOURCES["anthropic"]
        entry = {"commit": "a" * 40,
                 "url": f"https://raw.githubusercontent.com/{repo}/{'a' * 40}/{path}",
                 "sha256": sha(data)}
        (cache / "inputs.json").write_text(json.dumps({"anthropic": entry}))
        return cache

    def test_offline_build_is_deterministic_and_preserves_exact_cdn_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.prepare(root, "claude.ai\nanthropic.com\nfull:cdn.example.net\n")
            (root / "build/GeoLite2-ASN.mmdb").write_bytes(b"test database")
            result = collect_asn_networks([
                (ipaddress.ip_network("192.0.2.0/24"), {"autonomous_system_number": 399358}),
                (ipaddress.ip_network("2001:db8::/32"), {"autonomous_system_number": 399358}),
                (ipaddress.ip_network("198.51.100.0/24"), {"autonomous_system_number": 16509}),
            ], TARGET_ASNS)
            with contextlib.redirect_stdout(io.StringIO()), patch(
                "scripts.build_claude.extract_asn_networks", return_value=result
            ):
                first = build(root, offline=True)
                second = build(root, offline=True)
            self.assertEqual(first, second)
            self.assertEqual((root / "rules/Claude/Claude.list").read_text(),
                             "DOMAIN,cdn.example.net\nDOMAIN-SUFFIX,anthropic.com\nDOMAIN-SUFFIX,claude.ai\n"
                             "IP-CIDR,192.0.2.0/24\nIP-CIDR,2001:db8::/32\n")
            self.assertEqual(first["domain_count"], 3)
            self.assertEqual(first["ip_count"], 2)
            self.assertEqual(first["asn_source"]["target_asns"], [399358])
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(validate_pair(root / "rules/Claude/Claude.list",
                                               root / "rules/Claude/Claude-NoResolve.list"), (3, 2))

    def test_corrupt_cache_fails_before_publishing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cache = self.prepare(root, "claude.ai\n")
            (cache / "anthropic").write_text("changed.example\n")
            with self.assertRaises(ValueError):
                build(root, offline=True)
            self.assertFalse((root / "rules").exists())

    def test_include_or_invalid_source_fails_before_publishing(self):
        for content in ("claude.ai\ninclude:other", "claude.ai\nunknown:other", "# empty"):
            with self.subTest(content=content), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.prepare(root, content)
                with self.assertRaises(ValueError):
                    build(root, offline=True)
                self.assertFalse((root / "rules").exists())

    def test_cache_url_must_be_the_original_upstream(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cache = self.prepare(root, "claude.ai\n")
            path = cache / "inputs.json"
            manifest = json.loads(path.read_text())
            manifest["anthropic"]["url"] = "https://unrelated.example/source"
            path.write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):
                pinned_inputs(SOURCES, cache, offline=True)

    def test_multiple_files_from_one_repository_require_the_same_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            sources, manifest = {}, {}
            for name, commit in (("first", "a" * 40), ("second", "b" * 40)):
                sources[name] = ("v2fly/domain-list-community", "data/" + name)
                (cache / name).write_bytes(b"example.com\n")
                manifest[name] = {"commit": commit, "sha256": sha(b"example.com\n"),
                                  "url": f"https://raw.githubusercontent.com/v2fly/domain-list-community/{commit}/data/{name}"}
            (cache / "inputs.json").write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):
                pinned_inputs(sources, cache, offline=True)
