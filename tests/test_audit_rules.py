import tempfile
import contextlib
import io
import json
import unittest
from pathlib import Path

from scripts.audit_rules import audit, audit_file
from scripts.merge_rules import RuleValidationError
from scripts.source_utils import sha


class PublishedRuleAuditTests(unittest.TestCase):
    def fixture(self, root):
        outputs = {"AdGuard/Ad-Domain.list": "DOMAIN-SUFFIX,ads.example\n"}
        for service, domains, networks in (
            ("China", ("China-v2fly-Domain",), ("China-GeoIP",)),
            ("OpenAI", ("OpenAI-v2fly", "OpenAI-Official-Domain"),
             ("OpenAI-ASN-IP", "OpenAI-Voice-IP")),
            ("Claude", ("Claude-v2fly",), ("Claude-ASN-IP",)),
        ):
            domain = f"DOMAIN-SUFFIX,{service.lower()}.example\n"
            for name in domains:
                outputs[f"{service}/Sources/{name}.list"] = domain
            for variant, modifier in (("", ""), ("-NoResolve", ",no-resolve")):
                network = f"IP-CIDR,2001:db8::/32{modifier}\n"
                for name in networks:
                    outputs[f"{service}/Sources/{name}{variant}.list"] = network
                outputs[f"{service}/{service}{variant}.list"] = domain + network
        for service in ("WhatsApp", "Instagram", "Facebook"):
            domain = f"DOMAIN-SUFFIX,{service.lower()}.example\n"
            outputs[f"{service}/Sources/{service}-v2fly.list"] = domain
            outputs[f"{service}/{service}.list"] = domain
        for name, data in outputs.items():
            path = root / "rules" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(data)
        (root / "reports").mkdir()
        for name, services in (("meta", {"Facebook", "Instagram", "WhatsApp"}), ("claude", {"Claude"})):
            report = {"outputs": {path: sha(data.encode()) for path, data in outputs.items()
                                  if path.split("/")[0] in services}}
            (root / f"reports/{name}.json").write_text(json.dumps(report))

    def test_valid_aggregates_and_variants_pass_but_stale_aggregate_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertTrue(audit(root)["files"])
            path = root / "rules/China/China.list"
            path.write_text(path.read_text() + "DOMAIN,unrelated.example\n")
            with self.assertRaises(RuleValidationError):
                audit(root)

    def test_provenance_must_cover_all_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            (root / "reports/claude.json").write_text('{"outputs": {}}')
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(RuleValidationError):
                audit(root)

    def test_both_families_use_shadowrocket_ip_cidr(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rules.list"
            path.write_bytes(b"IP-CIDR,192.0.2.0/24\nIP-CIDR,2001:db8::/32,no-resolve\n")
            _, report = audit_file(path)
            self.assertEqual(report["ip_versions"], {"4": 1, "6": 1})

    def test_invalid_published_encoding_duplicates_and_syntax_fail(self):
        for data in (b"", b"DOMAIN,example.com", b"DOMAIN,example.com\r\n",
                     b"\xef\xbb\xbfDOMAIN,example.com\n", b"DOMAIN,example.com\n\n",
                     b"DOMAIN,example.com\nDOMAIN,example.com\n",
                     b"AND,((DOMAIN,example.com))\n", b"IP-CIDR6,2001:db8::/32\n"):
            with self.subTest(data=data), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "rules.list"
                path.write_bytes(data)
                with self.assertRaises(RuleValidationError):
                    audit_file(path)

    def test_missing_required_rulesets_fail(self):
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(RuleValidationError):
            audit(Path(directory))
