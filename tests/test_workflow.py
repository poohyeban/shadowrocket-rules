from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[1]
WORKFLOW = REPOSITORY / ".github" / "workflows" / "update.yml"
README = REPOSITORY / "README.md"
INCLUDE_PATTERN = r"^[[:space:]]*include:[A-Za-z0-9!-]+([[:space:]]|#|$)"


class WorkflowGuardTests(unittest.TestCase):
    def test_openai_include_guard_is_case_insensitive_and_specific(self):
        source = (
            "include:foo\n"
            "Include:foo\n"
            "INCLUDE:foo\n"
            "domain:include.example\n"
            "full:include.example\n"
            "keyword:include\n"
        )
        result = subprocess.run(
            ["grep", "-niE", INCLUDE_PATTERN],
            input=source,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.splitlines(),
            ["1:include:foo", "2:Include:foo", "3:INCLUDE:foo"],
        )

    def test_workflow_uses_case_insensitive_include_guard(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("if grep -niE \\\n", workflow)
        self.assertIn(f"'{INCLUDE_PATTERN}'", workflow)
        self.assertIn("build/openai-v2fly.txt > build/openai-includes.txt", workflow)

    def test_workflow_uses_local_reviewed_official_domain_source(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("data/OpenAI/official-domains.txt", workflow)
        self.assertIn("data/OpenAI/official-domains-excluded.txt", workflow)
        self.assertIn("scripts/convert_openai_official_domains.py", workflow)
        self.assertIn(
            "rules/OpenAI/Sources/OpenAI-Official-Domain.list \\\n"
            "            --exclude-file data/OpenAI/official-domains-excluded.txt",
            workflow,
        )
        self.assertNotIn("help.openai.com", workflow)

    def test_workflow_uses_only_explicit_openai_asns(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("--asn 401518", workflow)
        self.assertIn("--asn 401864", workflow)
        self.assertNotIn("--asn 8075", workflow)
        self.assertNotIn("--asn 20473", workflow)

    def test_workflow_builds_new_openai_sources_and_aggregates(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        expected_paths = (
            "rules/OpenAI/Sources/OpenAI-v2fly.list",
            "rules/OpenAI/Sources/OpenAI-Official-Domain.list",
            "rules/OpenAI/Sources/OpenAI-ASN-IP.list",
            "rules/OpenAI/Sources/OpenAI-ASN-IP-NoResolve.list",
            "rules/OpenAI/Sources/OpenAI-Voice-IP.list",
            "rules/OpenAI/Sources/OpenAI-Voice-IP-NoResolve.list",
            "rules/OpenAI/OpenAI.list",
            "rules/OpenAI/OpenAI-NoResolve.list",
        )
        for path in expected_paths:
            with self.subTest(path=path):
                self.assertIn(path, workflow)

        self.assertNotIn("scripts/filter_v2fly.py", workflow)
        self.assertNotIn("OpenAI-Ads.list", workflow)
        self.assertNotIn("OpenAI-NoAds.list", workflow)

    def test_workflow_builds_china_sources_and_aggregates(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        expected_paths = (
            "rules/China/Sources/China-v2fly-Domain.list",
            "rules/China/Sources/China-GeoIP.list",
            "rules/China/Sources/China-GeoIP-NoResolve.list",
            "rules/China/China.list",
            "rules/China/China-NoResolve.list",
        )
        for path in expected_paths:
            with self.subTest(path=path):
                self.assertIn(path, workflow)

        self.assertIn(
            "python scripts/merge_rules.py validate-pair \\\n"
            "            rules/China/China.list \\\n"
            "            rules/China/China-NoResolve.list",
            workflow,
        )

    def test_workflow_and_readme_do_not_reference_legacy_china_paths(self):
        content = WORKFLOW.read_text(encoding="utf-8") + README.read_text(
            encoding="utf-8"
        )
        legacy_paths = (
            "rules/China/China-Domain.list",
            "rules/China/GeoIP-CN.list",
            "rules/China/GeoIP-CN-NoResolve.list",
        )
        for path in legacy_paths:
            with self.subTest(path=path):
                self.assertNotIn(path, content)


if __name__ == "__main__":
    unittest.main()
