from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[1]
WORKFLOW = REPOSITORY / ".github" / "workflows" / "update.yml"
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


if __name__ == "__main__":
    unittest.main()
