import unittest

from scripts.meta_common import SERVICES, compact, covers, select_sukka


class MetaSelectionTests(unittest.TestCase):
    def setUp(self):
        self.primary = {service: {("domain", service.lower() + ".example")} for service in SERVICES}
        self.review = {"additions": {"DOMAIN-SUFFIX,ig.example": "Instagram"}, "excluded": {}}

    def test_scope_separation_and_unclassified_domains(self):
        text = """# >> Other
DOMAIN-SUFFIX,other.example
# >> Facebook
DOMAIN-SUFFIX,facebook.example
DOMAIN-SUFFIX,cdn.instagram.example
DOMAIN-SUFFIX,ig.example
# WhatsApp
DOMAIN-SUFFIX,whatsapp.example
DOMAIN-KEYWORD,facebook
DOMAIN-SUFFIX,unknown.example
# >> Twitter
DOMAIN-SUFFIX,twitter.example
"""
        result, report = select_sukka(text, self.primary, self.review)
        self.assertEqual(result["Facebook"], self.primary["Facebook"])
        self.assertEqual(result["WhatsApp"], self.primary["WhatsApp"])
        self.assertEqual(result["Instagram"], {("domain", "cdn.instagram.example"), ("domain", "ig.example")})
        self.assertEqual(len(report["skipped"]), 2)

    def test_review_mapping_does_not_reinject_removed_rules(self):
        result, report = select_sukka("# >> Facebook\nDOMAIN-SUFFIX,facebook.example", self.primary, self.review)
        self.assertEqual(result["Instagram"], set())
        self.assertEqual(report["review_entries_absent_upstream"], 1)

    def test_keyword_primary_does_not_classify_unrelated_domains(self):
        self.primary["Facebook"].add(("keyword", "facebook"))
        result, report = select_sukka("# >> Facebook\nDOMAIN-SUFFIX,notfacebook.example", self.primary, self.review)
        self.assertFalse(result["Facebook"])
        self.assertEqual(len(report["skipped"]), 1)

    def test_exclusion_overrides_primary(self):
        self.review["excluded"]["DOMAIN-SUFFIX,facebook.example"] = "outside scope"
        result, _ = select_sukka("# >> Facebook\nDOMAIN-SUFFIX,facebook.example", self.primary, self.review)
        self.assertFalse(result["Facebook"])

    def test_broken_section_and_policy_or_unknown_syntax_fail(self):
        for text in ("# >> Other\nDOMAIN,example.com", "# >> Facebook",
                     "# >> Facebook\nDOMAIN,example.com\n# >> Facebook\nDOMAIN,example.com",
                     "# >> Facebook\nDOMAIN,example.com,PROXY", "# >> Facebook\nUNKNOWN,example.com",
                     "# >> Facebook\nDOMAIN-SUFFIX,example.com/path"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                select_sukka(text, self.primary, self.review)

    def test_ambiguous_assignment_fails(self):
        self.primary["Instagram"] |= self.primary["Facebook"]
        with self.assertRaises(ValueError):
            select_sukka("# >> Facebook\nDOMAIN-SUFFIX,facebook.example", self.primary, self.review)

    def test_compaction_preserves_exact_regex_and_keyword(self):
        rules = {("domain", "example.com"), ("full", "www.example.com"),
                 ("domain", "cdn.example.com"), ("full", "exact.test"),
                 ("regexp", r"^r[0-9]+\.test$"), ("keyword", "needle")}
        self.assertEqual(compact(rules), rules - {("full", "www.example.com"), ("domain", "cdn.example.com")})
        self.assertFalse(covers(("full", "exact.test"), ("domain", "exact.test")))
        self.assertFalse(covers(("domain", "example.com"), ("domain", "notexample.com")))


if __name__ == "__main__":
    unittest.main()
