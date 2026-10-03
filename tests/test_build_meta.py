import unittest
from scripts.build_meta import primary_rules


class MetaConversionTests(unittest.TestCase):
    def test_native_converter_preserves_exact_suffix_and_finite_regex(self):
        rules, skipped = primary_rules("full:api.example\nexample.com @ads\nregexp:^(a|b)\\.example$\n")
        self.assertEqual(rules, {("full", "api.example"), ("domain", "example.com"),
                                 ("full", "a.example"), ("full", "b.example")})
        self.assertFalse(skipped)

    def test_unresolved_or_malformed_source_aborts(self):
        for text in ("include:facebook", "Include:facebook", "example.com\nunknown:example.net",
                     "example.com\nfull:invalid/path", "# empty"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                primary_rules(text)

    def test_every_unsupported_regex_is_reported(self):
        rules, skipped = primary_rules("example.com\n" + "regexp:^.+\\.example$\n" * 30)
        self.assertEqual(rules, {("domain", "example.com")})
        self.assertEqual(len(skipped), 30)


if __name__ == "__main__":
    unittest.main()
