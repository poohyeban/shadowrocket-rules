from __future__ import annotations

import unittest

from scripts.rule_utils import (
    DomainRule,
    ExpansionLimitError,
    UnsafeRegexError,
    expand_safe_hostname_regex,
    normalize_hostname,
    rules_intersect,
)


class HostnameValidationTests(unittest.TestCase):
    def test_normal_domain_is_lowercased(self):
        self.assertEqual(normalize_hostname("Example.COM"), "example.com")

    def test_punycode_domain_is_accepted(self):
        self.assertEqual(normalize_hostname("xn--fsqu00a.xn--0zwm56d"), "xn--fsqu00a.xn--0zwm56d")

    def test_unicode_domain_is_not_implicitly_rewritten(self):
        self.assertIsNone(normalize_hostname("例子.测试"))

    def test_ip_literals_are_not_domains(self):
        self.assertIsNone(normalize_hostname("192.0.2.1"))
        self.assertIsNone(normalize_hostname("2001:db8::1"))

    def test_invalid_labels_are_rejected(self):
        self.assertIsNone(normalize_hostname("-bad.example"))
        self.assertIsNone(normalize_hostname("bad_.example"))


class FiniteRegexExpansionTests(unittest.TestCase):
    def test_alternation_is_exactly_expanded(self):
        self.assertEqual(
            expand_safe_hostname_regex(r"^(foo|bar)\.example\.com$"),
            ["bar.example.com", "foo.example.com"],
        )

    def test_digit_range_is_exactly_expanded(self):
        values = expand_safe_hostname_regex(r"^ads[0-9]\.example\.com$")
        self.assertEqual(len(values), 10)
        self.assertIn("ads0.example.com", values)
        self.assertIn("ads9.example.com", values)

    def test_bounded_quantifier_is_expanded(self):
        self.assertEqual(
            expand_safe_hostname_regex(r"^a[0-1]{1,2}\.example$"),
            ["a0.example", "a00.example", "a01.example", "a1.example", "a10.example", "a11.example"],
        )

    def test_optional_group_is_finite(self):
        self.assertEqual(
            expand_safe_hostname_regex(r"^www(1)?\.example\.com$"),
            ["www.example.com", "www1.example.com"],
        )

    def test_unbounded_quantifier_is_skipped(self):
        with self.assertRaises(UnsafeRegexError):
            expand_safe_hostname_regex(r"^example\d+\.com$")

    def test_unanchored_regex_is_skipped(self):
        with self.assertRaises(UnsafeRegexError):
            expand_safe_hostname_regex(r"example[0-9]")

    def test_dot_wildcard_is_not_guessed_as_domain_wildcard(self):
        with self.assertRaises(UnsafeRegexError):
            expand_safe_hostname_regex(r"^example.*\.com$")

    def test_expansion_limit_is_enforced(self):
        with self.assertRaises(ExpansionLimitError):
            expand_safe_hostname_regex(r"^[0-9]{3}\.example$", max_expansions=999)

    def test_non_hostname_expansion_rejects_entire_regex(self):
        with self.assertRaises(UnsafeRegexError):
            expand_safe_hostname_regex(r"^(good\.example|bad_)$")


class RuleIntersectionTests(unittest.TestCase):
    def test_suffix_exception_intersects_ancestor_block(self):
        self.assertTrue(
            rules_intersect(
                DomainRule("DOMAIN-SUFFIX", "example.com"),
                DomainRule("DOMAIN-SUFFIX", "safe.example.com"),
            )
        )

    def test_unrelated_rules_do_not_intersect(self):
        self.assertFalse(
            rules_intersect(
                DomainRule("DOMAIN-SUFFIX", "example.com"),
                DomainRule("DOMAIN", "example.net"),
            )
        )


if __name__ == "__main__":
    unittest.main()
