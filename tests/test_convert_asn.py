from __future__ import annotations

import ipaddress
import tempfile
import unittest
from pathlib import Path

from scripts.convert_asn import collect_asn_networks, write_rules


REPOSITORY = Path(__file__).resolve().parents[1]
BUILD = REPOSITORY / "build"


class ASNConversionTests(unittest.TestCase):
    def records(self):
        return [
            (
                ipaddress.ip_network("2001:db8:1::/48"),
                {"autonomous_system_number": 401864},
            ),
            (
                ipaddress.ip_network("198.51.100.0/24"),
                {"autonomous_system_number": 401518},
            ),
            (
                ipaddress.ip_network("192.0.2.0/24"),
                {"autonomous_system_number": 401518},
            ),
            (
                ipaddress.ip_network("203.0.113.0/24"),
                {"autonomous_system_number": 8075},
            ),
        ]

    def test_target_asns_include_ipv4_and_ipv6_but_not_other_asns(self):
        result = collect_asn_networks(self.records(), [401518, 401864])
        self.assertEqual(
            [str(network) for network in result.ipv4_networks],
            ["192.0.2.0/24", "198.51.100.0/24"],
        )
        self.assertEqual(
            [str(network) for network in result.ipv6_networks],
            ["2001:db8:1::/48"],
        )
        rendered = [
            str(network)
            for networks in result.networks_by_asn.values()
            for network in networks
        ]
        self.assertNotIn("203.0.113.0/24", rendered)

    def test_individual_target_asn_may_have_zero_networks(self):
        result = collect_asn_networks(self.records()[:1], [401518, 401864])
        self.assertEqual(result.networks_by_asn[401518], ())
        self.assertEqual(len(result.networks_by_asn[401864]), 1)

    def test_all_target_asns_zero_fails_closed(self):
        with self.assertRaises(RuntimeError):
            collect_asn_networks(self.records(), [64500, 64501])

    def test_output_is_deterministic_and_has_no_resolve_variant(self):
        first = collect_asn_networks(self.records(), [401518, 401864])
        second = collect_asn_networks(reversed(self.records()), [401864, 401518])
        self.assertEqual(first.ipv4_networks, second.ipv4_networks)
        self.assertEqual(first.ipv6_networks, second.ipv6_networks)

        BUILD.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=BUILD) as directory:
            root = Path(directory)
            regular = root / "regular.list"
            no_resolve = root / "no-resolve.list"
            write_rules(
                regular,
                first.ipv4_networks,
                first.ipv6_networks,
                no_resolve=False,
            )
            write_rules(
                no_resolve,
                first.ipv4_networks,
                first.ipv6_networks,
                no_resolve=True,
            )
            self.assertEqual(
                regular.read_text(encoding="utf-8"),
                "IP-CIDR,192.0.2.0/24\n"
                "IP-CIDR,198.51.100.0/24\n"
                "IP-CIDR6,2001:db8:1::/48\n",
            )
            self.assertEqual(
                no_resolve.read_text(encoding="utf-8"),
                "IP-CIDR,192.0.2.0/24,no-resolve\n"
                "IP-CIDR,198.51.100.0/24,no-resolve\n"
                "IP-CIDR6,2001:db8:1::/48,no-resolve\n",
            )

    def test_duplicate_networks_are_removed(self):
        records = self.records()
        records.append(records[1])
        result = collect_asn_networks(records, [401518, 401864])
        self.assertEqual(len(result.ipv4_networks), 2)


if __name__ == "__main__":
    unittest.main()
