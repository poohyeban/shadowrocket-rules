import ipaddress
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.convert_geoip import extract_cn_networks, write_rules


class GeoIPConversionTests(unittest.TestCase):
    def test_selects_country_cn_and_collapses_without_including_other_countries(self):
        records = [
            (ipaddress.ip_network("192.0.2.0/25"), {"country": {"iso_code": "CN"}}),
            (ipaddress.ip_network("192.0.2.128/25"), {"country": {"iso_code": "CN"}}),
            (ipaddress.ip_network("2001:db8::/32"), {"country": {"iso_code": "CN"}}),
            (ipaddress.ip_network("198.51.100.0/24"), {"country": {"iso_code": "US"}}),
        ]
        with patch("scripts.convert_geoip.maxminddb.open_database") as database:
            database.return_value.__enter__.return_value = records
            ipv4, ipv6 = extract_cn_networks(Path("unused.mmdb"))
        self.assertEqual([str(value) for value in ipv4], ["192.0.2.0/24"])
        self.assertEqual([str(value) for value in ipv6], ["2001:db8::/32"])

    def test_ipv6_uses_ip_cidr_in_both_variants(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "geo.list"
            for no_resolve in (False, True):
                write_rules(path, [], [ipaddress.ip_network("2001:db8::/32")], no_resolve)
                modifier = ",no-resolve" if no_resolve else ""
                self.assertEqual(path.read_text(), f"IP-CIDR,2001:db8::/32{modifier}\n")
