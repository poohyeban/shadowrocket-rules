#!/usr/bin/env python3

import argparse
import ipaddress
from pathlib import Path

import maxminddb


def extract_cn_networks(database: Path):
    ipv4_networks = []
    ipv6_networks = []

    with maxminddb.open_database(database) as reader:
        for network, record in reader:
            if not record:
                continue

            country = record.get("country") or {}
            country_code = country.get("iso_code")

            if country_code != "CN":
                continue

            if network.version == 4:
                ipv4_networks.append(network)
            else:
                ipv6_networks.append(network)

    # 合并能够安全合并的相邻 CIDR，减少规则数量
    ipv4_networks = list(ipaddress.collapse_addresses(ipv4_networks))
    ipv6_networks = list(ipaddress.collapse_addresses(ipv6_networks))

    return ipv4_networks, ipv6_networks


def write_rules(
    output: Path,
    ipv4_networks,
    ipv6_networks,
    no_resolve: bool = False,
):
    output.parent.mkdir(parents=True, exist_ok=True)

    suffix = ",no-resolve" if no_resolve else ""

    with output.open("w", encoding="utf-8", newline="\n") as f:
        for network in ipv4_networks:
            f.write(f"IP-CIDR,{network}{suffix}\n")

        for network in ipv6_networks:
            f.write(f"IP-CIDR6,{network}{suffix}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Convert GeoLite2 Country MMDB CN networks "
        "to Shadowrocket RULE-SET format."
    )

    parser.add_argument(
        "database",
        type=Path,
        help="Path to GeoLite2-Country.mmdb",
    )

    parser.add_argument(
        "output",
        type=Path,
        help="Output GeoIP-CN.list",
    )

    parser.add_argument(
        "output_no_resolve",
        type=Path,
        help="Output GeoIP-CN-NoResolve.list",
    )

    args = parser.parse_args()

    if not args.database.is_file():
        parser.error(f"Database does not exist: {args.database}")

    ipv4_networks, ipv6_networks = extract_cn_networks(args.database)

    if not ipv4_networks:
        raise RuntimeError("No CN IPv4 networks found")

    if not ipv6_networks:
        raise RuntimeError("No CN IPv6 networks found")

    write_rules(
        args.output,
        ipv4_networks,
        ipv6_networks,
        no_resolve=False,
    )

    write_rules(
        args.output_no_resolve,
        ipv4_networks,
        ipv6_networks,
        no_resolve=True,
    )

    print(f"IPv4 networks: {len(ipv4_networks)}")
    print(f"IPv6 networks: {len(ipv6_networks)}")
    print(f"Generated: {args.output}")
    print(f"Generated: {args.output_no_resolve}")


if __name__ == "__main__":
    main()
