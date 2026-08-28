#!/usr/bin/env python3

"""Convert selected ASN prefixes from a GeoLite2 ASN database to rules."""

from __future__ import annotations

import argparse
import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Union


Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


@dataclass(frozen=True)
class ASNConversionResult:
    target_asns: tuple[int, ...]
    networks_by_asn: dict[int, tuple[Network, ...]]
    ipv4_networks: tuple[ipaddress.IPv4Network, ...]
    ipv6_networks: tuple[ipaddress.IPv6Network, ...]


def _network_sort_key(network: Network) -> tuple[int, int, int]:
    return network.version, int(network.network_address), network.prefixlen


def collect_asn_networks(
    records: Iterable[tuple[object, object]], target_asns: Iterable[int]
) -> ASNConversionResult:
    targets = tuple(sorted(set(target_asns)))
    if not targets:
        raise ValueError("at least one target ASN is required")

    collected: dict[int, set[Network]] = {asn: set() for asn in targets}
    for raw_network, raw_record in records:
        if not isinstance(raw_record, dict):
            continue
        asn = raw_record.get("autonomous_system_number")
        if isinstance(asn, bool) or not isinstance(asn, int) or asn not in collected:
            continue

        try:
            network = ipaddress.ip_network(str(raw_network), strict=False)
        except ValueError as error:
            raise ValueError(f"invalid network in ASN database: {raw_network}") from error
        collected[asn].add(network)

    networks_by_asn = {
        asn: tuple(sorted(networks, key=_network_sort_key))
        for asn, networks in collected.items()
    }
    all_networks = set().union(*collected.values())
    if not all_networks:
        joined = ", ".join(str(asn) for asn in targets)
        raise RuntimeError(f"No networks found for target ASNs: {joined}")

    ipv4_networks = tuple(
        sorted(
            (network for network in all_networks if network.version == 4),
            key=_network_sort_key,
        )
    )
    ipv6_networks = tuple(
        sorted(
            (network for network in all_networks if network.version == 6),
            key=_network_sort_key,
        )
    )
    return ASNConversionResult(
        target_asns=targets,
        networks_by_asn=networks_by_asn,
        ipv4_networks=ipv4_networks,
        ipv6_networks=ipv6_networks,
    )


def extract_asn_networks(database: Path, target_asns: Iterable[int]) -> ASNConversionResult:
    try:
        import maxminddb
    except ImportError as error:
        raise RuntimeError("maxminddb is required to read the ASN database") from error

    with maxminddb.open_database(database) as reader:
        return collect_asn_networks(reader, target_asns)


def write_rules(
    output: Path,
    ipv4_networks: Iterable[ipaddress.IPv4Network],
    ipv6_networks: Iterable[ipaddress.IPv6Network],
    *,
    no_resolve: bool,
) -> None:
    suffix = ",no-resolve" if no_resolve else ""
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="\n") as output_file:
        for network in ipv4_networks:
            output_file.write(f"IP-CIDR,{network}{suffix}\n")
        for network in ipv6_networks:
            output_file.write(f"IP-CIDR6,{network}{suffix}\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert selected GeoLite2 ASN networks to Shadowrocket rules."
    )
    parser.add_argument("database", type=Path, help="GeoLite2-ASN.mmdb")
    parser.add_argument("output", type=Path, help="regular ruleset")
    parser.add_argument("output_no_resolve", type=Path, help="no-resolve ruleset")
    parser.add_argument(
        "--asn",
        action="append",
        type=int,
        required=True,
        dest="target_asns",
        help="target autonomous system number; repeat for multiple ASNs",
    )
    args = parser.parse_args()

    if not args.database.is_file():
        parser.error(f"Database does not exist: {args.database}")
    if any(asn <= 0 for asn in args.target_asns):
        parser.error("--asn values must be positive")

    result = extract_asn_networks(args.database, args.target_asns)
    write_rules(
        args.output,
        result.ipv4_networks,
        result.ipv6_networks,
        no_resolve=False,
    )
    write_rules(
        args.output_no_resolve,
        result.ipv4_networks,
        result.ipv6_networks,
        no_resolve=True,
    )

    for asn in result.target_asns:
        networks = result.networks_by_asn[asn]
        ipv4_count = sum(network.version == 4 for network in networks)
        ipv6_count = sum(network.version == 6 for network in networks)
        print(f"ASN {asn}: {len(networks)} networks ({ipv4_count} IPv4, {ipv6_count} IPv6)")
    print(f"IPv4 networks: {len(result.ipv4_networks)}")
    print(f"IPv6 networks: {len(result.ipv6_networks)}")
    print(f"Generated: {args.output}")
    print(f"Generated: {args.output_no_resolve}")


if __name__ == "__main__":
    main()
