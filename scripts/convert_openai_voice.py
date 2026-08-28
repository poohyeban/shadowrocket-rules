#!/usr/bin/env python3

"""Convert the official ChatGPT Voice prefix JSON to Shadowrocket rules."""

from __future__ import annotations

import argparse
import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Union


Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


class VoiceDataError(ValueError):
    """Raised when the official Voice JSON does not match its expected schema."""


@dataclass(frozen=True)
class VoiceData:
    creation_time: str
    ipv4_networks: tuple[ipaddress.IPv4Network, ...]
    ipv6_networks: tuple[ipaddress.IPv6Network, ...]
    duplicate_prefixes: int


def _network_sort_key(network: Network) -> tuple[int, int, int]:
    return network.version, int(network.network_address), network.prefixlen


def _validate_creation_time(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise VoiceDataError("creationTime must be a non-empty timestamp string")
    candidate = value.strip()
    try:
        parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    except ValueError as error:
        raise VoiceDataError("creationTime is not a valid ISO 8601 timestamp") from error
    if parsed.tzinfo is None:
        raise VoiceDataError("creationTime must include a timezone")
    return candidate


def parse_voice_payload(payload: object) -> VoiceData:
    if not isinstance(payload, dict):
        raise VoiceDataError("top-level Voice JSON value must be an object")

    creation_time = _validate_creation_time(payload.get("creationTime"))
    prefixes = payload.get("prefixes")
    if not isinstance(prefixes, list):
        raise VoiceDataError("prefixes must be an array")
    if not prefixes:
        raise VoiceDataError("prefixes must not be empty")

    networks: set[Network] = set()
    parsed_prefix_count = 0
    for index, item in enumerate(prefixes):
        if not isinstance(item, dict):
            raise VoiceDataError(f"prefixes[{index}] must be an object")

        supported_keys = set(item) & {"ipv4Prefix", "ipv6Prefix"}
        if len(supported_keys) != 1 or set(item) != supported_keys:
            raise VoiceDataError(
                f"prefixes[{index}] must contain exactly one supported prefix field"
            )
        key = next(iter(supported_keys))
        value = item[key]
        if not isinstance(value, str) or "/" not in value:
            raise VoiceDataError(f"prefixes[{index}].{key} must be a CIDR string")

        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as error:
            raise VoiceDataError(
                f"prefixes[{index}].{key} is not a valid CIDR: {value}"
            ) from error
        expected_version = 4 if key == "ipv4Prefix" else 6
        if network.version != expected_version:
            raise VoiceDataError(
                f"prefixes[{index}].{key} has the wrong IP version: {value}"
            )

        parsed_prefix_count += 1
        networks.add(network)

    ipv4_networks = tuple(
        sorted(
            (network for network in networks if network.version == 4),
            key=_network_sort_key,
        )
    )
    ipv6_networks = tuple(
        sorted(
            (network for network in networks if network.version == 6),
            key=_network_sort_key,
        )
    )
    return VoiceData(
        creation_time=creation_time,
        ipv4_networks=ipv4_networks,
        ipv6_networks=ipv6_networks,
        duplicate_prefixes=parsed_prefix_count - len(networks),
    )


def load_voice_data(source: Path) -> VoiceData:
    try:
        with source.open("r", encoding="utf-8-sig") as input_file:
            payload = json.load(input_file)
    except json.JSONDecodeError as error:
        raise VoiceDataError(f"invalid Voice JSON: {error}") from error
    return parse_voice_payload(payload)


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


def convert_file(source: Path, output: Path, output_no_resolve: Path) -> VoiceData:
    data = load_voice_data(source)
    write_rules(
        output,
        data.ipv4_networks,
        data.ipv6_networks,
        no_resolve=False,
    )
    write_rules(
        output_no_resolve,
        data.ipv4_networks,
        data.ipv6_networks,
        no_resolve=True,
    )
    print(f"creationTime: {data.creation_time}")
    print(f"IPv4 prefixes: {len(data.ipv4_networks)}")
    print(f"IPv6 prefixes: {len(data.ipv6_networks)}")
    print(f"Duplicate prefixes removed: {data.duplicate_prefixes}")
    print(f"Generated: {output}")
    print(f"Generated: {output_no_resolve}")
    return data


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert official ChatGPT Voice prefixes to Shadowrocket rules."
    )
    parser.add_argument("source", type=Path, help="chatgpt-voice.json")
    parser.add_argument("output", type=Path, help="regular ruleset")
    parser.add_argument("output_no_resolve", type=Path, help="no-resolve ruleset")
    args = parser.parse_args()

    if not args.source.is_file():
        parser.error(f"Source file does not exist: {args.source}")

    convert_file(args.source, args.output, args.output_no_resolve)


if __name__ == "__main__":
    main()
