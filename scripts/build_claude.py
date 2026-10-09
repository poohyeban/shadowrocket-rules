"""Build Claude rules from maintained v2fly domains and Anthropic ASN prefixes."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .convert import convert_file
from .convert_asn import extract_asn_networks, write_rules
from .merge_rules import read_rules
from .source_utils import pinned_inputs, sha

ROOT = Path(__file__).resolve().parents[1]
SOURCES = {"anthropic": ("v2fly/domain-list-community", "data/anthropic")}
TARGET_ASNS = (399358,)


def build(root: Path = ROOT, offline: bool = False):
    cache = root / "build/claude"
    _, provenance = pinned_inputs(SOURCES, cache, offline)
    staging = cache / "Claude-v2fly.list"
    stats = convert_file(cache / "anthropic", staging,
                         unsupported_output=cache / "unsupported.txt", strict=True)
    domains = read_rules(staging)
    database = root / "build/GeoLite2-ASN.mmdb"
    asns = extract_asn_networks(database, TARGET_ASNS)
    outputs = {"Claude/Sources/Claude-v2fly.list": staging.read_bytes()}
    for variant, no_resolve in (("", False), ("-NoResolve", True)):
        path = cache / f"Claude-ASN-IP{variant}.list"
        write_rules(path, asns.ipv4_networks, asns.ipv6_networks, no_resolve=no_resolve)
        ips = read_rules(path)
        outputs[f"Claude/Sources/Claude-ASN-IP{variant}.list"] = path.read_bytes()
        outputs[f"Claude/Claude{variant}.list"] = "".join(
            line + "\n" for line in sorted(domains | ips)
        ).encode("utf-8")
    for name, data in outputs.items():
        target = root / "rules" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    report = {
        "sources": provenance,
        "domain_count": stats.final_rules,
        "ip_count": len(asns.ipv4_networks) + len(asns.ipv6_networks),
        "asn_source": {"url": "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb",
                       "sha256": sha(database.read_bytes()), "target_asns": list(TARGET_ASNS)},
        "asn_prefix_counts": {str(asn): len(prefixes) for asn, prefixes in asns.networks_by_asn.items()},
        "skipped": [{"line": number, "reason": reason, "source_rule": line}
                    for number, reason, line in stats.unsupported_records],
        "outputs": {name: sha(data) for name, data in outputs.items()},
    }
    (root / "reports").mkdir(exist_ok=True)
    (root / "reports/claude.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    build(offline=parser.parse_args().offline)
