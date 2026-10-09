"""Validate every published list, aggregate, variant and provenance digest."""
from __future__ import annotations

import argparse
from collections import Counter
import ipaddress
import json
from pathlib import Path

from .merge_rules import DOMAIN_TYPES, RuleValidationError, read_rules, validate_pair
from .meta_common import SERVICES, compact
from .source_utils import sha

ROOT = Path(__file__).resolve().parents[1]


def audit_file(path: Path):
    data = path.read_bytes()
    if data.startswith(b"\xef\xbb\xbf") or b"\r" in data or not data.endswith(b"\n"):
        raise RuleValidationError(f"{path}: expected UTF-8 without BOM and LF-terminated lines")
    lines = data.decode("utf-8").splitlines()
    rules = read_rules(path)
    if not all(lines) or len(lines) != len(rules):
        raise RuleValidationError(f"{path}: empty lines or duplicate rules")
    kinds = Counter(rule.split(",")[0] for rule in rules)
    versions = Counter(str(ipaddress.ip_network(rule.split(",")[1]).version)
                       for rule in rules if rule.startswith("IP-CIDR,"))
    return rules, {"rules": len(rules), "types": dict(sorted(kinds.items())),
                   "ip_versions": dict(sorted(versions.items())), "sha256": sha(data)}


def audit(root: Path = ROOT):
    inventory, files = {}, {}
    for path in sorted((root / "rules").rglob("*.list")):
        name = path.relative_to(root / "rules").as_posix()
        inventory[name], files[name] = audit_file(path)
        service = name.split("/")[0]
        if service in {*SERVICES, "AdGuard"} and any(
            rule.split(",")[0] not in DOMAIN_TYPES for rule in inventory[name]
        ):
            raise RuleValidationError(f"{path}: expected a domain-only ruleset")

    def required(name):
        if name not in inventory:
            raise RuleValidationError(f"Missing published ruleset: {name}")
        return inventory[name]

    aggregates = {}
    required("AdGuard/Ad-Domain.list")
    for service, domain_sources, ip_sources in (
        ("China", ("China-v2fly-Domain",), ("China-GeoIP",)),
        ("OpenAI", ("OpenAI-v2fly", "OpenAI-Official-Domain"),
         ("OpenAI-ASN-IP", "OpenAI-Voice-IP")),
        ("Claude", ("Claude-v2fly",), ("Claude-ASN-IP",)),
    ):
        for variant in ("", "-NoResolve") if ip_sources else ("",):
            names = [f"{service}/Sources/{name}.list" for name in domain_sources]
            names += [f"{service}/Sources/{name}{variant}.list" for name in ip_sources]
            expected = set().union(*(required(name) for name in names))
            target = f"{service}/{service}{variant}.list"
            if required(target) != expected:
                raise RuleValidationError(f"Aggregate differs from its sources: {target}")
            aggregates[target] = names

    for service in SERVICES:
        names = [f"{service}/Sources/{service}-v2fly.list"]
        combined = set(required(names[0]))
        supplement = f"{service}/Sources/{service}-Sukka.list"
        if supplement in inventory:
            names.append(supplement)
            combined |= inventory[supplement]
        kinds = {"DOMAIN": "full", "DOMAIN-SUFFIX": "domain", "DOMAIN-KEYWORD": "keyword",
                 "DOMAIN-WILDCARD": "wildcard"}
        reverse = {value: key for key, value in kinds.items()}
        expected = {f"{reverse[kind]},{value}" for kind, value in compact(
            {(kinds[rule.split(",")[0]], rule.split(",")[1]) for rule in combined}
        )}
        target = f"{service}/{service}.list"
        if required(target) != expected:
            raise RuleValidationError(f"Meta aggregate differs from its sources: {target}")
        aggregates[target] = names

    pairs = []
    for name in inventory:
        if name.endswith("-NoResolve.list"):
            regular = name.removesuffix("-NoResolve.list") + ".list"
            required(regular)
            validate_pair(root / "rules" / regular, root / "rules" / name)
            pairs.append([regular, name])

    for report_name in ("meta", "claude"):
        report = json.loads((root / f"reports/{report_name}.json").read_text(encoding="utf-8"))
        services = set(SERVICES) if report_name == "meta" else {"Claude"}
        expected_outputs = {name for name in inventory if name.split("/")[0] in services}
        if set(report["outputs"]) != expected_outputs:
            raise RuleValidationError(f"Provenance output inventory mismatch: {report_name}")
        for name, digest in report["outputs"].items():
            required(name)
            if files[name]["sha256"] != digest:
                raise RuleValidationError(f"Provenance output digest mismatch: {name}")

    return {"files": files, "aggregates": aggregates, "no_resolve_pairs": pairs,
            "allowed_types": sorted(DOMAIN_TYPES | {"IP-CIDR"}),
            "minimum_shadowrocket_for_wildcards": "2.2.65",
            "validation_scope": "static syntax and source consistency; no client runtime test"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=ROOT / "reports/health.json")
    args = parser.parse_args()
    report = audit()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Validated {len(report['files'])} rulesets; report: {args.report}")
