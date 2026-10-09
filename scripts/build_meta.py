"""Build policy-free Meta lists directly from pinned original upstreams."""
import argparse
import json
from pathlib import Path
import re

from .convert import ConversionStats, convert_rule
from .merge_rules import validate_rule
from .meta_common import SERVICES, compact, select_sukka
from .source_utils import pinned_inputs, sha

ROOT = Path(__file__).resolve().parents[1]
KINDS = {"DOMAIN": "full", "DOMAIN-SUFFIX": "domain", "DOMAIN-KEYWORD": "keyword"}
SOURCES = {**{s.lower(): ("v2fly/domain-list-community", "data/" + s.lower()) for s in SERVICES},
           "sukka": ("SukkaW/Surge", "Source/non_ip/global.conf")}


def inputs(cache, offline):
    return pinned_inputs(SOURCES, cache, offline)


def primary_rules(text):
    rules, skipped = set(), []
    for number, line in enumerate(text.splitlines(), 1):
        if re.match(r"\s*include\s*:", line, re.IGNORECASE):
            raise ValueError("Unresolved Meta include directive")
        stats = ConversionStats()
        converted = convert_rule(line, number, stats)
        for _, reason, source in stats.warning_examples:
            if not reason.startswith("unsafe-regexp:"):
                raise ValueError("Invalid Meta primary rule: " + reason)
            skipped.append({"line": number, "reason": reason, "source_rule": source})
        rules.update((KINDS[r.kind], r.value) for r in converted)
    if not rules:
        raise ValueError("Empty Meta primary rules")
    return rules, skipped


def build(root=ROOT, offline=False):
    raw, provenance = inputs(root / "build/meta", offline)
    primary, skipped = {}, {}
    for service in SERVICES:
        primary[service], skipped[service] = primary_rules(raw[service.lower()].decode("utf-8-sig"))
    review = (root / "data/Meta/sukka-review.json").read_bytes()
    supplement, selection = select_sukka(raw["sukka"].decode("utf-8-sig"), primary, json.loads(review))
    reverse = {value: key for key, value in KINDS.items()}
    outputs, counts = {}, {}
    for service in SERVICES:
        combined = compact(primary[service] | supplement[service])
        counts[service] = {"primary": len(primary[service]), "supplement": len(supplement[service]),
                           "total": len(combined), "added": sorted(combined - compact(primary[service]))}
        for path, rules in {f"{service}/{service}.list": combined,
                            f"{service}/Sources/{service}-v2fly.list": primary[service],
                            f"{service}/Sources/{service}-Sukka.list": supplement[service]}.items():
            lines = sorted(f"{reverse[kind]},{value}" for kind, value in rules)
            for number, line in enumerate(lines, 1):
                validate_rule(line, Path(path), number)
            outputs[path] = "".join(line + "\n" for line in lines).encode()
    for name, data in outputs.items():
        target = root / "rules" / name
        if not data:
            target.unlink(missing_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    report = {"sources": provenance, "review_sha256": sha(review), "counts": counts,
              "sukka_selection": selection, "primary_skipped": skipped,
              "outputs": {name: sha(data) for name, data in outputs.items() if data}}
    (root / "reports").mkdir(exist_ok=True)
    (root / "reports/meta.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(counts, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--offline", action="store_true")
    build(offline=parser.parse_args().offline)
