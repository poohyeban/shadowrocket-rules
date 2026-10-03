"""Build policy-free Meta lists directly from pinned original upstreams."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

from .convert import ConversionStats, convert_rule
from .merge_rules import validate_rule
from .meta_common import SERVICES, compact, select_sukka

ROOT = Path(__file__).resolve().parents[1]
KINDS = {"DOMAIN": "full", "DOMAIN-SUFFIX": "domain", "DOMAIN-KEYWORD": "keyword"}
SOURCES = {**{s.lower(): ("v2fly/domain-list-community", "data/" + s.lower()) for s in SERVICES},
           "sukka": ("SukkaW/Surge", "Source/non_ip/global.conf")}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def inputs(cache, offline):
    cache.mkdir(parents=True, exist_ok=True)
    if offline:
        manifest = json.loads((cache / "inputs.json").read_text())
        if set(manifest) != set(SOURCES):
            raise ValueError("Offline Meta source inventory mismatch")
    else:
        commits = {}
        for repo, _ in SOURCES.values():
            if repo in commits:
                continue
            result = subprocess.check_output(["git", "ls-remote", "https://github.com/" + repo + ".git",
                                              "refs/heads/master"], text=True, timeout=60).split()
            if len(result) != 2 or not re.fullmatch(r"[0-9a-f]{40}", result[0]):
                raise ValueError("Invalid upstream revision")
            commits[repo] = result[0]
        manifest = {}
        for name, (repo, path) in SOURCES.items():
            url = f"https://raw.githubusercontent.com/{repo}/{commits[repo]}/{path}"
            target = cache / (name + ".part")
            subprocess.run(["curl", "--fail", "--silent", "--show-error", "--location", "--retry", "3",
                            "--connect-timeout", "20", "--max-time", "180", "-o", str(target), url], check=True)
            data = target.read_bytes()
            if not data:
                raise ValueError("Empty Meta source")
            target.replace(cache / name)
            manifest[name] = {"url": url, "commit": commits[repo], "sha256": sha(data)}
        (cache / "inputs.json").write_text(json.dumps(manifest, sort_keys=True))
    raw = {name: (cache / name).read_bytes() for name in SOURCES}
    revisions = set()
    for name, (repo, path) in SOURCES.items():
        entry = manifest[name]
        if not re.fullmatch(r"[0-9a-f]{40}", entry["commit"]):
            raise ValueError("Invalid cached revision")
        expected = f"https://raw.githubusercontent.com/{repo}/{entry['commit']}/{path}"
        if entry["url"] != expected or sha(raw[name]) != entry["sha256"]:
            raise ValueError("Offline Meta source URL or digest mismatch")
        if repo.startswith("v2fly/"):
            revisions.add(entry["commit"])
    if len(revisions) != 1:
        raise ValueError("Meta primary sources must share a snapshot")
    return raw, manifest


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
