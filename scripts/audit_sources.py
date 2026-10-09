"""Record downloaded source digests and source-provided versions after generation."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import maxminddb

from .build_claude import SOURCES as CLAUDE_SOURCES
from .build_meta import SOURCES as META_SOURCES
from .convert_asn import extract_asn_networks
from .convert_openai_voice import load_voice_data
from .source_utils import pinned_inputs, sha

ROOT = Path(__file__).resolve().parents[1]
SOURCES = {
    "china-domains": ("cn.txt", "https://raw.githubusercontent.com/v2fly/domain-list-community/release/cn.txt"),
    "openai-domains": ("openai-v2fly.txt", "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/openai"),
    "china-country": ("GeoLite2-Country.mmdb", "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"),
    "asn-database": ("GeoLite2-ASN.mmdb", "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb"),
    "chatgpt-voice": ("chatgpt-voice.json", "https://openai.com/chatgpt-voice.json"),
    "adguard": ("adguard-filter.txt", "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"),
}


def audit(root: Path = ROOT):
    sources = {}
    for name, (filename, url) in SOURCES.items():
        path = root / "build" / filename
        data = path.read_bytes()
        if not data:
            raise ValueError(f"Empty downloaded source: {name}")
        entry = {"url": url, "bytes": len(data), "sha256": sha(data)}
        if filename.endswith(".mmdb"):
            with maxminddb.open_database(path) as reader:
                metadata = reader.metadata()
            expected_type = "GeoLite2-Country" if name == "china-country" else "GeoLite2-ASN"
            if metadata.database_type != expected_type:
                raise ValueError(f"Unexpected MMDB database type: {name}")
            entry["database_type"] = metadata.database_type
            entry["build_time"] = datetime.fromtimestamp(metadata.build_epoch, timezone.utc).isoformat()
        elif name == "chatgpt-voice":
            entry["creation_time"] = load_voice_data(path).creation_time
        elif name == "adguard":
            entry["version_headers"] = [line for line in data.decode("utf-8-sig").splitlines()[:20]
                                        if line.startswith(("! Version:", "! TimeUpdated:", "! Last modified:"))]
        sources[name] = entry
    for group, configured in (("meta", META_SOURCES), ("claude", CLAUDE_SOURCES)):
        raw, manifest = pinned_inputs(configured, root / "build" / group, offline=True)
        report = json.loads((root / f"reports/{group}.json").read_text(encoding="utf-8"))
        if report["sources"] != manifest:
            raise ValueError(f"Build provenance differs from downloaded sources: {group}")
        for name, entry in manifest.items():
            sources[f"{group}-{name}"] = {**entry, "bytes": len(raw[name])}
    asns = extract_asn_networks(root / "build/GeoLite2-ASN.mmdb", (401518, 401864))
    claude = json.loads((root / "reports/claude.json").read_text(encoding="utf-8"))
    if claude["asn_source"]["sha256"] != sources["asn-database"]["sha256"]:
        raise ValueError("Claude and OpenAI must use the same ASN database snapshot")
    return {"sources": sources,
            "openai_asn_prefix_counts": {str(asn): len(prefixes) for asn, prefixes in asns.networks_by_asn.items()},
            "claude_asn_prefix_counts": claude["asn_prefix_counts"],
            "reviewed_openai_snapshot_sha256": sha((root / "data/OpenAI/official-domains.txt").read_bytes()),
            "reviewed_openai_exclusions_sha256": sha((root / "data/OpenAI/official-domains-excluded.txt").read_bytes())}


if __name__ == "__main__":
    report = audit()
    path = ROOT / "reports/sources.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Recorded {len(report['sources'])} downloaded inputs: {path}")
