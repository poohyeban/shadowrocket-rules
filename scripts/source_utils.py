"""Download original GitHub inputs at one immutable revision per repository."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import subprocess


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pinned_inputs(sources: dict[str, tuple[str, str]], cache: Path, offline: bool = False):
    cache.mkdir(parents=True, exist_ok=True)
    if offline:
        manifest = json.loads((cache / "inputs.json").read_text(encoding="utf-8"))
    else:
        commits = {}
        for repo, _ in sources.values():
            if repo in commits:
                continue
            result = subprocess.check_output(
                ["git", "ls-remote", f"https://github.com/{repo}.git", "refs/heads/master"],
                text=True, timeout=60,
            ).split()
            if len(result) != 2 or not re.fullmatch(r"[0-9a-f]{40}", result[0]):
                raise ValueError("Invalid upstream revision")
            commits[repo] = result[0]
        manifest = {}
        for name, (repo, path) in sources.items():
            url = f"https://raw.githubusercontent.com/{repo}/{commits[repo]}/{path}"
            target = cache / (name + ".part")
            subprocess.run(
                ["curl", "--fail", "--silent", "--show-error", "--location", "--retry", "3",
                 "--connect-timeout", "20", "--max-time", "180", "-o", str(target), url],
                check=True, timeout=800,
            )
            data = target.read_bytes()
            if not data:
                raise ValueError("Empty upstream source")
            target.replace(cache / name)
            manifest[name] = {"url": url, "commit": commits[repo], "sha256": sha(data)}
        (cache / "inputs.json").write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")

    if set(manifest) != set(sources):
        raise ValueError("Offline source inventory mismatch")
    raw = {name: (cache / name).read_bytes() for name in sources}
    revisions = {}
    for name, (repo, path) in sources.items():
        entry = manifest[name]
        if not re.fullmatch(r"[0-9a-f]{40}", entry["commit"]):
            raise ValueError("Invalid cached revision")
        expected = f"https://raw.githubusercontent.com/{repo}/{entry['commit']}/{path}"
        if not raw[name] or entry["url"] != expected or sha(raw[name]) != entry["sha256"]:
            raise ValueError("Offline source URL or digest mismatch")
        revisions.setdefault(repo, set()).add(entry["commit"])
    if any(len(values) != 1 for values in revisions.values()):
        raise ValueError("Inputs from the same repository must share a snapshot")
    return raw, manifest
