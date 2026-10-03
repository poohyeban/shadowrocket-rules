"""Reviewed Meta service selection; pairs use v2fly domain/full/keyword kinds."""
import re

SERVICES = ("WhatsApp", "Instagram", "Facebook")


def covers(outer, inner):
    kind, host = outer
    other, target = inner
    if kind == "full":
        return other == "full" and host == target
    return kind == "domain" and other in {"full", "domain"} and (
        target == host or target.endswith("." + host))


def compact(rules):
    suffixes = {value for kind, value in rules if kind == "domain"}
    result = set()
    for kind, value in rules:
        if kind in {"domain", "full"}:
            labels = value.split(".")
            start = 1 if kind == "domain" else 0
            if any(".".join(labels[i:]) in suffixes for i in range(start, len(labels))):
                continue
        result.add((kind, value))
    return result


def parse_sukka(line):
    fields = line.split(",")
    kinds = {"DOMAIN": "full", "DOMAIN-SUFFIX": "domain", "DOMAIN-KEYWORD": "keyword"}
    if len(fields) != 2 or fields[0] not in kinds:
        raise ValueError("Unsupported or policy-bearing Sukka rule")
    value = fields[1]
    if not value or len(value) > 253 or value != value.lower():
        raise ValueError("Invalid Sukka hostname")
    if fields[0] == "DOMAIN-KEYWORD":
        valid = re.fullmatch(r"[a-z0-9.-]+", value)
    else:
        valid = all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) for p in value.split("."))
    if not valid:
        raise ValueError("Invalid Sukka hostname")
    return kinds[fields[0]], value


def select_sukka(text, primary, review):
    if set(primary) != set(SERVICES) or set(review) != {"additions", "excluded"}:
        raise ValueError("Invalid Meta service inventory")
    additions, excluded = review["additions"], review["excluded"]
    if set(additions) & set(excluded):
        raise ValueError("Conflicting review entries")
    for line, service in additions.items():
        if service not in SERVICES or parse_sukka(line)[0] not in {"full", "domain"}:
            raise ValueError("Invalid reviewed addition")
    for line, reason in excluded.items():
        parse_sukka(line)
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("Missing exclusion reason")
    selected = {service: set() for service in SERVICES}
    active, sections, count = False, 0, 0
    seen, skipped = set(), []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if line.startswith("# >> "):
            active = line == "# >> Facebook"
            sections += int(active)
        if not active or not line or line.startswith("#"):
            continue
        count += 1
        rule = parse_sukka(line)
        seen.add(line)
        reason = excluded.get(line)
        if reason is None and rule[0] not in {"domain", "full"}:
            reason = "not a service-specific exact domain or suffix"
        if reason is None:
            owners = {service for service, rules in primary.items() if any(covers(r, rule) for r in rules)}
            if line in additions:
                owners.add(additions[line])
            if len(owners) > 1:
                raise ValueError("Ambiguous Sukka service classification")
            if owners:
                selected[owners.pop()].add(rule)
                continue
            reason = "unclassified domain; requires service-boundary review"
        skipped.append({"line": number, "source_rule": line, "reason": reason})
    if sections != 1 or not count:
        raise ValueError("Missing, duplicate or empty Sukka Facebook section")
    return selected, {"input": count, "selected": {s: len(r) for s, r in selected.items()},
                      "skipped": skipped,
                      "review_entries_absent_upstream": len((set(additions) | set(excluded)) - seen)}
