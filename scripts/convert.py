#!/usr/bin/env python3

import argparse
import sys
from pathlib import Path


RULE_MAP = {
    "domain": "DOMAIN-SUFFIX",
    "full": "DOMAIN",
    "keyword": "DOMAIN-KEYWORD",
}


def convert_line(line: str):
    line = line.strip()

    # Ignore empty lines and comments
    if not line or line.startswith("#"):
        return None

    # v2fly exported lists may retain attributes in this form:
    # domain:example.com:@attr1,@attr2
    #
    # Shadowrocket does not need these attributes, so remove them.
    if ":@" in line:
        line = line.split(":@", 1)[0]

    # v2fly allows domain rules without an explicit "domain:" prefix.
    if ":" not in line:
        rule_type = "domain"
        value = line
    else:
        rule_type, value = line.split(":", 1)
        rule_type = rule_type.lower().strip()
        value = value.strip()

    if not value:
        return None

    if rule_type == "regexp":
        print(
            f"Warning: unsupported regexp rule skipped: {line}",
            file=sys.stderr,
        )
        return None

    shadowrocket_type = RULE_MAP.get(rule_type)

    if shadowrocket_type is None:
        print(
            f"Warning: unknown rule type skipped: {line}",
            file=sys.stderr,
        )
        return None

    return f"{shadowrocket_type},{value}"


def convert_file(source: Path, output: Path):
    rules = set()
    skipped = 0

    with source.open("r", encoding="utf-8") as f:
        for line in f:
            converted = convert_line(line)

            if converted is None:
                skipped += 1
                continue

            rules.add(converted)

    sorted_rules = sorted(rules)

    output.parent.mkdir(parents=True, exist_ok=True)

    with output.open("w", encoding="utf-8", newline="\n") as f:
        for rule in sorted_rules:
            f.write(rule + "\n")

    print(f"Generated: {output}")
    print(f"Rules: {len(sorted_rules)}")
    print(f"Skipped/ignored lines: {skipped}")


def main():
    parser = argparse.ArgumentParser(
        description="Convert v2fly domain lists to Shadowrocket RULE-SET format."
    )

    parser.add_argument(
        "source",
        type=Path,
        help="Path to the v2fly plaintext domain list.",
    )

    parser.add_argument(
        "output",
        type=Path,
        help="Path to the generated Shadowrocket ruleset.",
    )

    args = parser.parse_args()

    if not args.source.is_file():
        parser.error(f"Source file does not exist: {args.source}")

    convert_file(args.source, args.output)


if __name__ == "__main__":
    main()
