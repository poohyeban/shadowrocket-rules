# shadowrocket-rules

Automatically generated, deterministic rulesets for Shadowrocket.

## Generated rules

Generated rule files are organized by service or rule family under `rules/`:

```text
rules/
├── China/
├── OpenAI/
└── AdGuard/
```

- `rules/OpenAI/OpenAI.list`: OpenAI-related domains, OpenAI-owned ASN IP
  networks, and official ChatGPT Voice IP prefixes.
- `rules/OpenAI/OpenAI-NoResolve.list`: the same rules, with `no-resolve` on
  every `IP-CIDR` and `IP-CIDR6` rule.
- `rules/China/China-Domain.list`: China domain rules from
  [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community).
- `rules/China/GeoIP-CN.list`: China IPv4 and IPv6 CIDR rules.
- `rules/China/GeoIP-CN-NoResolve.list`: the same CIDR rules with `no-resolve`.
- `rules/AdGuard/Ad-Domain.list`: DNS-level advertising and tracking rules safely
  converted from the official
  [AdGuard DNS Filter](https://github.com/AdguardTeam/AdGuardSDNSFilter).

## OpenAI usage

Use the regular aggregate ruleset:

```ini
RULE-SET,https://raw.githubusercontent.com/poohyeban/shadowrocket-rules/main/rules/OpenAI/OpenAI.list,OpenAI
```

Or use the equivalent `no-resolve` variant when DNS resolution for IP rules is
not desired:

```ini
RULE-SET,https://raw.githubusercontent.com/poohyeban/shadowrocket-rules/main/rules/OpenAI/OpenAI-NoResolve.list,OpenAI
```

The aggregate rulesets are built from auditable files under
`rules/OpenAI/Sources/`:

- `OpenAI-v2fly.list`: OpenAI domains converted from
  [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community).
- `OpenAI-Official-Domain.list`: the OpenAI Help Center allowlist converted from
  the repository-owned, manually reviewed snapshot at
  `data/OpenAI/official-domains.txt`. CI does not scrape the Help Center page.
- `OpenAI-ASN-IP.list` and `OpenAI-ASN-IP-NoResolve.list`: networks belonging to
  AS401518 and AS401864, selected from the P3TERX GeoLite2 ASN database.
- `OpenAI-Voice-IP.list` and `OpenAI-Voice-IP-NoResolve.list`: official ChatGPT
  Voice prefixes automatically synchronized from
  [chatgpt-voice.json](https://openai.com/chatgpt-voice.json).

OpenAI documents UDP port 3478 as preferred for ChatGPT Voice and TCP port 443
as a fallback. The current Voice source rules are IP-only CIDR rules: they do
not encode port or protocol constraints. Runtime behavior should therefore be
verified separately in Shadowrocket.

## Conversion policy

The converters only emit a Shadowrocket rule when the source semantics can be
preserved. Finite, fully anchored hostname regular expressions can be exactly
expanded, with a hard limit of 1,000 results. Unbounded regexes, contextual
modifiers, URL patterns, and partial Adblock patterns are skipped with build
warnings instead of being widened into approximate wildcard or URL rules.

AdGuard exceptions are resolved before output. A wildcard exception with a
provable fixed hostname suffix removes every potentially conflicting block in
that suffix. If a future exception can match a hostname but cannot be safely
represented or conservatively covered, the build fails instead of publishing a
ruleset that may overblock.

For example, the current v2fly OpenAI source contains an unbounded
`chatgpt-async-webps-prod` hostname regexp. Shadowrocket cannot express it as an
equivalent hostname rule, so it is skipped with a diagnostic instead of being
widened to an approximate `DOMAIN-WILDCARD` rule.

Build-only diagnostics are written under `build/`, which is ignored by Git.
Generated `.list` files contain no timestamps, so unchanged source content does
not create a commit.

## Licensing

The repository's conversion code is covered by the root MIT license.
`rules/AdGuard/Ad-Domain.list` is derived from AdGuard DNS Filter and remains
subject to the upstream
[GNU GPLv3 license](https://github.com/AdguardTeam/AdGuardSDNSFilter/blob/master/LICENSE).
The v2fly and GeoLite-derived outputs remain subject to their respective
upstream data licenses and notices.
