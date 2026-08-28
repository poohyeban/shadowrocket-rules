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
- `rules/China/China.list`: v2fly China domains plus China IPv4 and IPv6 CIDR
  rules.
- `rules/China/China-NoResolve.list`: the same rules, with `no-resolve` on every
  `IP-CIDR` and `IP-CIDR6` rule.
- `rules/AdGuard/Ad-Domain.list`: DNS-level advertising and tracking rules safely
  converted from the official
  [AdGuard DNS Filter](https://github.com/AdguardTeam/AdGuardSDNSFilter).

## China usage

Use the regular aggregate ruleset:

```ini
RULE-SET,https://raw.githubusercontent.com/poohyeban/shadowrocket-rules/main/rules/China/China.list,国内直连
```

Or use the equivalent `no-resolve` variant:

```ini
RULE-SET,https://raw.githubusercontent.com/poohyeban/shadowrocket-rules/main/rules/China/China-NoResolve.list,国内直连
```

`China.list` combines v2fly China domain rules with China GeoIP IPv4/IPv6
rules. `China-NoResolve.list` contains the same domain and IP rule sets, but all
IP rules carry `no-resolve`.

The provenance files under `rules/China/Sources/` are also usable separately:

- `China-v2fly-Domain.list`: China domain rules converted from
  [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community).
- `China-GeoIP.list` and `China-GeoIP-NoResolve.list`: China networks extracted
  from the GeoLite2 Country database, in regular and `no-resolve` forms.

Most users only need `China.list` or `China-NoResolve.list`; the source files are
provided for provenance, auditing, debugging, and individual use.

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
