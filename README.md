# shadowrocket-rules

Automatically generated, deterministic rulesets for Shadowrocket.

## Generated rules

- `rules/China-Domain.list`: China domain rules from
  [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community).
- `rules/OpenAI.list`: v2fly OpenAI rules, including rules carrying the
  upstream `@ads` attribute.
- `rules/OpenAI-NoAds.list`: v2fly OpenAI rules excluding rules carrying the
  upstream `@ads` attribute.
- `rules/OpenAI-Ads.list`: only the subset of v2fly OpenAI rules carrying the
  upstream `@ads` attribute, so it can be assigned a separate policy.
- `rules/Ad-Domain.list`: DNS-level advertising and tracking rules safely
  converted from the official
  [AdGuard DNS Filter](https://github.com/AdguardTeam/AdGuardSDNSFilter).
- `rules/GeoIP-CN.list`: China IPv4 and IPv6 CIDR rules.
- `rules/GeoIP-CN-NoResolve.list`: the same CIDR rules with `no-resolve`.

## Conversion policy

The converters only emit a Shadowrocket rule when the source semantics can be
preserved.  Finite, fully anchored hostname regular expressions can be exactly
expanded, with a hard limit of 1,000 results.  Unbounded regexes, contextual
modifiers, URL patterns, and partial Adblock patterns are skipped with build
warnings instead of being widened into approximate wildcard or URL rules.

AdGuard exceptions are resolved before output.  A wildcard exception with a
provable fixed hostname suffix removes every potentially conflicting block in
that suffix.  If a future exception can match a hostname but cannot be safely
represented or conservatively covered, the build fails instead of publishing a
ruleset that may overblock.

For example, the current OpenAI source contains an unbounded
`chatgpt-async-webps-prod` hostname regexp.  Shadowrocket cannot express it as
an equivalent hostname rule, so it is skipped with a diagnostic instead of
being widened to an approximate `DOMAIN-WILDCARD` rule.

Build-only diagnostics are written under `build/`, which is ignored by Git.
Generated `.list` files contain no timestamps, so unchanged upstream content
does not create a commit.

## OpenAI usage

To route the complete OpenAI ruleset through one policy:

```ini
RULE-SET,https://raw.githubusercontent.com/poohyeban/shadowrocket-rules/main/rules/OpenAI.list,OpenAI
```

To assign the upstream `@ads` subset a separate policy, put that narrower rule
before the remaining OpenAI rules because Shadowrocket uses first-match
semantics:

```ini
RULE-SET,https://raw.githubusercontent.com/poohyeban/shadowrocket-rules/main/rules/OpenAI-Ads.list,REJECT
RULE-SET,https://raw.githubusercontent.com/poohyeban/shadowrocket-rules/main/rules/OpenAI-NoAds.list,OpenAI
```

`OpenAI-Ads.list` is not this repository's own judgment that an endpoint is an
advertising domain.  It faithfully exposes only the entries marked with
v2fly's upstream `@ads` metadata, and it does not bind those entries to
`REJECT` or any other policy.

## Licensing

The repository's conversion code is covered by the root MIT license.
`rules/Ad-Domain.list` is derived from AdGuard DNS Filter and remains subject to
the upstream [GNU GPLv3 license](https://github.com/AdguardTeam/AdGuardSDNSFilter/blob/master/LICENSE).
The v2fly and GeoLite-derived outputs remain subject to their respective
upstream data licenses and notices.
