# shadowrocket-rules

This repository generates deterministic rulesets for Shadowrocket from several
public and manually reviewed data sources.

The goal is not to convert as many source rules as possible. A rule is emitted
only when the converter can preserve its meaning safely, or when a documented
design boundary has been deliberately accepted. Rules that cannot be expressed
reliably are skipped with diagnostics, or cause the pipeline to fail closed,
rather than being guessed, widened, or silently approximated.

**Correctness over coverage.** Generated rulesets are useful inputs for a
Shadowrocket configuration, but this repository does not claim that every
upstream rule is representable or that every runtime behavior has been tested.

## Quick Start

For most configurations, use the `no-resolve` variants for China and OpenAI,
plus the AdGuard hostname ruleset:

```ini
RULE-SET,https://raw.githubusercontent.com/poohyeban/shadowrocket-rules/main/rules/China/China-NoResolve.list,China
RULE-SET,https://raw.githubusercontent.com/poohyeban/shadowrocket-rules/main/rules/OpenAI/OpenAI-NoResolve.list,OpenAI
RULE-SET,https://raw.githubusercontent.com/poohyeban/shadowrocket-rules/main/rules/AdGuard/Ad-Domain.list,REJECT
```

The policy names above are examples. Choose policy or proxy-group names that
fit your own configuration. Regular variants without the `no-resolve` modifier
are also available as `China.list` and `OpenAI.list`.

## Available Rulesets

### China

- [`rules/China/China.list`](rules/China/China.list) combines v2fly China domain
  rules with China IPv4 and IPv6 networks extracted from GeoLite2 Country.
- [`rules/China/China-NoResolve.list`](rules/China/China-NoResolve.list) contains
  the same domain and IP sets, but every `IP-CIDR` and `IP-CIDR6` rule carries
  `no-resolve`.

### OpenAI

- [`rules/OpenAI/OpenAI.list`](rules/OpenAI/OpenAI.list) combines OpenAI-related
  v2fly domains, a filtered routing subset derived from the reviewed OpenAI Help
  Center allowlist, explicitly tracked OpenAI-owned ASN networks, and official
  ChatGPT Voice IP prefixes.
- [`rules/OpenAI/OpenAI-NoResolve.list`](rules/OpenAI/OpenAI-NoResolve.list)
  contains the same logical domain and IP sets, but every IP rule carries
  `no-resolve`.

### AdGuard

- [`rules/AdGuard/Ad-Domain.list`](rules/AdGuard/Ad-Domain.list) is a derived,
  hostname-level subset of AdGuard DNS Filter. It contains only rules that the
  converter can map safely to supported Shadowrocket hostname rules. It is not
  a complete implementation of the AdGuard filtering engine.

## Repository Architecture

```text
rules/
├── China/
│   ├── China.list
│   ├── China-NoResolve.list
│   └── Sources/
│       ├── China-v2fly-Domain.list
│       ├── China-GeoIP.list
│       └── China-GeoIP-NoResolve.list
│
├── OpenAI/
│   ├── OpenAI.list
│   ├── OpenAI-NoResolve.list
│   └── Sources/
│       ├── OpenAI-v2fly.list
│       ├── OpenAI-Official-Domain.list
│       ├── OpenAI-ASN-IP.list
│       ├── OpenAI-ASN-IP-NoResolve.list
│       ├── OpenAI-Voice-IP.list
│       └── OpenAI-Voice-IP-NoResolve.list
│
└── AdGuard/
    └── Ad-Domain.list
```

Aggregate files such as `China.list` and `OpenAI.list` are the normal user-facing
rulesets. Files under `Sources/` preserve provenance and remain useful for
auditing, debugging, development, or individual use. They are not deprecated
compatibility files.

## Data Sources

### China

#### Domains

China domain rules come from the release export of
[`v2fly/domain-list-community`](https://github.com/v2fly/domain-list-community):

```text
https://raw.githubusercontent.com/v2fly/domain-list-community/release/cn.txt
```

The v2fly converter maps supported source types as follows:

| v2fly input | Shadowrocket output |
| --- | --- |
| `domain:example.cn` or an untyped hostname | `DOMAIN-SUFFIX,example.cn` |
| `full:www.example.cn` | `DOMAIN,www.example.cn` |
| `keyword:example` | `DOMAIN-KEYWORD,example` |
| provably finite, anchored hostname regexp | one or more exact `DOMAIN` rules |

#### Networks

China IP networks come from
[`P3TERX/GeoLite.mmdb`](https://github.com/P3TERX/GeoLite.mmdb), using
`GeoLite2-Country.mmdb`. The converter selects database records whose country
ISO code is exactly `CN`, then emits their IPv4 and IPv6 networks.

These are China networks according to the GeoLite2 data used by the pipeline.
They are not a repository-maintained or authoritative inventory of every
address used on the Chinese Internet.

### OpenAI

OpenAI is a routing-oriented, multi-source aggregate. It is not a verbatim copy
of one upstream and is not an OpenAI enterprise firewall allowlist:

```text
OpenAI.list
|
+-- v2fly OpenAI domains
|   `-- only safely convertible entries
|
+-- reviewed OpenAI Help Center domains
|   +-- full snapshot stored in official-domains.txt
|   `-- shared or uncertain dependencies removed by
|       official-domains-excluded.txt
|
+-- explicitly tracked OpenAI ASN networks
|
`-- official ChatGPT Voice IP prefixes
```

`OpenAI-NoResolve.list` contains the same logical rules. Its `IP-CIDR` and
`IP-CIDR6` entries additionally carry `no-resolve`.

#### v2fly domains

[`OpenAI-v2fly.list`](rules/OpenAI/Sources/OpenAI-v2fly.list) is converted from:

```text
https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/openai
```

#### Reviewed official domains

OpenAI publishes an allowlist in its Help Center article
[Network recommendations for ChatGPT errors on web and apps](https://help.openai.com/en/articles/9247338-network-recommendations-for-chatgpt-errors-on-web-and-apps).
The Help Center list describes dependencies to allow for OpenAI and ChatGPT
functionality. It is not an authoritative inventory of domains owned by OpenAI.
The workflow does **not** scrape this page. Instead, the repository maintains:

- [`data/OpenAI/official-domains.txt`](data/OpenAI/official-domains.txt), the
  complete manually reviewed snapshot of the documented allowlist; and
- [`data/OpenAI/official-domains-excluded.txt`](data/OpenAI/official-domains-excluded.txt),
  the explicit source entries that this repository does not classify as OpenAI
  traffic by default.

The generated
[`OpenAI-Official-Domain.list`](rules/OpenAI/Sources/OpenAI-Official-Domain.list)
is the exact normalized source-entry set difference:

```text
official-domains.txt - official-domains-excluded.txt
```

At the current reviewed snapshot, all 29 documented entries remain in the full
snapshot, 16 entries are excluded from default routing, and 13 entries are
retained in the generated routing subset. Exclusions use exact source-entry
matching after normalization. They do not trigger suffix inference, wildcard
expansion, or semantic compression.

The exclusion snapshot may contain zero active entries. An empty or
comments-only exclusion file means that no reviewed Help Center entries are
excluded from routing.

The documented allowlist includes shared infrastructure from providers such as
Cloudflare, WorkOS, Intercom, Stripe, Sentry, Datadog, SendGrid, and Apple.
These dependencies remain recorded in the complete snapshot because ChatGPT
may use them for authentication, challenges, telemetry, support, payments,
email, or other functionality. Routing an entire shared hostname or namespace
through an OpenAI policy could also capture unrelated traffic from other sites
or applications, so the default routing aggregate excludes them.

`cdn.openaimerge.com` is listed by OpenAI, but its ownership or dedicated-use
status has not been established sufficiently for this repository's strict
routing policy. It is currently excluded pending manual review; reliable
evidence that it is OpenAI-controlled or dedicated OpenAI infrastructure would
justify reviewing that decision.

Excluded entries are not useless or erroneous. Users whose network design
requires those dependencies to follow the same route can add them separately.
Conversely, exclusions apply only to the Help Center source and do not filter an
independently sourced v2fly rule with the same hostname.

**Do not use `OpenAI.list` or `OpenAI-NoResolve.list` as a replacement for
OpenAI's current enterprise firewall allowlist.** For complete ChatGPT
dependency allowlisting, consult the current official documentation. This
repository optimizes for traffic-routing precision, not maximum functionality
allowlisting coverage.

The Help Center HTML is not a stable, reliable machine-readable CI source, and
command-line fetching has previously returned HTTP 403. Manual maintenance is
therefore a deliberate fail-safe choice rather than a fragile scraping
dependency. When the official page changes, a maintainer must review it, update
the repository snapshot and its verification metadata, regenerate the derived
file, and commit the reviewed change. The snapshot can consequently be briefly
stale between an upstream change and the next manual review.

Official wildcard scope is preserved. For example:

```text
*.example.com
```

becomes:

```text
DOMAIN-WILDCARD,*.example.com
```

It is not widened to `DOMAIN-SUFFIX,example.com`, because a suffix rule may also
cover the apex `example.com`, which the original wildcard does not necessarily
express.

#### OpenAI-owned ASN networks

[`OpenAI-ASN-IP.list`](rules/OpenAI/Sources/OpenAI-ASN-IP.list) and its
`no-resolve` variant are generated from `GeoLite2-ASN.mmdb`, also provided by
[`P3TERX/GeoLite.mmdb`](https://github.com/P3TERX/GeoLite.mmdb). The workflow
explicitly tracks only:

- AS401518
- AS401864

These are explicitly selected OpenAI-owned ASNs, not a claim to cover all
infrastructure used by OpenAI.

#### ChatGPT Voice prefixes

[`OpenAI-Voice-IP.list`](rules/OpenAI/Sources/OpenAI-Voice-IP.list) and its
`no-resolve` variant are automatically synchronized from OpenAI's official,
machine-readable source:

```text
https://openai.com/chatgpt-voice.json
```

The converter validates the JSON structure, timestamp, prefix fields, CIDR
syntax, and IP version before publishing IPv4 or IPv6 rules.

### AdGuard

AdGuard rules come from the official
[`AdGuard DNS Filter`](https://github.com/AdguardTeam/AdGuardSDNSFilter):

```text
https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt
```

AdGuard syntax is substantially richer than Shadowrocket hostname rules. This
repository derives a safe hostname-level representation; it does not reproduce
all AdGuard matching, modifier, exception, or filtering-engine behavior.

## Conversion Philosophy

### Conservative conversion

Supported inputs are normalized and validated before output. Unsupported rules
are skipped with a reason when omission is safer than approximation. Conditions
that could publish an incomplete or incorrectly overblocking ruleset may fail
the entire run instead.

The converters do not introduce speculative `DOMAIN-WILDCARD`, `URL-REGEX`,
`SCRIPT`, domain hierarchy compression, or broader suffix rules merely to
increase coverage.

### Exact finite regexp expansion

A regexp is eligible for conversion only when it is:

- anchored with both `^` and `$`;
- finite under the converter's deliberately small grammar;
- expandable to at most 1,000 results; and
- composed entirely of outputs that normalize to valid hostnames without
  collapsing distinct regexp results.

Finite alternation can therefore be expanded exactly. For example,
`^(foo|bar)\.example\.com$` becomes two exact `DOMAIN` rules. Patterns using
unbounded constructs such as `.+`, `.*`, `\S+`, `*`, `+`, or another quantifier
without a finite upper bound are not enumerable and are skipped. If expansion
exceeds 1,000 results, or any result is not a valid hostname, the regexp is not
converted.

This is an exact-language check, not a heuristic regexp-to-wildcard translator.

### AdGuard handling

The AdGuard converter recognizes a conservative subset of plain hostname,
domain-anchor, blocking-hosts, finite regexp, `badfilter`, and exception
semantics. URL/path patterns, unsupported wildcard forms, contextual modifiers,
cosmetic constructs, and other syntax are not made unconditional hostname
rules.

Exceptions are resolved before output. If an exception can be covered safely,
conflicting block rules are removed. If an exception might apply to a hostname
but cannot be represented or conservatively covered without risking
overblocking, conversion fails closed rather than publishing a ruleset that
would violate the exception.

### Deterministic output

Generated lists use canonical values, exact deduplication, deterministic
ordering, UTF-8, LF line endings, and no generated timestamp or header. Merge
steps perform exact deduplication only; they do not apply domain hierarchy or
suffix compression.

Build-only diagnostics are written below `build/`, which is ignored by Git.
When upstream content is unchanged, regeneration should therefore produce no
meaningless ruleset commit.

## Source Files vs Aggregate Files

China aggregates are defined as:

```text
China.list
  = China-v2fly-Domain.list + China-GeoIP.list

China-NoResolve.list
  = China-v2fly-Domain.list + China-GeoIP-NoResolve.list
```

OpenAI aggregates are defined as:

```text
OpenAI.list
  = OpenAI-v2fly.list
  + OpenAI-Official-Domain.list
  + OpenAI-ASN-IP.list
  + OpenAI-Voice-IP.list

OpenAI-NoResolve.list
  = OpenAI-v2fly.list
  + OpenAI-Official-Domain.list
  + OpenAI-ASN-IP-NoResolve.list
  + OpenAI-Voice-IP-NoResolve.list
```

For each regular/`no-resolve` pair, the workflow validates that:

- the domain-rule sets are identical;
- the IP-rule sets are identical after removing `,no-resolve`;
- regular IP rules do not contain `no-resolve`; and
- every IP rule in the `no-resolve` aggregate contains it.

`no-resolve` changes only the IP rule modifier; it does not define a different
domain or network set.

## Known Limitations

| Area | Limitation | Current behavior | Possible future direction |
| --- | --- | --- | --- |
| v2fly regexp | Some hostname languages are unbounded or not fully anchored | Skip with `unsafe-regexp` diagnostics | Add more exact, provably finite mappings |
| OpenAI official domains | The Help Center allowlist includes shared dependencies and is manually reviewed rather than synchronized by CI | Preserve the complete snapshot, then publish its exact difference from explicit routing exclusions | Review exclusions and investigate reliable change detection without fragile scraping |
| OpenAI v2fly regexp | The current `\S+` Web PubSub rule is unbounded | Skip without wildcard approximation | Revisit only if an exact representation becomes available |
| ChatGPT Voice | CIDR rules do not constrain protocol or destination port | Deliberately match all traffic to listed Voice prefixes | Test reliable compound Shadowrocket rules before narrowing |
| OpenAI ASN | GeoLite2 ASN data may lag live routing and covers only tracked ASNs | Emit prefixes found for AS401518 and AS401864 | Periodically review ASN ownership and mapping freshness |
| AdGuard | Much of the source grammar has no equivalent hostname primitive | Publish a safe subset; fail closed for unsafe exceptions | Expand only semantics that can be proven safe |
| `DOMAIN-REGEX` | A tested Shadowrocket build did not persist manually entered rules | Do not generate `DOMAIN-REGEX` | Re-test future builds and document version-specific results |
| WebSocket runtime | Test Rule behavior does not establish real WS/WSS routing behavior | Make no general runtime claim | Perform controlled runtime tests |
| v2fly `include:` | Recursive include resolution is not implemented for OpenAI | Fail the OpenAI workflow guard on a valid directive | Implement and test a safe recursive resolver |

### Current v2fly China regexp gaps

The current `cn.txt` observed during maintenance contains at least these rules
that cannot be converted strictly:

```text
regexp:.+\.awsdns-cn-[0-9][0-9]\.(biz|com|net|top)$:@cn
regexp:.+\.awsdns-cn-[0-9][a-e0-9]\.cn$:@cn
regexp:^.+-mihayo\.akamaized\.net$:@cn
```

The first two are not anchored at both ends. All three also depend on an
unbounded wildcard alphabet that cannot be enumerated as a finite set of valid
hostnames. They are omitted from the generated China ruleset and recorded in
build diagnostics. Approximating them with `DOMAIN-WILDCARD` could introduce
false positives, so the converter does not do so.

This is a known coverage limitation. It can be revisited if Shadowrocket gains
appropriate hostname-regexp support or the converter can prove a new exact
mapping.

### Current OpenAI v2fly regexp gap

The current v2fly OpenAI source contains:

```text
regexp:^chatgpt-async-webps-prod-\S+-\d+\.webpubsub\.azure\.com$
```

The converter skips it with `unsafe-regexp: unsupported escape: \S`. The `\S+`
language is unbounded and cannot be enumerated exactly. It is not translated to
`DOMAIN-WILDCARD`, `URL-REGEX`, or `SCRIPT`.

Replacing `\S+` with `[^.]+` would not be strictly equivalent: `\S` can match a
dot, whereas `[^.]` cannot. This remains an explicit coverage limitation.

### ChatGPT Voice protocol and port widening

OpenAI's network guidance describes UDP port 3478 as preferred for ChatGPT
Voice, with TCP port 443 as fallback. The official JSON supplies server IP
prefixes, and this repository currently emits those prefixes as `IP-CIDR` or
`IP-CIDR6` rules.

Those rules match traffic to the listed IP networks without preserving the
documented protocol and port conditions. This is a deliberate semantic widening
accepted by the current design, not an exact representation of the official
network requirement. Compound forms involving `AND`, `PROTOCOL`,
`DEST-PORT`/`DST-PORT`, `SCRIPT`, or similar features should not be introduced
until their Shadowrocket runtime behavior has been tested reliably.

### OpenAI ASN scope and freshness

GeoLite2 ASN data is not a real-time BGP authority, so an ASN-to-prefix mapping
may lag live Internet routing. The tracked ASNs also do not represent every
network that can carry OpenAI traffic.

OpenAI relies on third-party infrastructure such as Azure, Cloudflare, and
other SaaS/CDN providers. That does not justify adding all of AS8075, all of
Microsoft, all of Cloudflare, all of Vultr, or another broad provider network.
The repository intentionally avoids that kind of overmatching.

### AdGuard subset boundary

AdGuard input may contain URL and path patterns, regular expressions, wildcard
forms, modifiers such as `important`, `badfilter`, contextual conditions,
exceptions, hosts/IP rules, and cosmetic or other non-DNS constructs.

Only the portion that can be mapped safely to hostname-level Shadowrocket rules
is emitted. Unsupported rules are diagnosed and skipped. Exceptions receive
stricter treatment: when an applicable exception cannot be handled safely, the
converter refuses to publish rather than risk false-positive blocking.

`Ad-Domain.list` is therefore a safe derived subset, not the complete AdGuard
DNS Filter.

### Shadowrocket Test Rule versus runtime behavior

Manual **Test Rule** experiments performed during development indicated that:

- `DOMAIN`, `DOMAIN-SUFFIX`, and `DOMAIN-KEYWORD` do not interpret their values
  as regular expressions;
- `DOMAIN-WILDCARD` is wildcard matching, not regexp matching;
- in that tested interface, `*` matched zero or more characters, `?` matched
  one character, and wildcard matching could cross `.` boundaries; and
- `URL-REGEX` matched HTTP/HTTPS URLs in Test Rule.

These observations are not a proof of all Shadowrocket runtime behavior. In
particular, Test Rule results for `ws://` or `wss://` inputs do not establish
how real WebSocket connections are routed at runtime. This repository does not
infer universal WS/WSS behavior from that interface.

In the specific Shadowrocket build tested during development, a manually entered
`DOMAIN-REGEX` rule disappeared after the configuration was saved and reopened.
The repository therefore does not generate `DOMAIN-REGEX`. This is a
build-specific observation, not a claim that every Shadowrocket version will
always reject or remove that rule type.

## Automation and Updates

The [Update Shadowrocket Rules workflow](.github/workflows/update.yml) runs on
two daily schedules, currently 05:17 and 06:18 Asia/Taipei. The second run acts
as a fallback opportunity; neither schedule is a guarantee that upstream
services or the network will always be available. Maintainers can also start the
same workflow with `workflow_dispatch`.

Each run:

1. checks out the repository and installs the pinned MMDB dependency;
2. runs the full unit-test suite before generation;
3. downloads the configured machine-readable upstream sources with retries and
   non-empty checks;
4. converts and validates individual source files;
5. merges China and OpenAI aggregates;
6. validates regular/`no-resolve` equivalence;
7. stages only `rules/`; and
8. commits and pushes only when generated rule content changed.

When generation matches the tracked files exactly, the commit step reports
`No rule changes detected.` and exits successfully without creating a commit.

An upstream, schema, download, conversion, or validation failure stops the run
instead of committing a partially generated ruleset. The workflow never stages
`build/`, and it does not automatically modify the manually maintained OpenAI
domain snapshot or routing-exclusion snapshot.

The OpenAI v2fly source has an additional case-insensitive fail-closed guard for
valid `include:` directives. Recursive include resolution is not implemented;
publishing only the directly downloaded file would be incomplete, so the run
fails instead of letting the converter silently skip the directive.

## Maintenance Notes

Converter warnings are evidence about coverage and upstream syntax changes, not
mere log noise. Examples include:

- `unsafe-regexp`
- `unsupported-adguard-pattern`
- `modifier-changes-or-conditions-hostname-semantics`

Review workflow warning summaries and build-only files such as
`build/unsupported-*.txt` when an upstream changes. A new warning may identify a
safe converter capability worth adding, a source-semantic change, or an input
that must remain unsupported.

When reviewing the OpenAI Help Center allowlist, update
`data/OpenAI/official-domains.txt` manually, preserve its source and verification
metadata, review `data/OpenAI/official-domains-excluded.txt` against the new
snapshot, regenerate `OpenAI-Official-Domain.list`, run the tests, and review the
exact diff. Every exclusion must still exist in the full snapshot or conversion
fails closed. Do not make CI depend on unaudited HTML scraping.

Tracked OpenAI ASN ownership and GeoLite2 mappings should also be reviewed
periodically. Third-party infrastructure should be added only with a narrowly
defined and auditable scope, never merely because one OpenAI request happened to
traverse a large shared provider.

## Development Notes and Future Improvements

Possible future work, without a promised timeline:

1. Implement safe, recursive v2fly `include:` resolution with cycle detection
   and explicit tests.
2. Extend exact finite regexp conversion where a complete hostname language can
   still be proven and bounded.
3. Re-evaluate the unsupported v2fly China regexp rules without replacing them
   with broader wildcard guesses.
4. Investigate reliable Shadowrocket runtime behavior for `AND`, protocol, port,
   and compound rules.
5. Perform controlled runtime testing for WebSocket and ChatGPT Voice traffic.
6. Explore reliable detection of changes to the OpenAI Help Center allowlist
   without making CI depend on fragile page scraping.
7. Improve provenance metadata outside generated `.list` files.
8. Re-check tracked OpenAI ASNs and ASN-to-prefix freshness periodically.
9. Expand regression tests when upstream syntax or schemas change.

The roadmap intentionally does not propose converting every regexp. Some source
languages cannot be represented exactly by the currently used Shadowrocket
primitives.

## Licensing

The repository's conversion code is covered by the root MIT license.
`rules/AdGuard/Ad-Domain.list` is derived from AdGuard DNS Filter and remains
subject to the upstream
[GNU GPLv3 license](https://github.com/AdguardTeam/AdGuardSDNSFilter/blob/master/LICENSE).
The v2fly- and GeoLite-derived outputs remain subject to their respective
upstream data licenses and notices.
