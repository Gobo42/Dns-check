I# DNSCheck Design

## Goal

Build a portable Go CLI that diagnoses DNS-based blocks for a web page. Given a URL, the tool discovers hostnames used by the page, queries a configured DNS server and reference resolvers, follows CNAME chains, identifies blocked names and matching blocklist lines, and prints both human diagnostics and sed commands for removing active blocklist entries.

The tool must not require access to DNS server logs or operational config files. It can use a configured local or HTTPS blocklist source and a configured DNS server that applies the active blocklist.

## Command Shape

The CLI will be a Go application named `dnscheck`.

```sh
dnscheck https://example.com/page
dnscheck --config ./custom.config https://example.com/page
dnscheck --json https://example.com/page
dnscheck --color https://example.com/page
dnscheck -k https://example.com/page
dnscheck --no-crawl https://example.com/page
dnscheck events.launchdarkly.com
dnscheck -v events.launchdarkly.com
dnscheck -vv events.launchdarkly.com
```

Configuration is optional. By default the tool looks for `./dnscheck.config`. If the file is missing, the tool runs with defaults and requires the target URL. Defaults should include public reference resolvers, conservative crawl settings, and dnscrypt-proxy HINFO blocked-response detection.

Command-line arguments take precedence over config file values. Config file values take precedence over built-in defaults.

If the positional target has no URL scheme, the CLI treats it as a bare hostname, normalizes it internally as an HTTPS URL for parsing, and forces effective crawl depth to `0`. This lets `dnscheck events.launchdarkly.com` run DNS checks directly without fetching a page.

## Configuration

The config file controls resolvers, blocklist source, blocked-response detection, DNS retry behavior, and crawl behavior.

Example:

```yaml
dns_servers:
  - name: home
    address: 10.255.255.20:53
    priority: 0

reference_resolvers:
  - name: cloudflare
    address: 1.1.1.1:53
    priority: 0
  - name: cloudflare-doh
    address: https://cloudflare-dns.com/dns-query
    priority: 0
  - name: google
    address: 8.8.8.8:53
    priority: 10

blocklist:
  source: /full/path/to/blocked-names.txt

blocked_signals:
  hinfo_contains:
    - locally blocked
    - dnscrypt-proxy
  blocked_ips:
    - 0.0.0.0
    - 127.0.0.1
  treat_nxdomain_as_blocked: false

dns:
  timeout: 3s
  retries: 2
  max_cname_depth: 10
  max_concurrent_queries: 4

crawl:
  depth: 1
  max_pages: 10
  document_extensions:
    - .html
    - .htm
    - .php
    - .aspx
    - ""
  user_agent: dnscheck/0.1
  insecure_skip_tls_verify: false

output:
  color: false
```

`blocklist.source` can be either a local path or an `http://` / `https://` URL. Local blocklist paths can be used directly in generated sed commands. Remote blocklist sources are used for matching, but sed output warns that a local active blocklist path is needed. If no blocklist source is configured, the tool still performs web discovery and DNS checks, identifies blocked hostnames from resolver responses, and omits blocklist-match and sed-command sections.

HTTPS fetches must use normal certificate verification by default. Certificate mismatch, expired certificate, unknown authority, and related TLS validation problems should produce a clear warning or error. The CLI flag `-k` and config value `crawl.insecure_skip_tls_verify: true` allow the user to ignore certificate validation errors for page, stylesheet, blocklist, and DoH HTTPS requests.

Resolver addresses that start with `https://` use DNS-over-HTTPS. Other resolver addresses use classic DNS over UDP/TCP at the configured host and port.

## Crawl Model

Depth controls document fetching, not DNS checking.

At depth `0`, the tool skips the crawl module entirely. It does not fetch the starting URL document. It extracts only the hostname from the provided URL and DNS-checks that hostname and its CNAME chain. The command-line option `--no-crawl` sets effective crawl depth to `0` regardless of the configured crawl depth.

At depth `1`, the tool fetches only the starting URL document. It extracts hostnames from:

- links
- scripts
- stylesheets
- images
- iframes
- preload and preconnect hints
- CSS `url(...)` references found in fetched document/style content where practical

Every discovered hostname is DNS-checked, including hosts from media and static assets. The tool does not fetch media/static asset bodies for recursion.

At depth `2` or greater, the tool may fetch additional linked document URLs. A URL is document-like if its path extension is configured in `crawl.document_extensions`, including the empty extension for extensionless page routes. The tool can fetch document URLs from any hostname because the purpose is to diagnose third-party page dependencies.

`crawl.max_pages` prevents accidental broad crawling.

## DNS Resolution Model

For each hostname, the tool queries every configured resolver independently:

- primary DNS servers are the servers being diagnosed
- reference resolvers are public or otherwise trusted outside resolvers used for comparison

Resolvers can include `priority`. Lower priority numbers are tried first. Omitted priority defaults to `0`.

For primary DNS servers, resolvers with the same priority are round-robined across hostnames and CNAME follow-up probes. Higher priority numbers are fallback groups and are used only when the lower-priority group fails for that query.

For reference resolvers, same-priority resolvers are queried together. Higher priority numbers are used only when none of the lower-priority reference resolvers returns a usable result.

For each resolver, the tool follows CNAMEs until one of these terminal states occurs:

- one or more IP addresses are reached
- a configured blocked signal is received
- a private/loopback IP address is reached (see Private/Loopback Address Detection)
- `NXDOMAIN` or another terminal DNS response is received
- timeout or network error after configured retries
- `dns.max_cname_depth` is reached

The full chain is recorded per resolver. CNAME chains with four or five levels are expected and should be handled normally.

Blocked detection applies at every chain member, not only the originally discovered hostname. The main default blocked signal is a `NOERROR` response with an `HINFO` answer containing text such as `locally blocked` or `dnscrypt-proxy`, matching dnscrypt-proxy behavior:

```text
events.launchdarkly.com. 10 IN HINFO "This query has been locally blocked" "by dnscrypt-proxy"
```

Other configured signals, such as blocked sinkhole IPs or `NXDOMAIN`, are optional and off by default where ambiguity is likely.

DNS timeouts and errors are recorded per resolver and per hostname. They do not abort the whole run unless the starting URL cannot be processed at all.

DNS-over-HTTPS resolvers follow the same timeout, retry, CNAME traversal, and blocked-response classification rules as classic DNS resolvers. TLS validation for DoH endpoints follows the global HTTPS certificate behavior, including `-k` / `crawl.insecure_skip_tls_verify`.

To avoid hammering external DNS servers, DNS checks are concurrency-limited. The config value `dns.max_concurrent_queries` controls how many resolver queries may run at once across all discovered hosts and configured resolvers. The default is conservative.

Reference chains should print every CNAME target in order when the resolver response contains the full chain. With color enabled, chain hostnames that match the configured blocklist are red and non-matching chain hostnames are green. This makes it clear whether an early CNAME, middle CNAME, or final CNAME is the blocked name.

Every CNAME discovered from reference resolver chains is also queried against the configured primary DNS servers. If those follow-up local probes are blocked, the matching chain member is reported and colored red. If multiple CNAMEs match different blocklist entries, every matched line is listed and every corresponding sed command is emitted.

## Private/Loopback Address Detection

In addition to the configured `blocked_signals`, any `A` record answer that falls in an RFC1918 private range (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) or the full IPv4 loopback range (`127.0.0.0/8`) is classified as its own terminal state, separate from an explicit blocked signal. This catches local sinkhole/redirect DNS blocking that answers with a private address instead of an explicit HINFO or blocked-IP signal. Detection is IPv4-only for the first version; IPv6 loopback (`::1`) and unique local addresses (`fc00::/7`) are not checked.

An explicit `blocked_signals.blocked_ips` match still takes priority over the private/loopback classification when an address matches both — for example, the default `blocked_ips` entry `127.0.0.1` is reported as an explicit `blocked_ip` match rather than a loopback match.

Private/loopback answers are treated as blocked for summary purposes — the host and chain member are shown in the red "Blocked hosts" section the same as an explicit block — but are also called out individually with a yellow warning line naming the specific address and whether it matched the RFC1918 or loopback range, so the two block mechanisms stay distinguishable in the output.

## Crawler DNS Resolution

The web crawler's own page fetches resolve hostnames the same way the diagnostic probe does, instead of going through the OS resolver. Before dialing a hostname it is about to fetch, the crawler queries the primary DNS servers first:

- if the primary answer resolves to a normal address, the crawler connects to that IP
- if the primary answer is blocked, or is a private/loopback address, the crawler falls back to the reference resolvers and connects to their resolved IP instead
- if neither the primary nor the reference resolvers return a usable address, the crawler falls through to normal OS-level DNS resolution rather than failing the fetch outright

The crawler never connects to a blocked sinkhole or private address returned by a resolver — only an address from a clean, non-blocked, non-private result is ever dialed. TLS certificate validation and the `Host` header still use the original hostname; only the underlying connection target changes, so this is invisible to the fetched site.

When no `dns_servers` are configured, the crawler behaves exactly as before, resolving through the OS resolver for every fetch.

Wire-level DNS queries are cached per run and shared between the crawler's lookups and the later diagnostic probe, so a host resolved once while crawling is not queried again during reporting.

## Blocklist Parsing And Matching

The first version supports DNS-style name patterns seen in the active blocklist and blocked-name output:

- exact names, such as `activate.adobe.com`
- leading wildcard names, such as `*.nr-data.net`
- simple label wildcard patterns, such as `ad.*` and `tracker.*`
- blank lines and comments ignored
- generator/header lines ignored

The matcher reports the original blocklist line that matched so the user can remove that exact line from the active blocklist. It does not attempt to implement the full adblock filter language unless future blocklist samples require it.

For every matched blocklist line, the matcher also reports the 1-based source line number. Line numbers are included for both local and remote blocklist sources so the user can inspect the original input quickly.

## Output

Default output is human-readable and grouped into sections.

Example:

```text
Blocked hosts
=============
events.launchdarkly.com
  blocked by resolver: home
  blocked chain member: events.launchdarkly.com
  matched blocklist line: 18542: *.events.launchdarkly.com
  reference chain: events.launchdarkly.com -> launchdarkly.map.fastly.net -> 151.101.x.x

Sed commands
============
sed -i '/^\*\.events\.launchdarkly\.com$/d' /full/path/to/blocked-names.txt

Allowed / not blocked hostnames
===============================
example.com
cdn.example.net
assets.example.org

Resolver errors
===============
slow.example.net
  home: timeout after 3 attempts
```

The sed section escapes regex-sensitive characters and anchors each delete expression so it removes only exact matching blocklist lines. Sed commands are generated for local blocklist sources only. For HTTPS sources, the tool still prints matched blocklist lines and warns that sed output needs a local active blocklist path.

Allowed hostnames are printed for manual allowlist decisions. The tool does not write to runtime allowlists or generator allowlists because it may not have access to operational configuration.

`--json` emits a machine-readable representation of the same information for future scripting.

`--color` or `output.color: true` enables ANSI color in human-readable output. Blocked hosts and blocked chain members, including chain members that resolved to a private/loopback address, are red. Hosts that resolve correctly are green. Warnings, including TLS certificate warnings, ignored TLS verification, and private/loopback DNS answers, are yellow. Color is disabled by default so output remains easy to pipe into other tools.

Runtime progress and diagnostic chatter is written to stderr. The final human-readable or JSON report is written to stdout so bash pipelines can consume it cleanly.

`-v` logs each DNS query to stderr. `-vv` logs each DNS query and the classified DNS result, including CNAMEs, IPs, blocked reason, or error.

## Suggested Go Package Layout

```text
cmd/dnscheck/main.go
internal/config
internal/blocklist
internal/dnsprobe
internal/webscan
internal/report
```

Responsibilities:

- `cmd/dnscheck`: parse CLI flags, load config, run the workflow
- `internal/config`: defaults, config loading, validation
- `internal/blocklist`: source loading, parsing, matching, sed escaping
- `internal/dnsprobe`: classic DNS and DoH resolver clients, retries, CNAME traversal, blocked-response classification, private/loopback address classification
- `internal/webscan`: URL normalization, HTTPS/TLS policy, document fetching, hostname extraction, document-recursion control, dialing through an injected DNS resolution override
- `internal/report`: text, ANSI color, and JSON output formatting

## Testing

Unit tests should cover behavior that is easy to get subtly wrong:

- blocklist parsing and matching for exact names, `*.domain`, `ad.*`, comments, blank lines, and headers
- blocklist source line-number reporting
- sed escaping and exact-line anchoring
- DNS result classification for HINFO blocked responses, CNAME chains, timeout, NXDOMAIN, and IP terminal states
- DNS classification for private/loopback IPv4 addresses (RFC1918 ranges and the full `127.0.0.0/8` range), including precedence against an explicit `blocked_ips` match, and that CNAME traversal stops cleanly on a private answer instead of running to `max_cname_depth`
- DNS concurrency limiting so discovered hosts do not hammer external resolvers
- resolver priority and fallback behavior for primary and reference DNS servers
- crawler DNS resolution: primary-first resolution, fallback to reference resolvers only on a blocked or private primary answer, and that the crawler never dials a sinkhole or private address
- shared DNS query cache between the crawler and the diagnostic probe so a host resolved once is not queried again
- reference-chain output where only blocklist-matching CNAME members are red
- follow-up local DNS probes for every CNAME discovered from reference resolvers
- verbose stderr logging for each DNS query with `-v` and each DNS query/result with `-vv`
- DoH resolver selection when a resolver address starts with `https://`
- HTTPS certificate validation failures and `-k` / `crawl.insecure_skip_tls_verify`
- crawl depth `0` where the page fetch is skipped and only the input URL hostname is checked
- bare hostname input where the CLI forces no-crawl DNS checking
- crawl extraction for links, scripts, images, stylesheets, preload hints, and CSS URLs
- document recursion where depth `1` fetches only the starting page and depth `2` fetches only document-like linked URLs
- output colorization where blocked entries are red and resolved entries are green

Integration-style tests should avoid hard dependencies on live DNS by default. Use mock resolver interfaces or a local fake DNS server for automated tests, and Go `httptest` pages for web crawling.

Manual or optional local integration tests can use the user's test DNS server and a sample blocklist file placed in the working directory. These tests should be opt-in so the normal test suite remains portable.

## Non-Goals For The First Version

- editing allowlists or operational DNS server configuration
- reading DNS server logs
- implementing the complete adblock filter syntax
- recursively fetching media/static asset bodies
- deleting blocklist entries automatically
- crawling the open web without `crawl.max_pages`
- disabling TLS verification by default
- IPv6 loopback (`::1`) or unique local address (`fc00::/7`) detection
