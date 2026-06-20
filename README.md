# dnscheck

`dnscheck` diagnoses DNS blocks for a URL by discovering page hostnames, querying a configured DNS server and reference resolvers, following CNAME chains, and reporting blocked names.

## Usage

```sh
dnscheck https://example.com
dnscheck --config dnscheck.config --color https://example.com
dnscheck --no-crawl https://events.launchdarkly.com
dnscheck events.launchdarkly.com
dnscheck -k https://self-signed.example.local
dnscheck -v events.launchdarkly.com
dnscheck -vv events.launchdarkly.com
dnscheck --json https://example.com
```

By default the tool looks for `./dnscheck.config`. Command-line flags override config values.
Options may appear before or after the target, so `dnscheck example.com -v` is equivalent to `dnscheck -v example.com`.

Run `dnscheck` without a target to print the help menu.

Runtime progress is written to stderr. The final human-readable or JSON report is written to stdout so it can be piped safely.

If no blocklist is configured, `dnscheck` still identifies blocked hostnames from DNS responses but skips sed-command output.
Local blocklist paths support `~`, such as `~/blocked-names.txt`.
Invalid blocklist lines are skipped with a stderr warning that includes the line number, entry text, and reason.
Plain domain rules match the domain and its subdomains, so `mmstat.com` matches both `mmstat.com` and `sg.mmstat.com`.

If the target has no URL scheme, `dnscheck` treats it as a bare hostname and skips crawling automatically.

With `--color`, reference-chain hostnames that match the blocklist are red, while other resolved CNAME names are green. This helps identify whether the original hostname, an early CNAME, or a later CNAME is responsible for the block.

Every CNAME discovered from reference resolvers is also queried against the configured local DNS servers. If multiple CNAMEs hit different blocklist entries, all matching blocklist lines and sed commands are listed.

Use `-v` to write crawler fetch/extraction summaries and each DNS query to stderr. Use `-vv` to also write per-link crawler discovery details and each classified DNS result to stderr.

## Resolver Priority

Resolvers can include `priority`. Lower numbers are preferred. Omitted priority defaults to `0`.

For `dns_servers`, resolvers with the same priority are round-robined across hostnames and CNAME follow-up probes. Higher priority numbers are fallback groups and are used only when the lower-priority resolver group fails for that query.

For `reference_resolvers`, same-priority resolvers are queried together. Higher priority numbers are used only when none of the lower-priority reference resolvers returns a usable DNS result.

## DNS Load

`dns.max_concurrent_queries` limits how many resolver queries run at once across discovered hosts and configured resolvers. The default is conservative so reference resolvers are not hammered by large pages.

Within a run, DNS responses are cached per resolver address, query type, and hostname. If multiple discovered hosts CNAME to the same parent, the shared parent is only looked up once on that resolver.

## Manual Integration Test

Place a blocklist sample in the working directory and configure `dns_servers` to point at the test DNS server. Then run:

```sh
go run ./cmd/dnscheck --config dnscheck.config --color https://example.com
```
