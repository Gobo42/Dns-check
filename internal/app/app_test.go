package app

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dnscheck/internal/blocklist"
	"dnscheck/internal/config"
	"dnscheck/internal/dnsprobe"
	"dnscheck/internal/report"
	"github.com/miekg/dns"
)

func TestParseFlagsNoCrawlOverridesConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "dnscheck.config")
	if err := os.WriteFile(cfgPath, []byte("crawl:\n  depth: 3\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	opts, cfg, err := Parse([]string{"--config", cfgPath, "--no-crawl", "--color", "-k", "https://example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.URL != "https://example.com" {
		t.Fatalf("url = %q", opts.URL)
	}
	if cfg.Crawl.Depth != 0 {
		t.Fatalf("crawl depth = %d, want 0", cfg.Crawl.Depth)
	}
	if !cfg.Output.Color {
		t.Fatal("expected color override")
	}
	if !cfg.Crawl.InsecureSkipTLSVerify {
		t.Fatal("expected -k override")
	}
}

func TestParseVerboseFlags(t *testing.T) {
	opts, _, err := Parse([]string{"-vv", "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Verbose != 2 {
		t.Fatalf("verbose = %d, want 2", opts.Verbose)
	}
}

func TestParseFlagsAfterHostname(t *testing.T) {
	opts, cfg, err := Parse([]string{"example.com", "-v", "--color", "--no-crawl"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Verbose != 1 {
		t.Fatalf("verbose = %d, want 1", opts.Verbose)
	}
	if !cfg.Output.Color {
		t.Fatal("expected trailing --color to apply")
	}
	if cfg.Crawl.Depth != 0 {
		t.Fatalf("crawl depth = %d, want 0", cfg.Crawl.Depth)
	}
}

func TestParseConfigFlagAfterHostname(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "dnscheck.config")
	if err := os.WriteFile(cfgPath, []byte("output:\n  color: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	opts, cfg, err := Parse([]string{"example.com", "--config", cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	if opts.ConfigPath != cfgPath {
		t.Fatalf("config path = %q, want %q", opts.ConfigPath, cfgPath)
	}
	if !cfg.Output.Color {
		t.Fatal("expected trailing --config value to load")
	}
}

func TestParseBareHostnameForcesNoCrawl(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "dnscheck.config")
	if err := os.WriteFile(cfgPath, []byte("crawl:\n  depth: 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	opts, cfg, err := Parse([]string{"--config", cfgPath, "events.launchdarkly.com"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.URL != "https://events.launchdarkly.com" {
		t.Fatalf("url = %q, want normalized https URL", opts.URL)
	}
	if cfg.Crawl.Depth != 0 {
		t.Fatalf("crawl depth = %d, want 0 for bare hostname", cfg.Crawl.Depth)
	}
}

func TestRunRequiresURL(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := Main([]string{}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("expected help without error, got %v", err)
	}
	if !strings.Contains(stderr.String(), "Usage: dnscheck [options] <url-or-hostname>") {
		t.Fatalf("stderr missing usage help:\n%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestRuntimeOutputGoesToStderr(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := Main([]string{"--no-crawl", "https://example.com"}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout.String(), "checking ") {
		t.Fatalf("stdout contains runtime output:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "checking ") {
		t.Fatalf("stderr missing runtime output:\n%s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "Blocked hosts") {
		t.Fatalf("stdout missing final report:\n%s", stdout.String())
	}
}

func TestBlocklistParseErrorsGoToStderr(t *testing.T) {
	dir := t.TempDir()
	blocklistPath := filepath.Join(dir, "blocked.txt")
	cfgPath := filepath.Join(dir, "dnscheck.config")
	if err := os.WriteFile(blocklistPath, []byte("good.example\nbad entry\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte("blocklist:\n  source: "+blocklistPath+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := Main([]string{"--config", cfgPath, "example.com"}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), `blocklist parse error line 2: bad entry`) {
		t.Fatalf("stderr missing blocklist parse error:\n%s", stderr.String())
	}
}

func TestBareHostnameRuntimeOutputSaysDNSOnly(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := Main([]string{"example.com"}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stderr.String(), "scanning https://example.com") {
		t.Fatalf("stderr should not claim page scanning in bare-host mode:\n%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "dns-only check example.com") {
		t.Fatalf("stderr missing dns-only message:\n%s", stderr.String())
	}
}

func TestBlocklistMatchesIncludeReferenceCNAMEChainMembers(t *testing.T) {
	list, err := blocklist.Parse(strings.NewReader("*.example2.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	results := []dnsprobe.ResolverResult{{
		Status: dnsprobe.StatusResolved,
		Steps: []dnsprobe.ChainStep{{
			Name: "server1.example.com",
			Classification: dnsprobe.Classification{
				Status: dnsprobe.StatusResolved,
				CNAMEs: []string{
					"server1.example1.com",
					"server1.example2.com",
					"server1.example3.com",
				},
				IPs: []string{"203.0.113.10"},
			},
		}},
	}}

	matches, blockedNames := matchesForHostAndChainMembers(list, "server1.example.com", nil, results)
	if len(matches) != 1 || matches[0].Text != "*.example2.com" {
		t.Fatalf("matches = %#v, want *.example2.com", matches)
	}
	if len(blockedNames) != 1 || blockedNames[0] != "server1.example2.com" {
		t.Fatalf("blocked names = %#v, want server1.example2.com", blockedNames)
	}
}

func TestCollectReferenceCNAMEsForLocalReprobe(t *testing.T) {
	results := []report.HostResult{
		{
			Reference: []dnsprobe.ResolverResult{{
				Status: dnsprobe.StatusResolved,
				Steps: []dnsprobe.ChainStep{{
					Name: "server1.example.com",
					Classification: dnsprobe.Classification{
						Status: dnsprobe.StatusResolved,
						CNAMEs: []string{
							"server1.example1.com",
							"server1.example2.com",
							"server1.example3.com",
						},
						IPs: []string{"203.0.113.10"},
					},
				}},
			}},
		},
	}

	got := collectReferenceCNAMEs(results)
	want := []string{"server1.example1.com", "server1.example2.com", "server1.example3.com"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("cnames = %#v, want %#v", got, want)
	}
}

func TestSelectLocalPriorityRoundRobinAndFallback(t *testing.T) {
	groups := []resolverGroup{
		{Priority: 0, Resolvers: []resolverRef{{Name: "home-a"}, {Name: "home-b"}}},
		{Priority: 10, Resolvers: []resolverRef{{Name: "home-fallback"}}},
	}
	probe := func(resolver resolverRef, host string) dnsprobe.ResolverResult {
		status := dnsprobe.StatusResolved
		if host == "needs-fallback.example" && (resolver.Name == "home-a" || resolver.Name == "home-b") {
			status = dnsprobe.StatusError
		}
		return dnsprobe.ResolverResult{ResolverName: resolver.Name, Status: status}
	}

	results := probeLocalPriorityGroups([]string{"a.example", "b.example", "needs-fallback.example"}, groups, probe)

	if results[0].Results[0].ResolverName != "home-a" {
		t.Fatalf("first host resolver = %s, want home-a", results[0].Results[0].ResolverName)
	}
	if results[1].Results[0].ResolverName != "home-b" {
		t.Fatalf("second host resolver = %s, want home-b", results[1].Results[0].ResolverName)
	}
	if got := results[2].Results[len(results[2].Results)-1].ResolverName; got != "home-fallback" {
		t.Fatalf("fallback resolver = %s, want home-fallback", got)
	}
}

func resolvedResult(ip string) dnsprobe.ResolverResult {
	return dnsprobe.ResolverResult{
		Status: dnsprobe.StatusResolved,
		Steps:  []dnsprobe.ChainStep{{Classification: dnsprobe.Classification{Status: dnsprobe.StatusResolved, IPs: []string{ip}}}},
	}
}

func blockedResult(sinkholeIP string) dnsprobe.ResolverResult {
	return dnsprobe.ResolverResult{
		Status: dnsprobe.StatusBlocked,
		Steps:  []dnsprobe.ChainStep{{Classification: dnsprobe.Classification{Status: dnsprobe.StatusBlocked, IPs: []string{sinkholeIP}}}},
	}
}

func privateResult(privateIP string) dnsprobe.ResolverResult {
	return dnsprobe.ResolverResult{
		Status: dnsprobe.StatusPrivate,
		Steps:  []dnsprobe.ChainStep{{Classification: dnsprobe.Classification{Status: dnsprobe.StatusPrivate, IPs: []string{privateIP}}}},
	}
}

func TestNewCrawlResolveNoDNSServersConfigured(t *testing.T) {
	probe := func(resolver resolverRef, host string) dnsprobe.ResolverResult {
		t.Fatal("probe should not be called when no dns_servers are configured")
		return dnsprobe.ResolverResult{}
	}
	resolve := newCrawlResolve(nil, []resolverGroup{{Resolvers: []resolverRef{{Name: "ref"}}}}, probe)

	ip, ok := resolve(context.Background(), "example.com")
	if ok || ip != "" {
		t.Fatalf("resolve = (%q, %v), want (\"\", false)", ip, ok)
	}
}

func TestNewCrawlResolveReturnsPrimaryIPWhenResolved(t *testing.T) {
	primaryGroups := []resolverGroup{{Resolvers: []resolverRef{{Name: "home"}}}}
	probe := func(resolver resolverRef, host string) dnsprobe.ResolverResult {
		if resolver.Name != "home" {
			t.Fatalf("unexpected resolver probed: %s", resolver.Name)
		}
		return resolvedResult("203.0.113.10")
	}
	resolve := newCrawlResolve(primaryGroups, nil, probe)

	ip, ok := resolve(context.Background(), "example.com")
	if !ok || ip != "203.0.113.10" {
		t.Fatalf("resolve = (%q, %v), want (203.0.113.10, true)", ip, ok)
	}
}

func TestNewCrawlResolveFallsBackToReferenceWhenPrimaryBlocked(t *testing.T) {
	primaryGroups := []resolverGroup{{Resolvers: []resolverRef{{Name: "home"}}}}
	referenceGroups := []resolverGroup{{Resolvers: []resolverRef{{Name: "cloudflare"}}}}
	probe := func(resolver resolverRef, host string) dnsprobe.ResolverResult {
		switch resolver.Name {
		case "home":
			return blockedResult("0.0.0.0")
		case "cloudflare":
			return resolvedResult("198.51.100.20")
		}
		t.Fatalf("unexpected resolver probed: %s", resolver.Name)
		return dnsprobe.ResolverResult{}
	}
	resolve := newCrawlResolve(primaryGroups, referenceGroups, probe)

	ip, ok := resolve(context.Background(), "example.com")
	if !ok || ip != "198.51.100.20" {
		t.Fatalf("resolve = (%q, %v), want (198.51.100.20, true)", ip, ok)
	}
}

func TestNewCrawlResolveFallsBackToReferenceWhenPrimaryPrivate(t *testing.T) {
	primaryGroups := []resolverGroup{{Resolvers: []resolverRef{{Name: "home"}}}}
	referenceGroups := []resolverGroup{{Resolvers: []resolverRef{{Name: "cloudflare"}}}}
	probe := func(resolver resolverRef, host string) dnsprobe.ResolverResult {
		switch resolver.Name {
		case "home":
			return privateResult("10.1.2.3")
		case "cloudflare":
			return resolvedResult("198.51.100.20")
		}
		t.Fatalf("unexpected resolver probed: %s", resolver.Name)
		return dnsprobe.ResolverResult{}
	}
	resolve := newCrawlResolve(primaryGroups, referenceGroups, probe)

	ip, ok := resolve(context.Background(), "example.com")
	if !ok || ip != "198.51.100.20" {
		t.Fatalf("resolve = (%q, %v), want (198.51.100.20, true)", ip, ok)
	}
}

func TestNewCrawlResolveNeverReturnsSinkholeOrPrivateIP(t *testing.T) {
	cases := []struct {
		name      string
		primary   dnsprobe.ResolverResult
		reference dnsprobe.ResolverResult
	}{
		{"reference also blocked", blockedResult("0.0.0.0"), blockedResult("127.0.0.1")},
		{"reference also private", blockedResult("0.0.0.0"), privateResult("10.0.0.5")},
		{"reference errors", privateResult("10.0.0.5"), dnsprobe.ResolverResult{Status: dnsprobe.StatusError}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			primaryGroups := []resolverGroup{{Resolvers: []resolverRef{{Name: "home"}}}}
			referenceGroups := []resolverGroup{{Resolvers: []resolverRef{{Name: "cloudflare"}}}}
			probe := func(resolver resolverRef, host string) dnsprobe.ResolverResult {
				switch resolver.Name {
				case "home":
					return c.primary
				case "cloudflare":
					return c.reference
				}
				t.Fatalf("unexpected resolver probed: %s", resolver.Name)
				return dnsprobe.ResolverResult{}
			}
			resolve := newCrawlResolve(primaryGroups, referenceGroups, probe)

			ip, ok := resolve(context.Background(), "example.com")
			if ok || ip != "" {
				t.Fatalf("resolve = (%q, %v), want (\"\", false) - must never dial a sinkhole/private IP", ip, ok)
			}
		})
	}
}

func TestNewCrawlResolveSkipsReferenceOnNXDOMAINOrError(t *testing.T) {
	cases := []dnsprobe.Status{dnsprobe.StatusNXDOMAIN, dnsprobe.StatusError}
	for _, status := range cases {
		t.Run(string(status), func(t *testing.T) {
			primaryGroups := []resolverGroup{{Resolvers: []resolverRef{{Name: "home"}}}}
			referenceGroups := []resolverGroup{{Resolvers: []resolverRef{{Name: "cloudflare"}}}}
			probe := func(resolver resolverRef, host string) dnsprobe.ResolverResult {
				if resolver.Name == "cloudflare" {
					t.Fatal("reference resolver should not be probed on NXDOMAIN/Error")
				}
				return dnsprobe.ResolverResult{Status: status}
			}
			resolve := newCrawlResolve(primaryGroups, referenceGroups, probe)

			ip, ok := resolve(context.Background(), "example.com")
			if ok || ip != "" {
				t.Fatalf("resolve = (%q, %v), want (\"\", false)", ip, ok)
			}
		})
	}
}

func TestCollectPrivateWarnings(t *testing.T) {
	results := []dnsprobe.ResolverResult{{
		ResolverName: "home",
		Steps: []dnsprobe.ChainStep{
			{Name: "example.com", Classification: dnsprobe.Classification{Status: dnsprobe.StatusResolved, IPs: []string{"203.0.113.10"}}},
			{Name: "sinkhole.vendor.net", Classification: dnsprobe.Classification{Status: dnsprobe.StatusPrivate, BlockedBy: "rfc1918", IPs: []string{"10.1.2.3"}}},
		},
	}}

	warnings := collectPrivateWarnings(results)
	if len(warnings) != 1 {
		t.Fatalf("warnings = %#v, want 1", warnings)
	}
	if !strings.Contains(warnings[0], "sinkhole.vendor.net") || !strings.Contains(warnings[0], "10.1.2.3") || !strings.Contains(warnings[0], "rfc1918") || !strings.Contains(warnings[0], "home") {
		t.Fatalf("warning = %q, missing expected details", warnings[0])
	}
}

// countingExchanger mimics a wire DNS exchange, counting how many times each
// query name was actually sent - used to prove a shared dnsprobe.Cache
// (as wired into every resolverRef by buildResolverGroups) dedupes queries
// between the crawler's dial-time lookups and the report-time probe.
type countingExchanger struct {
	replies map[string]*dns.Msg
	calls   map[string]int
}

func (c *countingExchanger) ExchangeContext(ctx context.Context, msg *dns.Msg, address string) (*dns.Msg, error) {
	if c.calls == nil {
		c.calls = map[string]int{}
	}
	name := msg.Question[0].Name
	c.calls[name]++
	return c.replies[name], nil
}

func TestSharedCacheDedupesWireQueriesAcrossCrawlAndReportProbing(t *testing.T) {
	fake := &countingExchanger{replies: map[string]*dns.Msg{
		"example.com.": mustA(t, "example.com. 60 IN A 203.0.113.10"),
	}}
	cfg := config.Default()
	cache := dnsprobe.NewCache()
	resolver := dnsprobe.NewResolver(
		config.ResolverConfig{Name: "home", Address: "127.0.0.1:53"},
		cfg.DNS,
		dnsprobe.NewClassifier(cfg.BlockedSignals),
		fake,
	).WithCache(cache)
	primaryGroups := []resolverGroup{{Resolvers: []resolverRef{{Name: "home", Resolver: resolver}}}}
	probe := func(resolver resolverRef, host string) dnsprobe.ResolverResult {
		return resolver.Resolver.Probe(context.Background(), host)
	}

	// Simulate a crawl-time lookup followed by the post-crawl report probe
	// for the same host, exactly like Main() does when they share one cache.
	newCrawlResolve(primaryGroups, nil, probe)(context.Background(), "example.com")
	probeLocalPriorityGroups([]string{"example.com"}, primaryGroups, probe)

	if got := fake.calls["example.com."]; got != 1 {
		t.Fatalf("wire calls for example.com = %d, want 1 (shared cache should dedupe the report probe)", got)
	}
}

func mustA(t *testing.T, rrText string) *dns.Msg {
	t.Helper()
	rr, err := dns.NewRR(rrText)
	if err != nil {
		t.Fatal(err)
	}
	msg := new(dns.Msg)
	msg.SetQuestion(rr.Header().Name, dns.TypeA)
	msg.Answer = []dns.RR{rr}
	return msg
}

func TestSelectReferencePriorityGroupsUseFallbackOnlyIfGroupFails(t *testing.T) {
	groups := []resolverGroup{
		{Priority: 0, Resolvers: []resolverRef{{Name: "ref-a"}, {Name: "ref-b"}}},
		{Priority: 10, Resolvers: []resolverRef{{Name: "ref-fallback"}}},
	}
	probe := func(resolver resolverRef, host string) dnsprobe.ResolverResult {
		if host == "all-fail.example" && (resolver.Name == "ref-a" || resolver.Name == "ref-b") {
			return dnsprobe.ResolverResult{ResolverName: resolver.Name, Status: dnsprobe.StatusError}
		}
		return dnsprobe.ResolverResult{ResolverName: resolver.Name, Status: dnsprobe.StatusResolved}
	}

	results := probeReferencePriorityGroups([]string{"ok.example", "all-fail.example"}, groups, probe)

	if len(results[0].Results) != 2 {
		t.Fatalf("ok result count = %d, want same-priority pair", len(results[0].Results))
	}
	if got := results[1].Results[len(results[1].Results)-1].ResolverName; got != "ref-fallback" {
		t.Fatalf("fallback resolver = %s, want ref-fallback", got)
	}
}
