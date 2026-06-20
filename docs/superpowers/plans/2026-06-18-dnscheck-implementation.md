# DNSCheck Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Go `dnscheck` CLI described in `docs/superpowers/specs/2026-06-18-dnscheck-design.md`.

**Architecture:** The CLI is a small orchestrator over focused internal packages: config loading, blocklist parsing, web hostname discovery, DNS probing, and reporting. DNS probing uses explicit resolver clients so classic DNS and DoH share the same result model and retry/CNAME traversal logic, with conservative concurrency limiting to avoid hammering external resolvers. Tests use fake HTTP and fake DNS components by default, with optional manual integration against the user's test DNS server.

**Tech Stack:** Go 1.22+, `github.com/miekg/dns` for DNS wire messages/classic DNS/DoH payloads, `gopkg.in/yaml.v3` for config, Go standard library `net/http`, `net/url`, `html`, `encoding/json`, and `testing`.

---

## File Map

- Create `go.mod`: module definition and dependencies.
- Create `cmd/dnscheck/main.go`: thin main entrypoint.
- Create `internal/app/app.go`: CLI flag parsing, config precedence, orchestration.
- Create `internal/config/config.go`: config structs, defaults, YAML loading, flag overrides.
- Create `internal/blocklist/blocklist.go`: source loading, parsing with line numbers, pattern matching, sed command generation.
- Create `internal/webscan/webscan.go`: depth-aware document fetching and hostname extraction.
- Create `internal/dnsprobe/types.go`: shared DNS result types.
- Create `internal/dnsprobe/classifier.go`: blocked-response classification.
- Create `internal/dnsprobe/resolver.go`: resolver interface, classic DNS client, DoH client, retry and CNAME traversal.
- Create `internal/report/report.go`: text, ANSI color, and JSON output.
- Create tests next to each package: `*_test.go`.

Do not create git commits during implementation. The user will commit once the project is complete.

## Task 1: Bootstrap Go Module And Config Package

**Files:**
- Create: `go.mod`
- Create: `internal/config/config.go`
- Test: `internal/config/config_test.go`

- [ ] **Step 1: Initialize module files**

Run:

```bash
go mod init dnscheck
go get github.com/miekg/dns@latest
go get gopkg.in/yaml.v3@latest
```

Expected: `go.mod` and `go.sum` exist. If network access is blocked, rerun the failed `go get` command with escalated network permission.

- [ ] **Step 2: Write failing config tests**

Create `internal/config/config_test.go`:

```go
package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaults(t *testing.T) {
	cfg := Default()

	if time.Duration(cfg.DNS.Timeout) != 3*time.Second {
		t.Fatalf("timeout = %s, want 3s", cfg.DNS.Timeout)
	}
	if cfg.DNS.Retries != 2 {
		t.Fatalf("retries = %d, want 2", cfg.DNS.Retries)
	}
	if cfg.DNS.MaxCNAMEdepth != 10 {
		t.Fatalf("max cname depth = %d, want 10", cfg.DNS.MaxCNAMEdepth)
	}
	if cfg.DNS.MaxConcurrentQueries != 4 {
		t.Fatalf("max concurrent queries = %d, want 4", cfg.DNS.MaxConcurrentQueries)
	}
	if cfg.Crawl.Depth != 1 {
		t.Fatalf("crawl depth = %d, want 1", cfg.Crawl.Depth)
	}
	if len(cfg.ReferenceResolvers) == 0 {
		t.Fatal("expected default reference resolvers")
	}
	if got := cfg.BlockedSignals.HINFOContains[0]; got != "locally blocked" {
		t.Fatalf("first HINFO marker = %q", got)
	}
}

func TestLoadYAMLAndApplyOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dnscheck.config")
	err := os.WriteFile(path, []byte(`
dns_servers:
  - name: home
    address: 10.255.255.20:53
reference_resolvers:
  - name: doh
    address: https://cloudflare-dns.com/dns-query
blocklist:
  source: /tmp/blocklist.txt
dns:
  timeout: 5s
  retries: 4
  max_cname_depth: 12
  max_concurrent_queries: 2
crawl:
  depth: 3
  insecure_skip_tls_verify: false
output:
  color: false
`), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	overrides := Overrides{
		NoCrawl:               true,
		InsecureSkipTLSVerify: true,
		Color:                 true,
	}
	cfg.Apply(overrides)

	if cfg.Crawl.Depth != 0 {
		t.Fatalf("crawl depth = %d, want 0 from --no-crawl", cfg.Crawl.Depth)
	}
	if !cfg.Crawl.InsecureSkipTLSVerify {
		t.Fatal("expected -k override to enable insecure TLS")
	}
	if !cfg.Output.Color {
		t.Fatal("expected --color override to enable color")
	}
	if time.Duration(cfg.DNS.Timeout) != 5*time.Second {
		t.Fatalf("timeout = %s, want 5s from config", cfg.DNS.Timeout)
	}
	if cfg.DNS.MaxConcurrentQueries != 2 {
		t.Fatalf("max concurrent queries = %d, want 2 from config", cfg.DNS.MaxConcurrentQueries)
	}
}
```

- [ ] **Step 3: Run config tests and verify they fail**

Run:

```bash
go test ./internal/config
```

Expected: FAIL because `Default`, `Load`, `Overrides`, and config structs are undefined.

- [ ] **Step 4: Implement config package**

Create `internal/config/config.go`:

```go
package config

import (
	"errors"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	DNSServers         []ResolverConfig `yaml:"dns_servers"`
	ReferenceResolvers []ResolverConfig `yaml:"reference_resolvers"`
	Blocklist          BlocklistConfig  `yaml:"blocklist"`
	BlockedSignals    BlockedSignals   `yaml:"blocked_signals"`
	DNS                DNSConfig        `yaml:"dns"`
	Crawl              CrawlConfig      `yaml:"crawl"`
	Output             OutputConfig     `yaml:"output"`
}

type ResolverConfig struct {
	Name    string `yaml:"name"`
	Address string `yaml:"address"`
}

type BlocklistConfig struct {
	Source string `yaml:"source"`
}

type BlockedSignals struct {
	HINFOContains         []string `yaml:"hinfo_contains"`
	BlockedIPs           []string `yaml:"blocked_ips"`
	TreatNXDOMAINAsBlocked bool     `yaml:"treat_nxdomain_as_blocked"`
}

type DNSConfig struct {
	Timeout              Duration `yaml:"timeout"`
	Retries              int      `yaml:"retries"`
	MaxCNAMEdepth        int      `yaml:"max_cname_depth"`
	MaxConcurrentQueries int      `yaml:"max_concurrent_queries"`
}

type Duration time.Duration

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	parsed, err := time.ParseDuration(value.Value)
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) String() string {
	return time.Duration(d).String()
}

type CrawlConfig struct {
	Depth                 int      `yaml:"depth"`
	MaxPages              int      `yaml:"max_pages"`
	DocumentExtensions    []string `yaml:"document_extensions"`
	UserAgent             string   `yaml:"user_agent"`
	InsecureSkipTLSVerify bool     `yaml:"insecure_skip_tls_verify"`
}

type OutputConfig struct {
	Color bool `yaml:"color"`
}

type Overrides struct {
	NoCrawl               bool
	InsecureSkipTLSVerify bool
	Color                 bool
}

func Default() Config {
	return Config{
		ReferenceResolvers: []ResolverConfig{
			{Name: "cloudflare", Address: "1.1.1.1:53"},
			{Name: "google", Address: "8.8.8.8:53"},
		},
		BlockedSignals: BlockedSignals{
			HINFOContains: []string{"locally blocked", "dnscrypt-proxy"},
			BlockedIPs:   []string{"0.0.0.0", "127.0.0.1"},
		},
		DNS: DNSConfig{
			Timeout:              Duration(3 * time.Second),
			Retries:              2,
			MaxCNAMEdepth:        10,
			MaxConcurrentQueries: 4,
		},
		Crawl: CrawlConfig{
			Depth:              1,
			MaxPages:           10,
			DocumentExtensions: []string{".html", ".htm", ".php", ".aspx", ""},
			UserAgent:          "dnscheck/0.1",
		},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return Config{}, err
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	cfg.fillDefaults()
	return cfg, nil
}

func (c *Config) Apply(o Overrides) {
	if o.NoCrawl {
		c.Crawl.Depth = 0
	}
	if o.InsecureSkipTLSVerify {
		c.Crawl.InsecureSkipTLSVerify = true
	}
	if o.Color {
		c.Output.Color = true
	}
}

func (c *Config) fillDefaults() {
	def := Default()
	if c.DNS.Timeout == 0 {
		c.DNS.Timeout = def.DNS.Timeout
	}
	if c.DNS.Retries == 0 {
		c.DNS.Retries = def.DNS.Retries
	}
	if c.DNS.MaxCNAMEdepth == 0 {
		c.DNS.MaxCNAMEdepth = def.DNS.MaxCNAMEdepth
	}
	if c.DNS.MaxConcurrentQueries == 0 {
		c.DNS.MaxConcurrentQueries = def.DNS.MaxConcurrentQueries
	}
	if c.Crawl.MaxPages == 0 {
		c.Crawl.MaxPages = def.Crawl.MaxPages
	}
	if c.Crawl.DocumentExtensions == nil {
		c.Crawl.DocumentExtensions = def.Crawl.DocumentExtensions
	}
	if c.Crawl.UserAgent == "" {
		c.Crawl.UserAgent = def.Crawl.UserAgent
	}
	if c.BlockedSignals.HINFOContains == nil {
		c.BlockedSignals.HINFOContains = def.BlockedSignals.HINFOContains
	}
	if c.BlockedSignals.BlockedIPs == nil {
		c.BlockedSignals.BlockedIPs = def.BlockedSignals.BlockedIPs
	}
	if c.ReferenceResolvers == nil {
		c.ReferenceResolvers = def.ReferenceResolvers
	}
}
```

- [ ] **Step 5: Run config tests and verify they pass**

Run:

```bash
go test ./internal/config
```

Expected: PASS.

## Task 2: Blocklist Parsing, Matching, And Sed Output

**Files:**
- Create: `internal/blocklist/blocklist.go`
- Test: `internal/blocklist/blocklist_test.go`

- [ ] **Step 1: Write failing blocklist tests**

Create `internal/blocklist/blocklist_test.go`:

```go
package blocklist

import (
	"strings"
	"testing"
)

func TestParsePreservesLineNumbersAndIgnoresComments(t *testing.T) {
	list, err := Parse(strings.NewReader("######## header ########\n# comment\nad.*\n\n*.nr-data.net\nactivate.adobe.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Rules) != 3 {
		t.Fatalf("rules = %d, want 3", len(list.Rules))
	}
	if list.Rules[0].LineNumber != 3 || list.Rules[0].Text != "ad.*" {
		t.Fatalf("first rule = %#v", list.Rules[0])
	}
	if list.Rules[1].LineNumber != 5 || list.Rules[1].Text != "*.nr-data.net" {
		t.Fatalf("second rule = %#v", list.Rules[1])
	}
}

func TestMatchExactLeadingWildcardAndLabelWildcard(t *testing.T) {
	list, err := Parse(strings.NewReader("ad.*\n*.nr-data.net\nactivate.adobe.com\n"))
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		"ad.example":             "ad.*",
		"bam.nr-data.net":        "*.nr-data.net",
		"deep.bam.nr-data.net":   "*.nr-data.net",
		"activate.adobe.com":     "activate.adobe.com",
	}

	for host, want := range cases {
		matches := list.Match(host)
		if len(matches) == 0 {
			t.Fatalf("%s: expected match %s", host, want)
		}
		if matches[0].Text != want {
			t.Fatalf("%s: match = %q, want %q", host, matches[0].Text, want)
		}
	}
}

func TestSedDeleteCommandEscapesExactRule(t *testing.T) {
	rule := Rule{LineNumber: 8, Text: "*.events.launchdarkly.com"}
	got := SedDeleteCommand("/tmp/blocked-names.txt", rule)
	want := `sed -i '/^\*\.events\.launchdarkly\.com$/d' /tmp/blocked-names.txt`
	if got != want {
		t.Fatalf("sed command = %q, want %q", got, want)
	}
}
```

- [ ] **Step 2: Run blocklist tests and verify they fail**

Run:

```bash
go test ./internal/blocklist
```

Expected: FAIL because package functions are undefined.

- [ ] **Step 3: Implement blocklist package**

Create `internal/blocklist/blocklist.go`:

```go
package blocklist

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"
)

type Rule struct {
	LineNumber int    `json:"line_number"`
	Text       string `json:"text"`
}

type List struct {
	Rules []Rule `json:"rules"`
}

func Parse(r io.Reader) (List, error) {
	scanner := bufio.NewScanner(r)
	var rules []Rule
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		rules = append(rules, Rule{LineNumber: lineNo, Text: strings.ToLower(strings.TrimSuffix(text, "."))})
	}
	if err := scanner.Err(); err != nil {
		return List{}, err
	}
	return List{Rules: rules}, nil
}

func (l List) Match(host string) []Rule {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	var matches []Rule
	for _, rule := range l.Rules {
		if ruleMatches(rule.Text, host) {
			matches = append(matches, rule)
		}
	}
	return matches
}

func ruleMatches(pattern, host string) bool {
	switch {
	case strings.HasPrefix(pattern, "*."):
		suffix := strings.TrimPrefix(pattern, "*.")
		return host == suffix || strings.HasSuffix(host, "."+suffix)
	case strings.Contains(pattern, "*"):
		re := "^" + regexp.QuoteMeta(pattern) + "$"
		re = strings.ReplaceAll(re, `\*`, `[^.]+`)
		return regexp.MustCompile(re).MatchString(host)
	default:
		return host == pattern
	}
}

func SedDeleteCommand(path string, rule Rule) string {
	return fmt.Sprintf("sed -i '/^%s$/d' %s", sedRegexEscape(rule.Text), shellQuote(path))
}

func sedRegexEscape(s string) string {
	replacer := strings.NewReplacer(
		`\`, `\\`,
		`.`, `\.`,
		`*`, `\*`,
		`[`, `\[`,
		`]`, `\]`,
		`^`, `\^`,
		`$`, `\$`,
		`/`, `\/`,
	)
	return replacer.Replace(s)
}

func shellQuote(s string) string {
	if s == "" || strings.ContainsAny(s, " \t\n'\"\\$`!*?[]{}();&|<>") {
		return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	}
	return s
}
```

- [ ] **Step 4: Run blocklist tests and verify they pass**

Run:

```bash
go test ./internal/blocklist
```

Expected: PASS.

## Task 3: DNS Result Types And Blocked Classifier

**Files:**
- Create: `internal/dnsprobe/types.go`
- Create: `internal/dnsprobe/classifier.go`
- Test: `internal/dnsprobe/classifier_test.go`

- [ ] **Step 1: Write failing classifier tests**

Create `internal/dnsprobe/classifier_test.go`:

```go
package dnsprobe

import (
	"testing"

	"github.com/miekg/dns"
	"dnscheck/internal/config"
)

func TestClassifiesHINFOBlockedResponse(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("events.launchdarkly.com.", dns.TypeA)
	msg.Rcode = dns.RcodeSuccess
	msg.Answer = []dns.RR{
		&dns.HINFO{
			Hdr: dns.RR_Header{Name: "events.launchdarkly.com.", Rrtype: dns.TypeHINFO, Class: dns.ClassINET, Ttl: 10},
			Cpu: "This query has been locally blocked",
			Os:  "by dnscrypt-proxy",
		},
	}

	classifier := NewClassifier(config.Default().BlockedSignals)
	got := classifier.Classify(msg)
	if got.Status != StatusBlocked {
		t.Fatalf("status = %s, want blocked", got.Status)
	}
	if got.BlockedBy != "hinfo" {
		t.Fatalf("blocked by = %q, want hinfo", got.BlockedBy)
	}
}

func TestClassifiesARecordAsResolved(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.Rcode = dns.RcodeSuccess
	msg.Answer = []dns.RR{
		mustRR(t, "example.com. 60 IN A 93.184.216.34"),
	}

	got := NewClassifier(config.Default().BlockedSignals).Classify(msg)
	if got.Status != StatusResolved {
		t.Fatalf("status = %s, want resolved", got.Status)
	}
	if len(got.IPs) != 1 || got.IPs[0] != "93.184.216.34" {
		t.Fatalf("ips = %#v", got.IPs)
	}
}

func TestClassifiesNXDOMAINAccordingToConfig(t *testing.T) {
	msg := new(dns.Msg)
	msg.Rcode = dns.RcodeNameError

	cfg := config.Default().BlockedSignals
	cfg.TreatNXDOMAINAsBlocked = true
	got := NewClassifier(cfg).Classify(msg)
	if got.Status != StatusBlocked {
		t.Fatalf("status = %s, want blocked", got.Status)
	}
}

func mustRR(t *testing.T, text string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(text)
	if err != nil {
		t.Fatal(err)
	}
	return rr
}
```

- [ ] **Step 2: Run classifier tests and verify they fail**

Run:

```bash
go test ./internal/dnsprobe
```

Expected: FAIL because DNS result types and classifier are undefined.

- [ ] **Step 3: Implement shared types and classifier**

Create `internal/dnsprobe/types.go`:

```go
package dnsprobe

type Status string

const (
	StatusResolved Status = "resolved"
	StatusBlocked  Status = "blocked"
	StatusCNAME    Status = "cname"
	StatusNXDOMAIN Status = "nxdomain"
	StatusError    Status = "error"
)

type Classification struct {
	Status    Status   `json:"status"`
	BlockedBy string   `json:"blocked_by,omitempty"`
	IPs       []string `json:"ips,omitempty"`
	CNAMEs    []string `json:"cnames,omitempty"`
	Error     string   `json:"error,omitempty"`
}

type ChainStep struct {
	Name           string         `json:"name"`
	Classification Classification `json:"classification"`
}

type ResolverResult struct {
	ResolverName string      `json:"resolver_name"`
	ResolverAddr string      `json:"resolver_addr"`
	Steps        []ChainStep `json:"steps"`
	Status       Status      `json:"status"`
	Error        string      `json:"error,omitempty"`
}
```

Create `internal/dnsprobe/classifier.go`:

```go
package dnsprobe

import (
	"strings"

	"github.com/miekg/dns"
	"dnscheck/internal/config"
)

type Classifier struct {
	signals config.BlockedSignals
}

func NewClassifier(signals config.BlockedSignals) Classifier {
	return Classifier{signals: signals}
}

func (c Classifier) Classify(msg *dns.Msg) Classification {
	if msg == nil {
		return Classification{Status: StatusError, Error: "nil dns response"}
	}
	if msg.Rcode == dns.RcodeNameError {
		if c.signals.TreatNXDOMAINAsBlocked {
			return Classification{Status: StatusBlocked, BlockedBy: "nxdomain"}
		}
		return Classification{Status: StatusNXDOMAIN}
	}

	var cnames []string
	var ips []string
	for _, answer := range msg.Answer {
		switch rr := answer.(type) {
		case *dns.HINFO:
			text := strings.ToLower(rr.Cpu + " " + rr.Os)
			for _, marker := range c.signals.HINFOContains {
				if strings.Contains(text, strings.ToLower(marker)) {
					return Classification{Status: StatusBlocked, BlockedBy: "hinfo"}
				}
			}
		case *dns.A:
			ip := rr.A.String()
			if c.isBlockedIP(ip) {
				return Classification{Status: StatusBlocked, BlockedBy: "blocked_ip", IPs: []string{ip}}
			}
			ips = append(ips, ip)
		case *dns.AAAA:
			ip := rr.AAAA.String()
			if c.isBlockedIP(ip) {
				return Classification{Status: StatusBlocked, BlockedBy: "blocked_ip", IPs: []string{ip}}
			}
			ips = append(ips, ip)
		case *dns.CNAME:
			cnames = append(cnames, strings.TrimSuffix(rr.Target, "."))
		}
	}
	if len(ips) > 0 {
		return Classification{Status: StatusResolved, IPs: ips, CNAMEs: cnames}
	}
	if len(cnames) > 0 {
		return Classification{Status: StatusCNAME, CNAMEs: cnames}
	}
	return Classification{Status: StatusError, Error: dns.RcodeToString[msg.Rcode]}
}

func (c Classifier) isBlockedIP(ip string) bool {
	for _, blocked := range c.signals.BlockedIPs {
		if ip == blocked {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run classifier tests and verify they pass**

Run:

```bash
go test ./internal/dnsprobe
```

Expected: PASS.

## Task 4: DNS Resolver Clients, Retries, DoH, And CNAME Traversal

**Files:**
- Create: `internal/dnsprobe/resolver.go`
- Test: `internal/dnsprobe/resolver_test.go`

- [ ] **Step 1: Write failing resolver traversal tests with fake exchange**

Create `internal/dnsprobe/resolver_test.go`:

```go
package dnsprobe

import (
	"context"
	"errors"
	"testing"

	"github.com/miekg/dns"
	"dnscheck/internal/config"
)

type fakeExchange struct {
	replies map[string]*dns.Msg
	calls   int
	err     error
}

func (f *fakeExchange) ExchangeContext(ctx context.Context, msg *dns.Msg, address string) (*dns.Msg, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	name := msg.Question[0].Name
	return f.replies[name], nil
}

func TestProbeFollowsCNAMEUntilIP(t *testing.T) {
	fake := &fakeExchange{replies: map[string]*dns.Msg{
		"start.example.": msgWithRR(t, "start.example. 60 IN CNAME a.vendor.net."),
		"a.vendor.net.": msgWithRR(t, "a.vendor.net. 60 IN CNAME b.vendor.net."),
		"b.vendor.net.": msgWithRR(t, "b.vendor.net. 60 IN A 203.0.113.10"),
	}}
	resolver := NewResolver(config.ResolverConfig{Name: "test", Address: "127.0.0.1:53"}, config.Default().DNS, NewClassifier(config.Default().BlockedSignals), fake)

	result := resolver.Probe(context.Background(), "start.example")
	if result.Status != StatusResolved {
		t.Fatalf("status = %s, want resolved", result.Status)
	}
	if len(result.Steps) != 3 {
		t.Fatalf("steps = %d, want 3", len(result.Steps))
	}
}

func TestProbeStopsOnBlockedCNAMEMember(t *testing.T) {
	fake := &fakeExchange{replies: map[string]*dns.Msg{
		"start.example.": msgWithRR(t, "start.example. 60 IN CNAME blocked.vendor.net."),
		"blocked.vendor.net.": hinfoBlocked("blocked.vendor.net."),
	}}
	resolver := NewResolver(config.ResolverConfig{Name: "test", Address: "127.0.0.1:53"}, config.Default().DNS, NewClassifier(config.Default().BlockedSignals), fake)

	result := resolver.Probe(context.Background(), "start.example")
	if result.Status != StatusBlocked {
		t.Fatalf("status = %s, want blocked", result.Status)
	}
	if got := result.Steps[1].Name; got != "blocked.vendor.net" {
		t.Fatalf("blocked step = %q", got)
	}
}

func TestProbeRetriesTimeouts(t *testing.T) {
	cfg := config.Default()
	cfg.DNS.Retries = 2
	fake := &fakeExchange{err: errors.New("timeout")}
	resolver := NewResolver(config.ResolverConfig{Name: "test", Address: "127.0.0.1:53"}, cfg.DNS, NewClassifier(cfg.BlockedSignals), fake)

	result := resolver.Probe(context.Background(), "start.example")
	if result.Status != StatusError {
		t.Fatalf("status = %s, want error", result.Status)
	}
	if fake.calls != 3 {
		t.Fatalf("calls = %d, want 3", fake.calls)
	}
}

func TestExchangeFactorySelectsDoHForHTTPSAddress(t *testing.T) {
	ex := NewExchange("https://cloudflare-dns.com/dns-query", false)
	if _, ok := ex.(*DoHExchange); !ok {
		t.Fatalf("exchange type = %T, want *DoHExchange", ex)
	}
}

func msgWithRR(t *testing.T, rrText string) *dns.Msg {
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

func hinfoBlocked(name string) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeA)
	msg.Answer = []dns.RR{
		&dns.HINFO{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeHINFO, Class: dns.ClassINET, Ttl: 10}, Cpu: "This query has been locally blocked", Os: "by dnscrypt-proxy"},
	}
	return msg
}
```

- [ ] **Step 2: Run resolver tests and verify they fail**

Run:

```bash
go test ./internal/dnsprobe
```

Expected: FAIL because resolver code is undefined.

- [ ] **Step 3: Implement resolver clients and traversal**

Create `internal/dnsprobe/resolver.go`:

```go
package dnsprobe

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
	"dnscheck/internal/config"
)

type Exchanger interface {
	ExchangeContext(ctx context.Context, msg *dns.Msg, address string) (*dns.Msg, error)
}

type Resolver struct {
	cfg        config.ResolverConfig
	dnsCfg     config.DNSConfig
	classifier Classifier
	exchange   Exchanger
}

func NewResolver(cfg config.ResolverConfig, dnsCfg config.DNSConfig, classifier Classifier, exchange Exchanger) Resolver {
	return Resolver{cfg: cfg, dnsCfg: dnsCfg, classifier: classifier, exchange: exchange}
}

func (r Resolver) Probe(ctx context.Context, host string) ResolverResult {
	current := strings.TrimSuffix(host, ".")
	result := ResolverResult{ResolverName: r.cfg.Name, ResolverAddr: r.cfg.Address}
	seen := map[string]bool{}

	for depth := 0; depth <= r.dnsCfg.MaxCNAMEdepth; depth++ {
		if seen[current] {
			result.Status = StatusError
			result.Error = "cname loop detected"
			return result
		}
		seen[current] = true

		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(current), dns.TypeA)
		reply, err := r.exchangeWithRetries(ctx, msg)
		if err != nil {
			result.Status = StatusError
			result.Error = err.Error()
			result.Steps = append(result.Steps, ChainStep{Name: current, Classification: Classification{Status: StatusError, Error: err.Error()}})
			return result
		}

		classification := r.classifier.Classify(reply)
		result.Steps = append(result.Steps, ChainStep{Name: current, Classification: classification})

		switch classification.Status {
		case StatusResolved, StatusBlocked, StatusNXDOMAIN, StatusError:
			result.Status = classification.Status
			result.Error = classification.Error
			return result
		case StatusCNAME:
			current = classification.CNAMEs[0]
		}
	}

	result.Status = StatusError
	result.Error = "max cname depth reached"
	return result
}

func (r Resolver) exchangeWithRetries(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	var lastErr error
	for attempt := 0; attempt <= r.dnsCfg.Retries; attempt++ {
		attemptCtx, cancel := context.WithTimeout(ctx, time.Duration(r.dnsCfg.Timeout))
		reply, err := r.exchange.ExchangeContext(attemptCtx, msg, r.cfg.Address)
		cancel()
		if err == nil {
			return reply, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("after %d attempts: %w", r.dnsCfg.Retries+1, lastErr)
}

type ClassicExchange struct {
	client *dns.Client
}

func (e *ClassicExchange) ExchangeContext(ctx context.Context, msg *dns.Msg, address string) (*dns.Msg, error) {
	reply, _, err := e.client.ExchangeContext(ctx, msg, address)
	return reply, err
}

type DoHExchange struct {
	client *http.Client
}

func (e *DoHExchange) ExchangeContext(ctx context.Context, msg *dns.Msg, address string) (*dns.Msg, error) {
	wire, err := msg.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, address, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("doh status %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	reply := new(dns.Msg)
	if err := reply.Unpack(body); err != nil {
		return nil, err
	}
	return reply, nil
}

func NewExchange(address string, insecureSkipTLSVerify bool) Exchanger {
	if strings.HasPrefix(strings.ToLower(address), "https://") {
		return &DoHExchange{client: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipTLSVerify}}}}
	}
	return &ClassicExchange{client: &dns.Client{Net: "udp"}}
}
```

- [ ] **Step 4: Run resolver tests and verify they pass**

Run:

```bash
go test ./internal/dnsprobe
```

Expected: PASS.

## Task 5: Web Scanner With Depth, TLS Policy, And Host Extraction

**Files:**
- Create: `internal/webscan/webscan.go`
- Test: `internal/webscan/webscan_test.go`

- [ ] **Step 1: Write failing web scanner tests**

Create `internal/webscan/webscan_test.go`:

```go
package webscan

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"dnscheck/internal/config"
)

func TestDepthZeroSkipsFetchAndReturnsInputHost(t *testing.T) {
	called := false
	scanner := Scanner{Client: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		called = true
		return nil, nil
	})}
	cfg := config.Default().Crawl
	cfg.Depth = 0

	result, err := scanner.Scan("https://example.com/path", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("depth 0 should not fetch")
	}
	if !result.Hosts["example.com"] {
		t.Fatalf("hosts = %#v, want example.com", result.Hosts)
	}
}

func TestDepthOneExtractsHostsWithoutFetchingLinkedDocuments(t *testing.T) {
	var pageFetches int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pageFetches++
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head>
<script src="https://scripts.example.net/app.js"></script>
<link rel="stylesheet" href="//cdn.example.net/app.css">
<link rel="preconnect" href="https://preconnect.example.org">
</head><body>
<img src="https://images.example.net/logo.png">
<a href="https://linked.example.net/page.html">linked</a>
</body></html>`))
	}))
	defer server.Close()

	cfg := config.Default().Crawl
	cfg.Depth = 1
	result, err := New(false).Scan(server.URL, cfg)
	if err != nil {
		t.Fatal(err)
	}

	for _, host := range []string{"scripts.example.net", "cdn.example.net", "preconnect.example.org", "images.example.net", "linked.example.net"} {
		if !result.Hosts[host] {
			t.Fatalf("missing host %s in %#v", host, result.Hosts)
		}
	}
	if pageFetches != 1 {
		t.Fatalf("page fetches = %d, want 1", pageFetches)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
```

- [ ] **Step 2: Run web scanner tests and verify they fail**

Run:

```bash
go test ./internal/webscan
```

Expected: FAIL because scanner code is undefined.

- [ ] **Step 3: Implement web scanner**

Create `internal/webscan/webscan.go`:

```go
package webscan

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"

	"dnscheck/internal/config"
)

type Scanner struct {
	Client *http.Client
}

type Result struct {
	Hosts    map[string]bool `json:"hosts"`
	Warnings []string        `json:"warnings,omitempty"`
}

func New(insecureSkipTLSVerify bool) Scanner {
	return Scanner{Client: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipTLSVerify}}}}
}

func (s Scanner) Scan(rawURL string, cfg config.CrawlConfig) (Result, error) {
	if s.Client == nil {
		s = New(cfg.InsecureSkipTLSVerify)
	}
	start, err := url.Parse(rawURL)
	if err != nil {
		return Result{}, err
	}
	result := Result{Hosts: map[string]bool{}}
	if start.Hostname() != "" {
		result.Hosts[strings.ToLower(start.Hostname())] = true
	}
	if cfg.Depth == 0 {
		return result, nil
	}

	visited := map[string]bool{}
	queue := []string{start.String()}
	for depth := 1; depth <= cfg.Depth && len(queue) > 0 && len(visited) < cfg.MaxPages; depth++ {
		currentBatch := queue
		queue = nil
		for _, item := range currentBatch {
			if visited[item] || len(visited) >= cfg.MaxPages {
				continue
			}
			visited[item] = true
			body, err := s.fetch(item, cfg.UserAgent)
			if err != nil {
				result.Warnings = append(result.Warnings, err.Error())
				continue
			}
			links := extractURLs(body)
			base, _ := url.Parse(item)
			for _, link := range links {
				resolved := resolveURL(base, link)
				if resolved == nil || resolved.Hostname() == "" {
					continue
				}
				result.Hosts[strings.ToLower(resolved.Hostname())] = true
				if depth < cfg.Depth && isDocumentLike(resolved, cfg.DocumentExtensions) {
					queue = append(queue, resolved.String())
				}
			}
		}
	}
	return result, nil
}

func (s Scanner) fetch(rawURL, userAgent string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

var urlAttrRe = regexp.MustCompile(`(?i)(?:href|src)=["']([^"']+)["']|url\(([^)]+)\)`)

func extractURLs(body string) []string {
	var out []string
	for _, match := range urlAttrRe.FindAllStringSubmatch(body, -1) {
		value := match[1]
		if value == "" {
			value = match[2]
		}
		value = strings.Trim(value, ` "'`)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func resolveURL(base *url.URL, raw string) *url.URL {
	if strings.HasPrefix(raw, "//") {
		raw = base.Scheme + ":" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	return base.ResolveReference(u)
}

func isDocumentLike(u *url.URL, exts []string) bool {
	ext := strings.ToLower(path.Ext(u.Path))
	for _, allowed := range exts {
		if ext == allowed {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run web scanner tests and verify they pass**

Run:

```bash
go test ./internal/webscan
```

Expected: PASS.

## Task 6: Report Formatting, JSON, Color, No-Blocklist Mode

**Files:**
- Create: `internal/report/report.go`
- Test: `internal/report/report_test.go`

- [ ] **Step 1: Write failing report tests**

Create `internal/report/report_test.go`:

```go
package report

import (
	"strings"
	"testing"

	"dnscheck/internal/blocklist"
	"dnscheck/internal/dnsprobe"
)

func TestTextReportIncludesLineNumbersAndSed(t *testing.T) {
	run := Run{
		Hosts: []HostResult{{
			Host: "events.launchdarkly.com",
			Primary: []dnsprobe.ResolverResult{{
				ResolverName: "home",
				Status:       dnsprobe.StatusBlocked,
				Steps: []dnsprobe.ChainStep{{
					Name: "events.launchdarkly.com",
					Classification: dnsprobe.Classification{Status: dnsprobe.StatusBlocked, BlockedBy: "hinfo"},
				}},
			}},
			Matches: []blocklist.Rule{{LineNumber: 18542, Text: "*.events.launchdarkly.com"}},
		}},
		BlocklistPath: "/tmp/blocked-names.txt",
	}

	out := Text(run, Options{})
	for _, want := range []string{"Blocked hosts", "18542: *.events.launchdarkly.com", "sed -i"} {
		if !strings.Contains(out, want) {
			t.Fatalf("report missing %q:\n%s", want, out)
		}
	}
}

func TestTextReportOmitsSedWithoutBlocklistPath(t *testing.T) {
	run := Run{Hosts: []HostResult{{Host: "blocked.example", Primary: []dnsprobe.ResolverResult{{ResolverName: "home", Status: dnsprobe.StatusBlocked}}}}}
	out := Text(run, Options{})
	if strings.Contains(out, "Sed commands") {
		t.Fatalf("expected no sed section without local blocklist path:\n%s", out)
	}
}

func TestColorReportMarksBlockedAndResolved(t *testing.T) {
	run := Run{Hosts: []HostResult{
		{Host: "blocked.example", Primary: []dnsprobe.ResolverResult{{Status: dnsprobe.StatusBlocked}}},
		{Host: "ok.example", Primary: []dnsprobe.ResolverResult{{Status: dnsprobe.StatusResolved}}},
	}}
	out := Text(run, Options{Color: true})
	if !strings.Contains(out, "\x1b[31mblocked.example\x1b[0m") {
		t.Fatalf("blocked host not red:\n%s", out)
	}
	if !strings.Contains(out, "\x1b[32mok.example\x1b[0m") {
		t.Fatalf("resolved host not green:\n%s", out)
	}
}
```

- [ ] **Step 2: Run report tests and verify they fail**

Run:

```bash
go test ./internal/report
```

Expected: FAIL because report types and functions are undefined.

- [ ] **Step 3: Implement report package**

Create `internal/report/report.go`:

```go
package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"dnscheck/internal/blocklist"
	"dnscheck/internal/dnsprobe"
)

type Run struct {
	Hosts         []HostResult `json:"hosts"`
	BlocklistPath string       `json:"blocklist_path,omitempty"`
	Warnings      []string     `json:"warnings,omitempty"`
}

type HostResult struct {
	Host      string                    `json:"host"`
	Primary   []dnsprobe.ResolverResult `json:"primary"`
	Reference []dnsprobe.ResolverResult `json:"reference"`
	Matches   []blocklist.Rule          `json:"matches,omitempty"`
}

type Options struct {
	Color bool
}

func Text(run Run, opts Options) string {
	var b strings.Builder
	writeBlocked(&b, run, opts)
	writeSed(&b, run)
	writeAllowed(&b, run, opts)
	writeWarnings(&b, run, opts)
	return b.String()
}

func JSON(run Run) ([]byte, error) {
	return json.MarshalIndent(run, "", "  ")
}

func writeBlocked(b *strings.Builder, run Run, opts Options) {
	b.WriteString("Blocked hosts\n=============\n")
	for _, host := range run.Hosts {
		if !isBlocked(host) {
			continue
		}
		fmt.Fprintf(b, "%s\n", color(host.Host, "red", opts.Color))
		for _, primary := range host.Primary {
			if primary.Status == dnsprobe.StatusBlocked {
				fmt.Fprintf(b, "  blocked by resolver: %s\n", primary.ResolverName)
				for _, step := range primary.Steps {
					if step.Classification.Status == dnsprobe.StatusBlocked {
						fmt.Fprintf(b, "  blocked chain member: %s\n", color(step.Name, "red", opts.Color))
					}
				}
			}
		}
		for _, match := range host.Matches {
			fmt.Fprintf(b, "  matched blocklist line: %d: %s\n", match.LineNumber, match.Text)
		}
	}
	b.WriteString("\n")
}

func writeSed(b *strings.Builder, run Run) {
	if run.BlocklistPath == "" {
		return
	}
	seen := map[string]blocklist.Rule{}
	for _, host := range run.Hosts {
		for _, match := range host.Matches {
			seen[match.Text] = match
		}
	}
	if len(seen) == 0 {
		return
	}
	b.WriteString("Sed commands\n============\n")
	for _, rule := range seen {
		b.WriteString(blocklist.SedDeleteCommand(run.BlocklistPath, rule))
		b.WriteString("\n")
	}
	b.WriteString("\n")
}

func writeAllowed(b *strings.Builder, run Run, opts Options) {
	b.WriteString("Allowed / not blocked hostnames\n===============================\n")
	for _, host := range run.Hosts {
		if isBlocked(host) {
			continue
		}
		b.WriteString(color(host.Host, "green", opts.Color))
		b.WriteString("\n")
	}
	b.WriteString("\n")
}

func writeWarnings(b *strings.Builder, run Run, opts Options) {
	if len(run.Warnings) == 0 {
		return
	}
	b.WriteString("Warnings\n========\n")
	for _, warning := range run.Warnings {
		b.WriteString(color(warning, "yellow", opts.Color))
		b.WriteString("\n")
	}
}

func isBlocked(host HostResult) bool {
	for _, primary := range host.Primary {
		if primary.Status == dnsprobe.StatusBlocked {
			return true
		}
	}
	return false
}

func color(s, name string, enabled bool) string {
	if !enabled {
		return s
	}
	code := map[string]string{"red": "31", "green": "32", "yellow": "33"}[name]
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}
```

- [ ] **Step 4: Run report tests and verify they pass**

Run:

```bash
go test ./internal/report
```

Expected: PASS.

## Task 7: CLI Orchestration And End-To-End Fakeable Flow

**Files:**
- Create: `internal/app/app.go`
- Create: `cmd/dnscheck/main.go`
- Test: `internal/app/app_test.go`

- [ ] **Step 1: Write failing app tests for flag precedence and no-crawl**

Create `internal/app/app_test.go`:

```go
package app

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

func TestRunRequiresURL(t *testing.T) {
	var out bytes.Buffer
	err := Main([]string{}, &out, &out)
	if err == nil {
		t.Fatal("expected missing URL error")
	}
	if !strings.Contains(err.Error(), "url is required") {
		t.Fatalf("error = %v", err)
	}
}
```

- [ ] **Step 2: Run app tests and verify they fail**

Run:

```bash
go test ./internal/app
```

Expected: FAIL because app package is undefined.

- [ ] **Step 3: Implement app parsing and main entrypoint**

Create `internal/app/app.go`:

```go
package app

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"dnscheck/internal/config"
)

type Options struct {
	ConfigPath string
	URL        string
	JSON       bool
}

func Parse(args []string) (Options, config.Config, error) {
	fs := flag.NewFlagSet("dnscheck", flag.ContinueOnError)
	cfgPath := fs.String("config", "dnscheck.config", "config file path")
	jsonOut := fs.Bool("json", false, "print JSON output")
	color := fs.Bool("color", false, "enable ANSI color")
	insecure := fs.Bool("k", false, "ignore HTTPS certificate validation errors")
	noCrawl := fs.Bool("no-crawl", false, "skip page crawl and only check the input URL hostname")

	if err := fs.Parse(args); err != nil {
		return Options{}, config.Config{}, err
	}
	if fs.NArg() != 1 {
		return Options{}, config.Config{}, errors.New("url is required")
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return Options{}, config.Config{}, err
	}
	cfg.Apply(config.Overrides{
		NoCrawl:               *noCrawl,
		InsecureSkipTLSVerify: *insecure,
		Color:                 *color,
	})

	return Options{ConfigPath: *cfgPath, URL: fs.Arg(0), JSON: *jsonOut}, cfg, nil
}

func Main(args []string, stdout io.Writer, stderr io.Writer) error {
	opts, cfg, err := Parse(args)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "dnscheck planned run: url=%s depth=%d color=%t json=%t\n", opts.URL, cfg.Crawl.Depth, cfg.Output.Color, opts.JSON)
	return nil
}
```

Create `cmd/dnscheck/main.go`:

```go
package main

import (
	"fmt"
	"os"

	"dnscheck/internal/app"
)

func main() {
	if err := app.Main(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
```

- [ ] **Step 4: Run app tests and verify they pass**

Run:

```bash
go test ./internal/app
```

Expected: PASS.

- [ ] **Step 5: Keep the app layer compiling before source loading exists**

Run:

```bash
go test ./internal/app
go test ./...
```

Expected: package tests that have been implemented so far pass. The temporary `dnscheck planned run` output remains in place until Task 9, after blocklist source loading exists.

## Task 8: Blocklist Source Loading And HTTPS TLS Warnings

**Files:**
- Modify: `internal/blocklist/blocklist.go`
- Test: `internal/blocklist/source_test.go`

- [ ] **Step 1: Write failing source-loading tests**

Create `internal/blocklist/source_test.go`:

```go
package blocklist

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSourceFromLocalFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocked.txt")
	if err := os.WriteFile(path, []byte("*.nr-data.net\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadSource(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Local || loaded.LocalPath != path {
		t.Fatalf("loaded = %#v", loaded)
	}
	if got := loaded.List.Match("bam.nr-data.net"); len(got) != 1 {
		t.Fatalf("matches = %#v, want one", got)
	}
}

func TestLoadSourceFromHTTPSAllowsInsecureWhenRequested(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("*.events.launchdarkly.com\n"))
	}))
	defer server.Close()

	if _, err := LoadSource(server.URL, false); err == nil {
		t.Fatal("expected certificate error without insecure mode")
	}

	loaded, err := LoadSource(server.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Local {
		t.Fatalf("expected remote source: %#v", loaded)
	}
}
```

- [ ] **Step 2: Run source tests and verify they fail**

Run:

```bash
go test ./internal/blocklist
```

Expected: FAIL because `LoadSource` is undefined.

- [ ] **Step 3: Implement source loading**

Append to `internal/blocklist/blocklist.go`:

```go
type Loaded struct {
	List      List
	Source    string
	Local     bool
	LocalPath string
}

func LoadSource(source string, insecureSkipTLSVerify bool) (Loaded, error) {
	var reader io.Reader
	loaded := Loaded{Source: source}
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipTLSVerify}}}
		resp, err := client.Get(source)
		if err != nil {
			return Loaded{}, err
		}
		defer resp.Body.Close()
		reader = resp.Body
	} else {
		file, err := os.Open(source)
		if err != nil {
			return Loaded{}, err
		}
		defer file.Close()
		reader = file
		loaded.Local = true
		loaded.LocalPath = source
	}
	list, err := Parse(reader)
	if err != nil {
		return Loaded{}, err
	}
	loaded.List = list
	return loaded, nil
}
```

Add imports used by the new code: `crypto/tls`, `net/http`, and `os`.

- [ ] **Step 4: Run source tests and verify they pass**

Run:

```bash
go test ./internal/blocklist
```

Expected: PASS.

## Task 9: Final Orchestration, Full Test Run, Build, And Manual Integration Notes

**Files:**
- Modify: `internal/app/app.go`
- Create: `dnscheck.config.example`
- Modify: `README.md`

- [ ] **Step 1: Replace planned-run stub with real orchestration**

Modify `internal/app/app.go` imports to include:

```go
import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"dnscheck/internal/blocklist"
	"dnscheck/internal/config"
	"dnscheck/internal/dnsprobe"
	"dnscheck/internal/report"
	"dnscheck/internal/webscan"
)
```

Replace `Main` with:

```go
func Main(args []string, stdout io.Writer, stderr io.Writer) error {
	opts, cfg, err := Parse(args)
	if err != nil {
		return err
	}

	var list blocklist.List
	var blocklistPath string
	var warnings []string
	if cfg.Blocklist.Source != "" {
		loaded, err := blocklist.LoadSource(cfg.Blocklist.Source, cfg.Crawl.InsecureSkipTLSVerify)
		if err != nil {
			return fmt.Errorf("load blocklist: %w", err)
		}
		list = loaded.List
		if loaded.Local {
			blocklistPath = loaded.LocalPath
		} else {
			warnings = append(warnings, "remote blocklist source configured; sed commands require a local active blocklist path")
		}
	}
	if cfg.Crawl.InsecureSkipTLSVerify {
		warnings = append(warnings, "HTTPS certificate verification disabled by -k or config")
	}

	scanResult, err := webscan.New(cfg.Crawl.InsecureSkipTLSVerify).Scan(opts.URL, cfg.Crawl)
	if err != nil {
		return fmt.Errorf("scan URL: %w", err)
	}
	warnings = append(warnings, scanResult.Warnings...)

	classifier := dnsprobe.NewClassifier(cfg.BlockedSignals)
	ctx := context.Background()
	var hostResults []report.HostResult
	for host := range scanResult.Hosts {
		hostResult := report.HostResult{Host: host}
		for _, resolverCfg := range cfg.DNSServers {
			resolver := dnsprobe.NewResolver(resolverCfg, cfg.DNS, classifier, dnsprobe.NewExchange(resolverCfg.Address, cfg.Crawl.InsecureSkipTLSVerify))
			hostResult.Primary = append(hostResult.Primary, resolver.Probe(ctx, host))
		}
		for _, resolverCfg := range cfg.ReferenceResolvers {
			resolver := dnsprobe.NewResolver(resolverCfg, cfg.DNS, classifier, dnsprobe.NewExchange(resolverCfg.Address, cfg.Crawl.InsecureSkipTLSVerify))
			hostResult.Reference = append(hostResult.Reference, resolver.Probe(ctx, host))
		}
		if len(list.Rules) > 0 {
			hostResult.Matches = append(hostResult.Matches, matchesForHostAndBlockedSteps(list, host, hostResult.Primary)...)
		}
		hostResults = append(hostResults, hostResult)
	}

	run := report.Run{Hosts: hostResults, BlocklistPath: blocklistPath, Warnings: warnings}
	if opts.JSON {
		data, err := report.JSON(run)
		if err != nil {
			return err
		}
		_, err = stdout.Write(append(data, '\n'))
		return err
	}
	_, err = io.WriteString(stdout, report.Text(run, report.Options{Color: cfg.Output.Color}))
	return err
}
```

Add helpers below `Main`:

```go
func matchesForHostAndBlockedSteps(list blocklist.List, host string, primary []dnsprobe.ResolverResult) []blocklist.Rule {
	seen := map[string]blocklist.Rule{}
	for _, rule := range list.Match(host) {
		seen[rule.Text] = rule
	}
	for _, resolver := range primary {
		for _, step := range resolver.Steps {
			if step.Classification.Status != dnsprobe.StatusBlocked {
				continue
			}
			for _, rule := range list.Match(step.Name) {
				seen[rule.Text] = rule
			}
		}
	}
	var matches []blocklist.Rule
	for _, rule := range seen {
		matches = append(matches, rule)
	}
	return matches
}

func isLocalBlocklistSource(source string) bool {
	return source != "" && !strings.HasPrefix(source, "http://") && !strings.HasPrefix(source, "https://")
}
```

Run:

```bash
go test ./internal/app
```

Expected: PASS. The CLI now performs the real workflow. `isLocalBlocklistSource` is available for future CLI validation or report refinements; if unused after implementation, remove it before final verification.

- [ ] **Step 2: Add example config**

Create `dnscheck.config.example`:

```yaml
dns_servers:
  - name: home
    address: 10.255.255.20:53

reference_resolvers:
  - name: cloudflare
    address: 1.1.1.1:53
  - name: cloudflare-doh
    address: https://cloudflare-dns.com/dns-query
  - name: google
    address: 8.8.8.8:53

blocklist:
  source: ./blocked-names-sample.txt

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
  color: true
```

- [ ] **Step 3: Add README usage**

Create `README.md`:

```markdown
# dnscheck

`dnscheck` diagnoses DNS blocks for a URL by discovering page hostnames, querying a configured DNS server and reference resolvers, following CNAME chains, and reporting blocked names.

## Usage

```sh
dnscheck https://example.com
dnscheck --config dnscheck.config --color https://example.com
dnscheck --no-crawl https://events.launchdarkly.com
dnscheck -k https://self-signed.example.local
```

By default the tool looks for `./dnscheck.config`. Command-line flags override config values.

If no blocklist is configured, `dnscheck` still identifies blocked hostnames from DNS responses but skips sed-command output.

## Manual Integration Test

Place a blocklist sample in the working directory and configure `dns_servers` to point at the test DNS server. Then run:

```sh
go run ./cmd/dnscheck --config dnscheck.config --color https://example.com
```
```

- [ ] **Step 4: Run all tests**

Run:

```bash
go test ./...
```

Expected: PASS.

- [ ] **Step 5: Build CLI**

Run:

```bash
go build ./cmd/dnscheck
```

Expected: command exits 0 and creates `./dnscheck`.

- [ ] **Step 6: Run smoke commands**

Run:

```bash
./dnscheck --no-crawl --color https://example.com
./dnscheck --no-crawl --json https://example.com
```

Expected: both commands exit 0. Color output contains ANSI escapes only for `--color`; JSON output parses as JSON.

- [ ] **Step 7: Check working tree**

Run:

```bash
git status --short
```

Expected: implementation files are present and no generated binary is staged. If `./dnscheck` exists, leave it untracked or add it to `.gitignore` before the user commits later.

## Self-Review Checklist

- Spec coverage:
  - Optional config and default `dnscheck.config`: Task 1 and Task 7.
  - CLI precedence, `-k`, `--color`, `--no-crawl`: Task 1 and Task 7.
  - Classic DNS and DoH resolver selection: Task 4.
  - Recursive CNAME traversal and retries/timeouts: Task 4.
  - HINFO, blocked IP, NXDOMAIN classification: Task 3.
  - Depth `0`, depth `1`, document-like recursion: Task 5.
  - Blocklist source local/HTTPS, line numbers, sed: Task 2 and Task 8.
  - No blocklist mode: Task 6 and Task 7.
  - ANSI color and JSON: Task 6.
  - TLS validation and insecure override: Task 4, Task 5, and Task 8.
- Placeholder scan: no `TBD`, `TODO`, or undefined future function names are intentionally left in this plan.
- User preference: no git commit steps are included.
