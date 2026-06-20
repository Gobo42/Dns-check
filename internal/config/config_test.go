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
    priority: 20
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
	if cfg.ReferenceResolvers[0].Priority != 20 {
		t.Fatalf("reference priority = %d, want 20", cfg.ReferenceResolvers[0].Priority)
	}
}

func TestExplicitZeroRetriesIsPreserved(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dnscheck.config")
	err := os.WriteFile(path, []byte(`
dns:
  retries: 0
`), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DNS.Retries != 0 {
		t.Fatalf("retries = %d, want explicit 0", cfg.DNS.Retries)
	}
}
