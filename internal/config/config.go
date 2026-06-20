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
	BlockedSignals     BlockedSignals   `yaml:"blocked_signals"`
	DNS                DNSConfig        `yaml:"dns"`
	Crawl              CrawlConfig      `yaml:"crawl"`
	Output             OutputConfig     `yaml:"output"`
}

type ResolverConfig struct {
	Name     string `yaml:"name"`
	Address  string `yaml:"address"`
	Priority int    `yaml:"priority"`
}

type BlocklistConfig struct {
	Source string `yaml:"source"`
}

type BlockedSignals struct {
	HINFOContains          []string `yaml:"hinfo_contains"`
	BlockedIPs             []string `yaml:"blocked_ips"`
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
			BlockedIPs:    []string{"0.0.0.0", "127.0.0.1"},
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
