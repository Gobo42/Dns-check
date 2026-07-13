package dnsprobe

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"dnscheck/internal/ansicolor"
	"dnscheck/internal/config"
	"github.com/miekg/dns"
)

type Exchanger interface {
	ExchangeContext(ctx context.Context, msg *dns.Msg, address string) (*dns.Msg, error)
}

type Resolver struct {
	cfg        config.ResolverConfig
	dnsCfg     config.DNSConfig
	classifier Classifier
	exchange   Exchanger
	log        LogOptions
	cache      *Cache
}

type HostProbeResult struct {
	Host    string           `json:"host"`
	Results []ResolverResult `json:"results"`
}

type LogOptions struct {
	Level    int
	Writer   io.Writer
	Color    bool
	Internal bool
}

func NewResolver(cfg config.ResolverConfig, dnsCfg config.DNSConfig, classifier Classifier, exchange Exchanger, logOptions ...LogOptions) Resolver {
	log := LogOptions{}
	if len(logOptions) > 0 {
		log = logOptions[0]
	}
	if log.Level > 0 && log.Writer == nil {
		log.Writer = os.Stderr
	}
	return Resolver{cfg: cfg, dnsCfg: dnsCfg, classifier: classifier, exchange: exchange, log: log}
}

type Cache struct {
	mu      sync.Mutex
	replies map[string]*dns.Msg
}

func NewCache() *Cache {
	return &Cache{replies: map[string]*dns.Msg{}}
}

func (r Resolver) WithCache(cache *Cache) Resolver {
	r.cache = cache
	return r
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
		r.logQuery(current)
		reply, err := r.exchangeWithRetries(ctx, msg)
		if err != nil {
			result.Status = StatusError
			result.Error = err.Error()
			result.Steps = append(result.Steps, ChainStep{Name: current, Classification: Classification{Status: StatusError, Error: err.Error()}})
			r.logResult(current, Classification{Status: StatusError, Error: err.Error()})
			return result
		}

		classification := r.classifier.Classify(reply)
		r.logResult(current, classification)
		result.Steps = append(result.Steps, ChainStep{Name: current, Classification: classification})

		switch classification.Status {
		case StatusResolved, StatusBlocked, StatusPrivate, StatusNXDOMAIN, StatusError:
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

func (r Resolver) logQuery(host string) {
	if r.log.Level < 1 || r.log.Writer == nil {
		return
	}
	fmt.Fprintf(r.log.Writer, "dns query resolver=%s host=%s address=%s type=%s\n",
		r.colorResolverName(),
		ansicolor.Color(host, "purple", r.log.Color),
		colorAddress(r.cfg.Address, r.log.Color),
		ansicolor.Color("A", "purple", r.log.Color))
}

func (r Resolver) logResult(host string, classification Classification) {
	if r.log.Level < 2 || r.log.Writer == nil {
		return
	}
	parts := []string{
		fmt.Sprintf("dns result resolver=%s", r.colorResolverName()),
		fmt.Sprintf("host=%s", ansicolor.Color(host, "purple", r.log.Color)),
		fmt.Sprintf("status=%s", classification.Status),
	}
	if classification.BlockedBy != "" {
		parts = append(parts, "blocked_by="+classification.BlockedBy)
	}
	if len(classification.CNAMEs) > 0 {
		colored := make([]string, len(classification.CNAMEs))
		for i, name := range classification.CNAMEs {
			colored[i] = ansicolor.Color(name, "purple", r.log.Color)
		}
		parts = append(parts, "cnames="+strings.Join(colored, ","))
	}
	if len(classification.IPs) > 0 {
		colored := make([]string, len(classification.IPs))
		for i, ip := range classification.IPs {
			colored[i] = colorIP(ip, r.log.Color)
		}
		parts = append(parts, "ips="+strings.Join(colored, ","))
	}
	if classification.Error != "" {
		parts = append(parts, "error="+classification.Error)
	}
	fmt.Fprintln(r.log.Writer, strings.Join(parts, " "))
}

// colorResolverName colors the resolver's name yellow if it is one of the
// internal (primary, dns_servers) resolvers being diagnosed, or green if it
// is an external reference resolver.
func (r Resolver) colorResolverName() string {
	if r.log.Internal {
		return ansicolor.Color(r.cfg.Name, "yellow", r.log.Color)
	}
	return ansicolor.Color(r.cfg.Name, "green", r.log.Color)
}

// colorAddress colors a resolver address (host:port, or a DoH URL) purple,
// or yellow if its host portion is a private/loopback IP.
func colorAddress(address string, enabled bool) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	if ip := net.ParseIP(host); ip != nil {
		if _, private := classifyPrivateIP(ip); private {
			return ansicolor.Color(address, "yellow", enabled)
		}
	}
	return ansicolor.Color(address, "purple", enabled)
}

// colorIP colors a resolved IP address purple, or yellow if it is a
// private/loopback address.
func colorIP(ipStr string, enabled bool) string {
	if ip := net.ParseIP(ipStr); ip != nil {
		if _, private := classifyPrivateIP(ip); private {
			return ansicolor.Color(ipStr, "yellow", enabled)
		}
	}
	return ansicolor.Color(ipStr, "purple", enabled)
}

func ProbeAll(ctx context.Context, hosts []string, resolvers []Resolver, maxConcurrent int) []HostProbeResult {
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	cache := NewCache()
	cachedResolvers := make([]Resolver, len(resolvers))
	for i, resolver := range resolvers {
		cachedResolvers[i] = resolver.WithCache(cache)
	}
	sortedHosts := append([]string(nil), hosts...)
	sort.Strings(sortedHosts)

	results := make([]HostProbeResult, len(sortedHosts))
	for i, host := range sortedHosts {
		results[i].Host = host
		results[i].Results = make([]ResolverResult, len(cachedResolvers))
	}

	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	for hostIndex, host := range sortedHosts {
		for resolverIndex, resolver := range cachedResolvers {
			wg.Add(1)
			go func(hostIndex int, host string, resolverIndex int, resolver Resolver) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				results[hostIndex].Results[resolverIndex] = resolver.Probe(ctx, host)
			}(hostIndex, host, resolverIndex, resolver)
		}
	}
	wg.Wait()
	return results
}

func (r Resolver) exchangeWithRetries(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	cacheKey := r.cacheKey(msg)
	if r.cache != nil {
		if reply, ok := r.cachedReply(cacheKey); ok {
			return reply, nil
		}
	}
	var lastErr error
	for attempt := 0; attempt <= r.dnsCfg.Retries; attempt++ {
		attemptCtx, cancel := context.WithTimeout(ctx, time.Duration(r.dnsCfg.Timeout))
		reply, err := r.exchange.ExchangeContext(attemptCtx, msg, r.cfg.Address)
		cancel()
		if err == nil {
			if r.cache != nil {
				r.storeCachedReply(cacheKey, reply)
			}
			return reply, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("after %d attempts: %w", r.dnsCfg.Retries+1, lastErr)
}

func (r Resolver) cacheKey(msg *dns.Msg) string {
	if len(msg.Question) == 0 {
		return r.cfg.Name + "|" + r.cfg.Address + "|unknown"
	}
	q := msg.Question[0]
	return fmt.Sprintf("%s|%s|%d|%s", r.cfg.Name, r.cfg.Address, q.Qtype, strings.ToLower(q.Name))
}

func (r Resolver) cachedReply(key string) (*dns.Msg, bool) {
	r.cache.mu.Lock()
	defer r.cache.mu.Unlock()
	reply, ok := r.cache.replies[key]
	if !ok {
		return nil, false
	}
	return reply.Copy(), true
}

func (r Resolver) storeCachedReply(key string, reply *dns.Msg) {
	r.cache.mu.Lock()
	defer r.cache.mu.Unlock()
	r.cache.replies[key] = reply.Copy()
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
		return &DoHExchange{
			client: &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipTLSVerify},
				},
			},
		}
	}
	return &ClassicExchange{client: &dns.Client{Net: "udp"}}
}
