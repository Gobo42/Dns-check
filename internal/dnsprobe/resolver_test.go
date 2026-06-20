package dnsprobe

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"dnscheck/internal/config"
	"github.com/miekg/dns"
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
		"a.vendor.net.":  msgWithRR(t, "a.vendor.net. 60 IN CNAME b.vendor.net."),
		"b.vendor.net.":  msgWithRR(t, "b.vendor.net. 60 IN A 203.0.113.10"),
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
		"start.example.":      msgWithRR(t, "start.example. 60 IN CNAME blocked.vendor.net."),
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

func TestProbeLogsQueryAtVerboseLevelOne(t *testing.T) {
	var log bytes.Buffer
	fake := &fakeExchange{replies: map[string]*dns.Msg{
		"start.example.": msgWithRR(t, "start.example. 60 IN A 203.0.113.10"),
	}}
	resolver := NewResolver(
		config.ResolverConfig{Name: "test", Address: "127.0.0.1:53"},
		config.Default().DNS,
		NewClassifier(config.Default().BlockedSignals),
		fake,
		LogOptions{Level: 1, Writer: &log},
	)

	_ = resolver.Probe(context.Background(), "start.example")
	if !strings.Contains(log.String(), "dns query resolver=test host=start.example") {
		t.Fatalf("log missing query:\n%s", log.String())
	}
	if strings.Contains(log.String(), "dns result") {
		t.Fatalf("level 1 should not include result:\n%s", log.String())
	}
}

func TestProbeLogsResultAtVerboseLevelTwo(t *testing.T) {
	var log bytes.Buffer
	fake := &fakeExchange{replies: map[string]*dns.Msg{
		"start.example.": msgWithRR(t, "start.example. 60 IN A 203.0.113.10"),
	}}
	resolver := NewResolver(
		config.ResolverConfig{Name: "test", Address: "127.0.0.1:53"},
		config.Default().DNS,
		NewClassifier(config.Default().BlockedSignals),
		fake,
		LogOptions{Level: 2, Writer: &log},
	)

	_ = resolver.Probe(context.Background(), "start.example")
	if !strings.Contains(log.String(), "dns result resolver=test host=start.example status=resolved ips=203.0.113.10") {
		t.Fatalf("log missing result:\n%s", log.String())
	}
}

func TestProbeAllLimitsConcurrency(t *testing.T) {
	var active int32
	var maxActive int32
	ex := exchangeFunc(func(ctx context.Context, msg *dns.Msg, address string) (*dns.Msg, error) {
		now := atomic.AddInt32(&active, 1)
		for {
			max := atomic.LoadInt32(&maxActive)
			if now <= max || atomic.CompareAndSwapInt32(&maxActive, max, now) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		atomic.AddInt32(&active, -1)
		return msgWithRR(t, msg.Question[0].Name+" 60 IN A 203.0.113.10"), nil
	})
	cfg := config.Default()
	cfg.DNS.MaxConcurrentQueries = 2
	resolvers := []Resolver{
		NewResolver(config.ResolverConfig{Name: "r1", Address: "127.0.0.1:53"}, cfg.DNS, NewClassifier(cfg.BlockedSignals), ex),
		NewResolver(config.ResolverConfig{Name: "r2", Address: "127.0.0.2:53"}, cfg.DNS, NewClassifier(cfg.BlockedSignals), ex),
	}

	_ = ProbeAll(context.Background(), []string{"a.example", "b.example", "c.example"}, resolvers, cfg.DNS.MaxConcurrentQueries)
	if got := atomic.LoadInt32(&maxActive); got > 2 {
		t.Fatalf("max concurrent probes = %d, want <= 2", got)
	}
}

func TestProbeAllCachesSharedCNAMEParentPerResolver(t *testing.T) {
	fake := &countingExchange{replies: map[string]*dns.Msg{
		"a.example.":         msgWithRR(t, "a.example. 60 IN CNAME shared.vendor.net."),
		"b.example.":         msgWithRR(t, "b.example. 60 IN CNAME shared.vendor.net."),
		"shared.vendor.net.": msgWithRR(t, "shared.vendor.net. 60 IN A 203.0.113.10"),
	}}
	cfg := config.Default()
	resolver := NewResolver(config.ResolverConfig{Name: "r1", Address: "127.0.0.1:53"}, cfg.DNS, NewClassifier(cfg.BlockedSignals), fake)

	results := ProbeAll(context.Background(), []string{"a.example", "b.example"}, []Resolver{resolver}, cfg.DNS.MaxConcurrentQueries)
	if len(results) != 2 {
		t.Fatalf("results = %d, want 2", len(results))
	}
	if got := fake.calls["shared.vendor.net."]; got != 1 {
		t.Fatalf("shared parent lookups = %d, want 1", got)
	}
}

type exchangeFunc func(context.Context, *dns.Msg, string) (*dns.Msg, error)

func (f exchangeFunc) ExchangeContext(ctx context.Context, msg *dns.Msg, address string) (*dns.Msg, error) {
	return f(ctx, msg, address)
}

type countingExchange struct {
	replies map[string]*dns.Msg
	calls   map[string]int
}

func (c *countingExchange) ExchangeContext(ctx context.Context, msg *dns.Msg, address string) (*dns.Msg, error) {
	if c.calls == nil {
		c.calls = map[string]int{}
	}
	name := msg.Question[0].Name
	c.calls[name]++
	return c.replies[name], nil
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
