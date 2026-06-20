package dnsprobe

import (
	"testing"

	"dnscheck/internal/config"
	"github.com/miekg/dns"
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
