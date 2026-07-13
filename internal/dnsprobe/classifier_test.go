package dnsprobe

import (
	"net"
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

func TestClassifiesRFC1918AddressAsPrivate(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("blocked.example.", dns.TypeA)
	msg.Rcode = dns.RcodeSuccess
	msg.Answer = []dns.RR{
		mustRR(t, "blocked.example. 60 IN A 10.1.2.3"),
	}

	got := NewClassifier(config.Default().BlockedSignals).Classify(msg)
	if got.Status != StatusPrivate {
		t.Fatalf("status = %s, want private", got.Status)
	}
	if got.BlockedBy != "rfc1918" {
		t.Fatalf("blocked by = %q, want rfc1918", got.BlockedBy)
	}
	if len(got.IPs) != 1 || got.IPs[0] != "10.1.2.3" {
		t.Fatalf("ips = %#v", got.IPs)
	}
}

func TestClassifiesLoopbackAddressAsPrivate(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("blocked.example.", dns.TypeA)
	msg.Rcode = dns.RcodeSuccess
	msg.Answer = []dns.RR{
		mustRR(t, "blocked.example. 60 IN A 127.5.5.5"),
	}

	got := NewClassifier(config.Default().BlockedSignals).Classify(msg)
	if got.Status != StatusPrivate {
		t.Fatalf("status = %s, want private", got.Status)
	}
	if got.BlockedBy != "loopback" {
		t.Fatalf("blocked by = %q, want loopback", got.BlockedBy)
	}
}

func TestBlockedIPConfigWinsOverPrivateClassification(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("blocked.example.", dns.TypeA)
	msg.Rcode = dns.RcodeSuccess
	msg.Answer = []dns.RR{
		mustRR(t, "blocked.example. 60 IN A 127.0.0.1"),
	}

	got := NewClassifier(config.Default().BlockedSignals).Classify(msg)
	if got.Status != StatusBlocked {
		t.Fatalf("status = %s, want blocked (explicit blocked_ip config should win)", got.Status)
	}
	if got.BlockedBy != "blocked_ip" {
		t.Fatalf("blocked by = %q, want blocked_ip", got.BlockedBy)
	}
}

func TestClassifyPrivateIP(t *testing.T) {
	cases := []struct {
		ip         string
		wantReason string
		wantOK     bool
	}{
		{"10.0.0.1", "rfc1918", true},
		{"172.16.0.1", "rfc1918", true},
		{"172.31.255.255", "rfc1918", true},
		{"192.168.1.1", "rfc1918", true},
		{"127.0.0.1", "loopback", true},
		{"127.255.255.255", "loopback", true},
		{"93.184.216.34", "", false},
		{"172.32.0.1", "", false},
		{"8.8.8.8", "", false},
	}
	for _, c := range cases {
		reason, ok := classifyPrivateIP(net.ParseIP(c.ip))
		if ok != c.wantOK || reason != c.wantReason {
			t.Errorf("classifyPrivateIP(%s) = (%q, %v), want (%q, %v)", c.ip, reason, ok, c.wantReason, c.wantOK)
		}
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
