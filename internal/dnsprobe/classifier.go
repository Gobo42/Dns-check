package dnsprobe

import (
	"net"
	"strings"

	"dnscheck/internal/config"
	"github.com/miekg/dns"
)

type Classifier struct {
	signals config.BlockedSignals
}

var privateIPBlocks = []struct {
	network *net.IPNet
	reason  string
}{
	{mustParseCIDR("10.0.0.0/8"), "rfc1918"},
	{mustParseCIDR("172.16.0.0/12"), "rfc1918"},
	{mustParseCIDR("192.168.0.0/16"), "rfc1918"},
	{mustParseCIDR("127.0.0.0/8"), "loopback"},
}

func mustParseCIDR(cidr string) *net.IPNet {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	return network
}

func classifyPrivateIP(ip net.IP) (reason string, private bool) {
	for _, block := range privateIPBlocks {
		if block.network.Contains(ip) {
			return block.reason, true
		}
	}
	return "", false
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
			if reason, private := classifyPrivateIP(rr.A); private {
				return Classification{Status: StatusPrivate, BlockedBy: reason, IPs: []string{ip}}
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
