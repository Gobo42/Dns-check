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
					Name:           "events.launchdarkly.com",
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
	run := Run{
		Hosts: []HostResult{
			{Host: "blocked.example", Primary: []dnsprobe.ResolverResult{{Status: dnsprobe.StatusBlocked}}},
			{Host: "ok.example", Primary: []dnsprobe.ResolverResult{{Status: dnsprobe.StatusResolved}}},
		},
	}
	out := Text(run, Options{Color: true})
	if !strings.Contains(out, "\x1b[31mblocked.example\x1b[0m") {
		t.Fatalf("blocked host not red:\n%s", out)
	}
	if !strings.Contains(out, "\x1b[32mok.example\x1b[0m") {
		t.Fatalf("resolved host not green:\n%s", out)
	}
}

func TestColorReportMarksReferenceChainHostnames(t *testing.T) {
	run := Run{
		Hosts: []HostResult{{
			Host: "blocked.example",
			Primary: []dnsprobe.ResolverResult{{
				Status: dnsprobe.StatusBlocked,
				Steps: []dnsprobe.ChainStep{{
					Name:           "blocked.example",
					Classification: dnsprobe.Classification{Status: dnsprobe.StatusBlocked, BlockedBy: "hinfo"},
				}},
			}},
			Reference: []dnsprobe.ResolverResult{{
				Status: dnsprobe.StatusResolved,
				Steps: []dnsprobe.ChainStep{
					{Name: "blocked.example", Classification: dnsprobe.Classification{Status: dnsprobe.StatusCNAME, CNAMEs: []string{"target.example"}}},
					{Name: "target.example", Classification: dnsprobe.Classification{Status: dnsprobe.StatusResolved, IPs: []string{"203.0.113.10"}}},
				},
			}},
		}},
	}

	out := Text(run, Options{Color: true})
	for _, want := range []string{
		"\x1b[32mblocked.example\x1b[0m",
		"\x1b[32mtarget.example\x1b[0m",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("reference chain missing colored hostname %q:\n%s", want, out)
		}
	}
}

func TestReferenceChainMarksOnlyBlockedCNAMEsRed(t *testing.T) {
	run := Run{
		Hosts: []HostResult{{
			Host:         "server1.example.com",
			BlockedNames: []string{"server1.example2.com"},
			Primary: []dnsprobe.ResolverResult{{
				Status: dnsprobe.StatusBlocked,
				Steps: []dnsprobe.ChainStep{{
					Name:           "server1.example2.com",
					Classification: dnsprobe.Classification{Status: dnsprobe.StatusBlocked, BlockedBy: "hinfo"},
				}},
			}},
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
		}},
	}

	out := Text(run, Options{Color: true})
	for _, want := range []string{
		"\x1b[32mserver1.example.com\x1b[0m",
		"\x1b[32mserver1.example1.com\x1b[0m",
		"\x1b[31mserver1.example2.com\x1b[0m",
		"\x1b[32mserver1.example3.com\x1b[0m",
		"203.0.113.10",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("reference chain missing %q:\n%s", want, out)
		}
	}
}

func TestTextReportListsMultipleMatchedCNAMEBlocklistLines(t *testing.T) {
	run := Run{
		BlocklistPath: "/tmp/blocked-names.txt",
		Hosts: []HostResult{{
			Host:         "server1.example.com",
			BlockedNames: []string{"server1.example2.com", "server1.example3.com"},
			Matches: []blocklist.Rule{
				{LineNumber: 120, Text: "*.example2.com"},
				{LineNumber: 451, Text: "server1.example3.com"},
			},
			Primary: []dnsprobe.ResolverResult{{
				ResolverName: "home",
				Status:       dnsprobe.StatusBlocked,
				Steps: []dnsprobe.ChainStep{{
					Name:           "server1.example2.com",
					Classification: dnsprobe.Classification{Status: dnsprobe.StatusBlocked, BlockedBy: "hinfo"},
				}},
			}},
			Reference: []dnsprobe.ResolverResult{{
				Status: dnsprobe.StatusResolved,
				Steps: []dnsprobe.ChainStep{{
					Name: "server1.example.com",
					Classification: dnsprobe.Classification{
						Status: dnsprobe.StatusResolved,
						CNAMEs: []string{"server1.example2.com", "server1.example3.com"},
						IPs:    []string{"203.0.113.10"},
					},
				}},
			}},
		}},
	}

	out := Text(run, Options{})
	for _, want := range []string{
		"matched blocklist line: 120: *.example2.com",
		"matched blocklist line: 451: server1.example3.com",
		`sed -i '/^\*\.example2\.com$/d' /tmp/blocked-names.txt`,
		`sed -i '/^server1\.example3\.com$/d' /tmp/blocked-names.txt`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("report missing %q:\n%s", want, out)
		}
	}
}

func TestTextReportDeduplicatesBlockedChainMembers(t *testing.T) {
	run := Run{
		Hosts: []HostResult{{
			Host: "sg.mmstat.com",
			Primary: []dnsprobe.ResolverResult{
				{
					ResolverName: "home",
					Status:       dnsprobe.StatusBlocked,
					Steps: []dnsprobe.ChainStep{{
						Name:           "sg.mmstat.com",
						Classification: dnsprobe.Classification{Status: dnsprobe.StatusBlocked, BlockedBy: "hinfo"},
					}},
				},
				{
					ResolverName: "home",
					Status:       dnsprobe.StatusBlocked,
					Steps: []dnsprobe.ChainStep{{
						Name:           "sg.mmstat.com.gds.alibabadns.com",
						Classification: dnsprobe.Classification{Status: dnsprobe.StatusBlocked, BlockedBy: "hinfo"},
					}},
				},
				{
					ResolverName: "home",
					Status:       dnsprobe.StatusBlocked,
					Steps: []dnsprobe.ChainStep{{
						Name:           "sg.mmstat.com.gds.alibabadns.com",
						Classification: dnsprobe.Classification{Status: dnsprobe.StatusBlocked, BlockedBy: "hinfo"},
					}},
				},
			},
		}},
	}

	out := Text(run, Options{})
	if count := strings.Count(out, "blocked chain member: sg.mmstat.com.gds.alibabadns.com"); count != 1 {
		t.Fatalf("duplicate blocked chain member count = %d, want 1:\n%s", count, out)
	}
	if count := strings.Count(out, "blocked by resolver: home"); count != 1 {
		t.Fatalf("duplicate resolver line count = %d, want 1:\n%s", count, out)
	}
}

func TestJSONReportSerializes(t *testing.T) {
	data, err := JSON(Run{Hosts: []HostResult{{Host: "example.com"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"host": "example.com"`) {
		t.Fatalf("json = %s", data)
	}
}
