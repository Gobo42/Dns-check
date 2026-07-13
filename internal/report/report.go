package report

import (
	"encoding/json"
	"fmt"
	"sort"
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
	Host         string                    `json:"host"`
	Primary      []dnsprobe.ResolverResult `json:"primary"`
	Reference    []dnsprobe.ResolverResult `json:"reference"`
	Matches      []blocklist.Rule          `json:"matches,omitempty"`
	BlockedNames []string                  `json:"blocked_names,omitempty"`
}

type Options struct {
	Color bool
}

func Text(run Run, opts Options) string {
	sort.Slice(run.Hosts, func(i, j int) bool { return run.Hosts[i].Host < run.Hosts[j].Host })
	var b strings.Builder
	writeBlocked(&b, run, opts)
	writeSed(&b, run)
	writeAllowed(&b, run, opts)
	writeResolverErrors(&b, run)
	writeWarnings(&b, run, opts)
	return b.String()
}

func JSON(run Run) ([]byte, error) {
	return json.MarshalIndent(run, "", "  ")
}

func writeBlocked(b *strings.Builder, run Run, opts Options) {
	b.WriteString("Blocked hosts\n=============\n")
	wrote := false
	for _, host := range run.Hosts {
		if !isBlocked(host) {
			continue
		}
		wrote = true
		fmt.Fprintf(b, "%s\n", color(host.Host, "red", opts.Color))
		wroteResolvers := map[string]bool{}
		wroteMembers := map[string]bool{}
		for _, primary := range host.Primary {
			if primary.Status == dnsprobe.StatusBlocked || primary.Status == dnsprobe.StatusPrivate {
				if !wroteResolvers[primary.ResolverName] {
					wroteResolvers[primary.ResolverName] = true
					fmt.Fprintf(b, "  blocked by resolver: %s\n", primary.ResolverName)
				}
				for _, step := range primary.Steps {
					if step.Classification.Status == dnsprobe.StatusBlocked || step.Classification.Status == dnsprobe.StatusPrivate {
						normalized := strings.ToLower(strings.TrimSuffix(step.Name, "."))
						if wroteMembers[normalized] {
							continue
						}
						wroteMembers[normalized] = true
						fmt.Fprintf(b, "  blocked chain member: %s\n", color(normalized, "red", opts.Color))
					}
				}
			}
		}
		for _, match := range host.Matches {
			fmt.Fprintf(b, "  matched blocklist line: %d: %s\n", match.LineNumber, match.Text)
		}
		if chain := firstReferenceChain(host.Reference, host.BlockedNames, opts); chain != "" {
			fmt.Fprintf(b, "  reference chain: %s\n", chain)
		}
	}
	if !wrote {
		b.WriteString("none\n")
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
	var rules []blocklist.Rule
	for _, rule := range seen {
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].LineNumber < rules[j].LineNumber })
	b.WriteString("Sed commands\n============\n")
	for _, rule := range rules {
		b.WriteString(blocklist.SedDeleteCommand(run.BlocklistPath, rule))
		b.WriteString("\n")
	}
	b.WriteString("\n")
}

func writeAllowed(b *strings.Builder, run Run, opts Options) {
	b.WriteString("Allowed / not blocked hostnames\n===============================\n")
	wrote := false
	for _, host := range run.Hosts {
		if isBlocked(host) {
			continue
		}
		wrote = true
		b.WriteString(color(host.Host, "green", opts.Color))
		b.WriteString("\n")
	}
	if !wrote {
		b.WriteString("none\n")
	}
	b.WriteString("\n")
}

func writeResolverErrors(b *strings.Builder, run Run) {
	var lines []string
	for _, host := range run.Hosts {
		for _, resolver := range append(host.Primary, host.Reference...) {
			if resolver.Status == dnsprobe.StatusError {
				lines = append(lines, fmt.Sprintf("%s\n  %s: %s", host.Host, resolver.ResolverName, resolver.Error))
			}
		}
	}
	if len(lines) == 0 {
		return
	}
	b.WriteString("Resolver errors\n===============\n")
	for _, line := range lines {
		b.WriteString(line)
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
	if len(host.Matches) > 0 || len(host.BlockedNames) > 0 {
		return true
	}
	for _, primary := range host.Primary {
		if primary.Status == dnsprobe.StatusBlocked || primary.Status == dnsprobe.StatusPrivate {
			return true
		}
	}
	return false
}

func firstReferenceChain(results []dnsprobe.ResolverResult, blockedNames []string, opts Options) string {
	blocked := map[string]bool{}
	for _, name := range blockedNames {
		blocked[strings.ToLower(strings.TrimSuffix(name, "."))] = true
	}
	for _, result := range results {
		if len(result.Steps) == 0 {
			continue
		}
		var names []string
		for _, step := range result.Steps {
			names = appendChainName(names, step.Name, blocked, opts)
			for _, cname := range step.Classification.CNAMEs {
				names = appendChainName(names, cname, blocked, opts)
			}
		}
		last := result.Steps[len(result.Steps)-1]
		if len(last.Classification.IPs) > 0 {
			names = append(names, last.Classification.IPs...)
		}
		return strings.Join(names, " -> ")
	}
	return ""
}

func appendChainName(names []string, name string, blocked map[string]bool, opts Options) []string {
	normalized := strings.ToLower(strings.TrimSuffix(name, "."))
	if normalized == "" {
		return names
	}
	if len(names) > 0 && stripANSI(names[len(names)-1]) == normalized {
		return names
	}
	colorName := "green"
	if blocked[normalized] {
		colorName = "red"
	}
	return append(names, color(normalized, colorName, opts.Color))
}

func stripANSI(s string) string {
	for _, code := range []string{"\x1b[31m", "\x1b[32m", "\x1b[33m", "\x1b[0m"} {
		s = strings.ReplaceAll(s, code, "")
	}
	return s
}

func color(s, name string, enabled bool) string {
	if !enabled {
		return s
	}
	code := map[string]string{"red": "31", "green": "32", "yellow": "33"}[name]
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}
