package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"dnscheck/internal/ansicolor"
	"dnscheck/internal/blocklist"
	"dnscheck/internal/config"
	"dnscheck/internal/dnsprobe"
	"dnscheck/internal/report"
	"dnscheck/internal/webscan"
)

func colorNum(n int, enabled bool) string {
	return ansicolor.Color(strconv.Itoa(n), "purple", enabled)
}

type Options struct {
	ConfigPath string
	URL        string
	JSON       bool
	Help       bool
	Verbose    int
}

func Parse(args []string) (Options, config.Config, error) {
	fs := flag.NewFlagSet("dnscheck", flag.ContinueOnError)
	cfgPath := fs.String("config", "dnscheck.config", "config file path")
	jsonOut := fs.Bool("json", false, "print JSON output")
	color := fs.Bool("color", false, "enable ANSI color")
	insecure := fs.Bool("k", false, "ignore HTTPS certificate validation errors")
	noCrawl := fs.Bool("no-crawl", false, "skip page crawl and only check the input URL hostname")
	verbose := fs.Bool("v", false, "log each DNS query to stderr")
	veryVerbose := fs.Bool("vv", false, "log each DNS query and DNS result to stderr")

	if err := fs.Parse(normalizeArgs(args)); err != nil {
		return Options{}, config.Config{}, err
	}
	if fs.NArg() == 0 {
		return Options{Help: true}, config.Config{}, nil
	}
	if fs.NArg() != 1 {
		return Options{}, config.Config{}, errors.New("url is required")
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return Options{}, config.Config{}, err
	}
	target := fs.Arg(0)
	bareHost := isBareHost(target)
	cfg.Apply(config.Overrides{
		NoCrawl:               *noCrawl,
		InsecureSkipTLSVerify: *insecure,
		Color:                 *color,
	})
	if bareHost {
		cfg.Crawl.Depth = 0
		target = "https://" + target
	}

	verboseLevel := 0
	if *verbose {
		verboseLevel = 1
	}
	if *veryVerbose {
		verboseLevel = 2
	}

	return Options{ConfigPath: *cfgPath, URL: target, JSON: *jsonOut, Verbose: verboseLevel}, cfg, nil
}

func normalizeArgs(args []string) []string {
	var flags []string
	var positionals []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--":
			positionals = append(positionals, args[i+1:]...)
			i = len(args)
		case arg == "--config":
			flags = append(flags, arg)
			if i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		case strings.HasPrefix(arg, "--config="):
			flags = append(flags, arg)
		case isKnownBoolFlag(arg):
			flags = append(flags, arg)
		default:
			positionals = append(positionals, arg)
		}
	}
	return append(flags, positionals...)
}

func isKnownBoolFlag(arg string) bool {
	switch arg {
	case "--json", "--color", "--no-crawl", "-k", "-v", "-vv":
		return true
	default:
		return false
	}
}

func Main(args []string, stdout io.Writer, stderr io.Writer) error {
	opts, cfg, err := Parse(args)
	if err != nil {
		return err
	}
	if opts.Help {
		printHelp(stderr)
		return nil
	}

	var list blocklist.List
	var blocklistPath string
	var warnings []string
	if cfg.Blocklist.Source != "" {
		fmt.Fprintf(stderr, "loading blocklist %s\n", cfg.Blocklist.Source)
		loaded, err := blocklist.LoadSource(cfg.Blocklist.Source, cfg.Crawl.InsecureSkipTLSVerify)
		if err != nil {
			return fmt.Errorf("load blocklist: %w", err)
		}
		list = loaded.List
		for _, parseErr := range list.Errors {
			fmt.Fprintf(stderr, "blocklist parse error line %d: %s (%s)\n", parseErr.LineNumber, parseErr.Text, parseErr.Reason)
		}
		if loaded.Local {
			blocklistPath = loaded.LocalPath
		} else {
			warnings = append(warnings, "remote blocklist source configured; sed commands require a local active blocklist path")
		}
	}
	if cfg.Crawl.InsecureSkipTLSVerify {
		warnings = append(warnings, "HTTPS certificate verification disabled by -k or config")
	}

	probe := func(resolver resolverRef, host string) dnsprobe.ResolverResult {
		return resolver.Resolver.Probe(context.Background(), host)
	}
	cache := dnsprobe.NewCache()
	primaryGroups := buildResolverGroups(cfg.DNSServers, cfg, opts.Verbose, stderr, cache, true)
	referenceGroups := buildResolverGroups(cfg.ReferenceResolvers, cfg, opts.Verbose, stderr, cache, false)

	if cfg.Crawl.Depth == 0 {
		fmt.Fprintf(stderr, "dns-only check %s\n", ansicolor.Color(displayTarget(opts.URL), "blue", cfg.Output.Color))
	} else {
		fmt.Fprintf(stderr, "scanning %s\n", ansicolor.Color(opts.URL, "blue", cfg.Output.Color))
	}
	scanner := webscan.New(cfg.Crawl.InsecureSkipTLSVerify)
	scanner.Log = webscan.LogOptions{Level: opts.Verbose, Writer: stderr, Color: cfg.Output.Color}
	scanner.Resolve = newCrawlResolve(primaryGroups, referenceGroups, probe)
	scanResult, err := scanner.Scan(opts.URL, cfg.Crawl)
	if err != nil {
		return fmt.Errorf("scan URL: %w", err)
	}
	warnings = append(warnings, scanResult.Warnings...)

	hosts := sortedHosts(scanResult.Hosts)
	fmt.Fprintf(stderr, "checking %s hosts with %s local resolver groups and %s reference resolver groups, max concurrency %s\n",
		colorNum(len(hosts), cfg.Output.Color),
		colorNum(len(primaryGroups), cfg.Output.Color),
		colorNum(len(referenceGroups), cfg.Output.Color),
		colorNum(cfg.DNS.MaxConcurrentQueries, cfg.Output.Color))
	primaryProbed := probeLocalPriorityGroups(hosts, primaryGroups, probe)
	referenceProbed := probeReferencePriorityGroups(hosts, referenceGroups, probe)

	var hostResults []report.HostResult
	for i, item := range primaryProbed {
		hostResult := report.HostResult{Host: item.Host}
		hostResult.Primary = append(hostResult.Primary, item.Results...)
		if i < len(referenceProbed) {
			hostResult.Reference = append(hostResult.Reference, referenceProbed[i].Results...)
		}
		if len(list.Rules) > 0 {
			hostResult.Matches, hostResult.BlockedNames = matchesForHostAndChainMembers(list, item.Host, hostResult.Primary, hostResult.Reference)
		}
		warnings = append(warnings, collectPrivateWarnings(hostResult.Primary)...)
		hostResults = append(hostResults, hostResult)
	}

	if len(cfg.DNSServers) > 0 {
		cnames := collectReferenceCNAMEs(hostResults)
		if len(cnames) > 0 {
			fmt.Fprintf(stderr, "checking %s reference cnames with %s local resolver groups, max concurrency %s\n",
				colorNum(len(cnames), cfg.Output.Color),
				colorNum(len(primaryGroups), cfg.Output.Color),
				colorNum(cfg.DNS.MaxConcurrentQueries, cfg.Output.Color))
			cnameProbes := probeLocalPriorityGroups(cnames, primaryGroups, probe)
			mergeCNAMEProbeResults(hostResults, cnameProbes, list)
		}
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

type resolverRef struct {
	Name     string
	Priority int
	Resolver dnsprobe.Resolver
}

type resolverGroup struct {
	Priority  int
	Resolvers []resolverRef
}

func buildResolverGroups(configs []config.ResolverConfig, cfg config.Config, verbose int, log io.Writer, cache *dnsprobe.Cache, internal bool) []resolverGroup {
	classifier := dnsprobe.NewClassifier(cfg.BlockedSignals)
	byPriority := map[int][]resolverRef{}
	for _, resolverCfg := range configs {
		ref := resolverRef{
			Name:     resolverCfg.Name,
			Priority: resolverCfg.Priority,
			Resolver: dnsprobe.NewResolver(
				resolverCfg,
				cfg.DNS,
				classifier,
				dnsprobe.NewExchange(resolverCfg.Address, cfg.Crawl.InsecureSkipTLSVerify),
				dnsprobe.LogOptions{Level: verbose, Writer: log, Color: cfg.Output.Color, Internal: internal},
			).WithCache(cache),
		}
		byPriority[resolverCfg.Priority] = append(byPriority[resolverCfg.Priority], ref)
	}
	var priorities []int
	for priority := range byPriority {
		priorities = append(priorities, priority)
	}
	sort.Ints(priorities)
	var groups []resolverGroup
	for _, priority := range priorities {
		groups = append(groups, resolverGroup{Priority: priority, Resolvers: byPriority[priority]})
	}
	return groups
}

type probeFunc func(resolver resolverRef, host string) dnsprobe.ResolverResult

func probeLocalPriorityGroups(hosts []string, groups []resolverGroup, probe probeFunc) []dnsprobe.HostProbeResult {
	var results []dnsprobe.HostProbeResult
	for hostIndex, host := range hosts {
		hostResult := dnsprobe.HostProbeResult{Host: host}
		for _, group := range groups {
			if len(group.Resolvers) == 0 {
				continue
			}
			start := hostIndex % len(group.Resolvers)
			groupResults := make([]dnsprobe.ResolverResult, 0, len(group.Resolvers))
			for offset := range group.Resolvers {
				resolver := group.Resolvers[(start+offset)%len(group.Resolvers)]
				result := probe(resolver, host)
				groupResults = append(groupResults, result)
				if resolverWorked(result) {
					hostResult.Results = append(hostResult.Results, result)
					break
				}
			}
			if len(hostResult.Results) > 0 && resolverWorked(hostResult.Results[len(hostResult.Results)-1]) {
				break
			}
			hostResult.Results = append(hostResult.Results, groupResults...)
		}
		results = append(results, hostResult)
	}
	return results
}

func probeReferencePriorityGroups(hosts []string, groups []resolverGroup, probe probeFunc) []dnsprobe.HostProbeResult {
	var results []dnsprobe.HostProbeResult
	for _, host := range hosts {
		hostResult := dnsprobe.HostProbeResult{Host: host}
		for _, group := range groups {
			var groupResults []dnsprobe.ResolverResult
			worked := false
			for _, resolver := range group.Resolvers {
				result := probe(resolver, host)
				groupResults = append(groupResults, result)
				if resolverWorked(result) {
					worked = true
				}
			}
			hostResult.Results = append(hostResult.Results, groupResults...)
			if worked {
				break
			}
		}
		results = append(results, hostResult)
	}
	return results
}

func resolverWorked(result dnsprobe.ResolverResult) bool {
	return result.Status == dnsprobe.StatusResolved || result.Status == dnsprobe.StatusBlocked ||
		result.Status == dnsprobe.StatusPrivate || result.Status == dnsprobe.StatusNXDOMAIN
}

// newCrawlResolve builds a webscan.Resolve that pins the crawler's dials to
// the internal (dns_servers) resolver's answer, falling back to the
// reference resolvers only when the internal answer is blocked or resolves
// to a private/loopback address. It never returns an IP that didn't come
// from a StatusResolved result, since blocked/private classifications carry
// the sinkhole/private address itself in their IPs field.
func newCrawlResolve(primaryGroups, referenceGroups []resolverGroup, probe probeFunc) webscan.Resolve {
	return func(ctx context.Context, host string) (string, bool) {
		if len(primaryGroups) == 0 {
			return "", false
		}
		primary := lastResult(probeLocalPriorityGroups([]string{host}, primaryGroups, probe)[0])
		if primary.Status == dnsprobe.StatusResolved {
			return firstIP(primary)
		}
		if (primary.Status == dnsprobe.StatusBlocked || primary.Status == dnsprobe.StatusPrivate) && len(referenceGroups) > 0 {
			reference := lastResult(probeReferencePriorityGroups([]string{host}, referenceGroups, probe)[0])
			if reference.Status == dnsprobe.StatusResolved {
				return firstIP(reference)
			}
		}
		return "", false
	}
}

func lastResult(hp dnsprobe.HostProbeResult) dnsprobe.ResolverResult {
	if len(hp.Results) == 0 {
		return dnsprobe.ResolverResult{}
	}
	return hp.Results[len(hp.Results)-1]
}

func firstIP(result dnsprobe.ResolverResult) (string, bool) {
	if len(result.Steps) == 0 {
		return "", false
	}
	last := result.Steps[len(result.Steps)-1]
	if len(last.Classification.IPs) == 0 {
		return "", false
	}
	return last.Classification.IPs[0], true
}

// collectPrivateWarnings surfaces private/loopback DNS answers (from any
// attempted resolver, not just the decisive one) as report warnings.
func collectPrivateWarnings(results []dnsprobe.ResolverResult) []string {
	var warnings []string
	for _, result := range results {
		for _, step := range result.Steps {
			if step.Classification.Status != dnsprobe.StatusPrivate {
				continue
			}
			ip := ""
			if len(step.Classification.IPs) > 0 {
				ip = step.Classification.IPs[0]
			}
			warnings = append(warnings, fmt.Sprintf("%s resolved to private address %s (%s) via resolver %s", step.Name, ip, step.Classification.BlockedBy, result.ResolverName))
		}
	}
	return warnings
}

func collectReferenceCNAMEs(results []report.HostResult) []string {
	seen := map[string]bool{}
	for _, result := range results {
		for _, resolver := range result.Reference {
			for _, step := range resolver.Steps {
				for _, cname := range step.Classification.CNAMEs {
					normalized := strings.ToLower(strings.TrimSuffix(cname, "."))
					if normalized != "" {
						seen[normalized] = true
					}
				}
			}
		}
	}
	var names []string
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func mergeCNAMEProbeResults(hostResults []report.HostResult, cnameProbes []dnsprobe.HostProbeResult, list blocklist.List) {
	probeByHost := map[string]dnsprobe.HostProbeResult{}
	for _, probe := range cnameProbes {
		probeByHost[strings.ToLower(strings.TrimSuffix(probe.Host, "."))] = probe
	}
	for i := range hostResults {
		for _, resolver := range hostResults[i].Reference {
			for _, step := range resolver.Steps {
				for _, cname := range step.Classification.CNAMEs {
					probe, ok := probeByHost[strings.ToLower(strings.TrimSuffix(cname, "."))]
					if !ok {
						continue
					}
					hostResults[i].Primary = append(hostResults[i].Primary, probe.Results...)
				}
			}
		}
		if len(list.Rules) > 0 {
			hostResults[i].Matches, hostResults[i].BlockedNames = matchesForHostAndChainMembers(list, hostResults[i].Host, hostResults[i].Primary, hostResults[i].Reference)
		} else {
			_, hostResults[i].BlockedNames = matchesForHostAndChainMembers(list, hostResults[i].Host, hostResults[i].Primary, hostResults[i].Reference)
		}
	}
}

func matchesForHostAndChainMembers(list blocklist.List, host string, primary []dnsprobe.ResolverResult, reference []dnsprobe.ResolverResult) ([]blocklist.Rule, []string) {
	seen := map[string]blocklist.Rule{}
	blockedNames := map[string]string{}
	recordMatches := func(name string) {
		for _, rule := range list.Match(name) {
			seen[rule.Text] = rule
			normalized := strings.ToLower(strings.TrimSuffix(name, "."))
			blockedNames[normalized] = normalized
		}
	}

	recordMatches(host)
	for _, resolver := range append(primary, reference...) {
		for _, step := range resolver.Steps {
			recordMatches(step.Name)
			for _, cname := range step.Classification.CNAMEs {
				recordMatches(cname)
			}
			if step.Classification.Status == dnsprobe.StatusBlocked || step.Classification.Status == dnsprobe.StatusPrivate {
				normalized := strings.ToLower(strings.TrimSuffix(step.Name, "."))
				blockedNames[normalized] = normalized
			}
		}
	}

	var matches []blocklist.Rule
	for _, rule := range seen {
		matches = append(matches, rule)
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].LineNumber < matches[j].LineNumber })

	var names []string
	for _, name := range blockedNames {
		names = append(names, name)
	}
	sort.Strings(names)
	return matches, names
}

func sortedHosts(hosts map[string]bool) []string {
	out := make([]string, 0, len(hosts))
	for host := range hosts {
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}

func isLocalBlocklistSource(source string) bool {
	return source != "" && !strings.HasPrefix(source, "http://") && !strings.HasPrefix(source, "https://")
}

func isBareHost(target string) bool {
	return !strings.Contains(target, "://")
}

func displayTarget(target string) string {
	return strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")
}

func printHelp(w io.Writer) {
	fmt.Fprintln(w, "Usage: dnscheck [options] <url-or-hostname>")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Options:")
	fmt.Fprintln(w, "  --config PATH   config file path (default dnscheck.config)")
	fmt.Fprintln(w, "  --json          print JSON output")
	fmt.Fprintln(w, "  --color         enable ANSI color")
	fmt.Fprintln(w, "  --no-crawl      skip page crawl and only check the input hostname")
	fmt.Fprintln(w, "  -v              log each DNS query to stderr")
	fmt.Fprintln(w, "  -vv             log each DNS query and result to stderr")
	fmt.Fprintln(w, "  -k              ignore HTTPS certificate validation errors")
}
