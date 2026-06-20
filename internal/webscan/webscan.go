package webscan

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"

	"dnscheck/internal/config"
)

type Scanner struct {
	Client *http.Client
	Log    LogOptions
}

type LogOptions struct {
	Level  int
	Writer io.Writer
}

type Result struct {
	Hosts    map[string]bool `json:"hosts"`
	Warnings []string        `json:"warnings,omitempty"`
}

func New(insecureSkipTLSVerify bool) Scanner {
	return Scanner{
		Client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipTLSVerify},
			},
		},
	}
}

func (s Scanner) Scan(rawURL string, cfg config.CrawlConfig) (Result, error) {
	if s.Client == nil {
		s = New(cfg.InsecureSkipTLSVerify)
	}
	if s.Log.Level > 0 && s.Log.Writer == nil {
		s.Log.Writer = os.Stderr
	}
	start, err := url.Parse(rawURL)
	if err != nil {
		return Result{}, err
	}
	result := Result{Hosts: map[string]bool{}}
	if start.Hostname() != "" {
		result.Hosts[strings.ToLower(start.Hostname())] = true
	}
	if cfg.Depth == 0 {
		return result, nil
	}
	if cfg.MaxPages <= 0 {
		cfg.MaxPages = 1
	}

	visited := map[string]bool{}
	queue := []string{start.String()}
	for depth := 1; depth <= cfg.Depth && len(queue) > 0 && len(visited) < cfg.MaxPages; depth++ {
		currentBatch := queue
		queue = nil
		for _, item := range currentBatch {
			if visited[item] || len(visited) >= cfg.MaxPages {
				continue
			}
			visited[item] = true
			s.logf(1, "crawl fetch depth=%d url=%s\n", depth, item)
			body, err := s.fetch(item, cfg.UserAgent)
			if err != nil {
				result.Warnings = append(result.Warnings, err.Error())
				continue
			}
			links := extractURLs(body)
			base, _ := url.Parse(item)
			for _, link := range links {
				resolved := resolveURL(base, link)
				if resolved == nil || resolved.Hostname() == "" {
					s.logf(2, "crawl discovered raw=%s resolved= host= document=false queued=false\n", link)
					continue
				}
				host := strings.ToLower(resolved.Hostname())
				result.Hosts[host] = true
				document := isDocumentLike(resolved, cfg.DocumentExtensions)
				queued := depth < cfg.Depth && document
				s.logf(2, "crawl discovered raw=%s resolved=%s host=%s document=%t queued=%t\n", link, resolved.String(), host, document, queued)
				if queued {
					queue = append(queue, resolved.String())
				}
			}
			s.logf(1, "crawl extracted url=%s links=%d hosts=%d\n", item, len(links), len(result.Hosts))
		}
	}
	return result, nil
}

func (s Scanner) logf(level int, format string, args ...any) {
	if s.Log.Level < level || s.Log.Writer == nil {
		return
	}
	fmt.Fprintf(s.Log.Writer, format, args...)
}

func (s Scanner) fetch(rawURL, userAgent string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("fetch %s: %s", rawURL, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

var urlAttrRe = regexp.MustCompile(`(?i)(?:href|src)=["']([^"']+)["']|url\(([^)]+)\)`)

func extractURLs(body string) []string {
	var out []string
	for _, match := range urlAttrRe.FindAllStringSubmatch(body, -1) {
		value := match[1]
		if value == "" {
			value = match[2]
		}
		value = strings.Trim(value, ` "'`)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func resolveURL(base *url.URL, raw string) *url.URL {
	if strings.HasPrefix(raw, "//") {
		raw = base.Scheme + ":" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	return base.ResolveReference(u)
}

func isDocumentLike(u *url.URL, exts []string) bool {
	ext := strings.ToLower(path.Ext(u.Path))
	for _, allowed := range exts {
		if ext == allowed {
			return true
		}
	}
	return false
}
