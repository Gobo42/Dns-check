package webscan

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	"dnscheck/internal/config"
)

func TestDepthZeroSkipsFetchAndReturnsInputHost(t *testing.T) {
	called := false
	scanner := Scanner{Client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		called = true
		return nil, nil
	})}}
	cfg := config.Default().Crawl
	cfg.Depth = 0

	result, err := scanner.Scan("https://example.com/path", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("depth 0 should not fetch")
	}
	if !result.Hosts["example.com"] {
		t.Fatalf("hosts = %#v, want example.com", result.Hosts)
	}
}

func TestDepthOneExtractsHostsWithoutFetchingLinkedDocuments(t *testing.T) {
	var pageFetches int
	scanner := Scanner{Client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		pageFetches++
		return &http.Response{
			StatusCode: 200,
			Status:     "200 OK",
			Header:     make(http.Header),
			Body: io.NopCloser(strings.NewReader(`<html><head>
<script src="https://scripts.example.net/app.js"></script>
<link rel="stylesheet" href="//cdn.example.net/app.css">
<link rel="preconnect" href="https://preconnect.example.org">
</head><body>
<img src="https://images.example.net/logo.png">
<a href="https://linked.example.net/page.html">linked</a>
</body></html>`)),
		}, nil
	})}}
	cfg := config.Default().Crawl
	cfg.Depth = 1

	result, err := scanner.Scan("https://origin.example/index.html", cfg)
	if err != nil {
		t.Fatal(err)
	}

	for _, host := range []string{"origin.example", "scripts.example.net", "cdn.example.net", "preconnect.example.org", "images.example.net", "linked.example.net"} {
		if !result.Hosts[host] {
			t.Fatalf("missing host %s in %#v", host, result.Hosts)
		}
	}
	if pageFetches != 1 {
		t.Fatalf("page fetches = %d, want 1", pageFetches)
	}
}

func TestDepthTwoFetchesOnlyDocumentLikeURLs(t *testing.T) {
	fetched := map[string]int{}
	scanner := Scanner{Client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		fetched[req.URL.String()]++
		body := `<a href="https://next.example/page.php">page</a><img src="https://media.example/pixel.png">`
		return &http.Response{
			StatusCode: 200,
			Status:     "200 OK",
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
		}, nil
	})}}
	cfg := config.Default().Crawl
	cfg.Depth = 2

	result, err := scanner.Scan("https://origin.example/index.html", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if fetched["https://origin.example/index.html"] != 1 {
		t.Fatalf("start fetches = %d, want 1", fetched["https://origin.example/index.html"])
	}
	if fetched["https://next.example/page.php"] != 1 {
		t.Fatalf("document fetches = %d, want 1", fetched["https://next.example/page.php"])
	}
	if fetched["https://media.example/pixel.png"] != 0 {
		t.Fatalf("media fetches = %d, want 0", fetched["https://media.example/pixel.png"])
	}
	if !result.Hosts["media.example"] {
		t.Fatal("expected media host to be DNS-checked even when body is not fetched")
	}
}

func TestVerboseLevelOneLogsFetchSummary(t *testing.T) {
	var log bytes.Buffer
	scanner := Scanner{
		Client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: 200,
				Status:     "200 OK",
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`<script src="https://cdn.example/app.js"></script>`)),
			}, nil
		})},
		Log: LogOptions{Level: 1, Writer: &log},
	}
	cfg := config.Default().Crawl
	cfg.Depth = 1

	_, err := scanner.Scan("https://origin.example/index.html", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(log.String(), "crawl fetch depth=1 url=https://origin.example/index.html") {
		t.Fatalf("missing fetch log:\n%s", log.String())
	}
	if !strings.Contains(log.String(), "crawl extracted url=https://origin.example/index.html links=1 hosts=2") {
		t.Fatalf("missing extraction summary:\n%s", log.String())
	}
	if strings.Contains(log.String(), "crawl discovered") {
		t.Fatalf("level 1 should not include per-link detail:\n%s", log.String())
	}
}

func TestVerboseLevelTwoLogsDiscoveredLinks(t *testing.T) {
	var log bytes.Buffer
	scanner := Scanner{
		Client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: 200,
				Status:     "200 OK",
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`<a href="https://next.example/page.html">next</a><img src="https://media.example/pixel.png">`)),
			}, nil
		})},
		Log: LogOptions{Level: 2, Writer: &log},
	}
	cfg := config.Default().Crawl
	cfg.Depth = 2

	_, err := scanner.Scan("https://origin.example/index.html", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(log.String(), "crawl discovered raw=https://next.example/page.html resolved=https://next.example/page.html host=next.example document=true queued=true") {
		t.Fatalf("missing document discovery log:\n%s", log.String())
	}
	if !strings.Contains(log.String(), "crawl discovered raw=https://media.example/pixel.png resolved=https://media.example/pixel.png host=media.example document=false queued=false") {
		t.Fatalf("missing media discovery log:\n%s", log.String())
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
