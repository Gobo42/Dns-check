package webscan

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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

func TestVerboseLevelOneColorsFetchSummary(t *testing.T) {
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
		Log: LogOptions{Level: 1, Writer: &log, Color: true},
	}
	cfg := config.Default().Crawl
	cfg.Depth = 1

	_, err := scanner.Scan("https://origin.example/index.html", cfg)
	if err != nil {
		t.Fatal(err)
	}
	out := log.String()
	for _, want := range []string{
		"depth=\x1b[35m1\x1b[0m",
		"crawl fetch depth=\x1b[35m1\x1b[0m url=\x1b[34mhttps://origin.example/index.html\x1b[0m",
		"crawl extracted url=\x1b[34mhttps://origin.example/index.html\x1b[0m links=\x1b[35m1\x1b[0m hosts=\x1b[35m2\x1b[0m",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing colored segment %q:\n%s", want, out)
		}
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

func TestVerboseLevelTwoColorsDiscoveredLinks(t *testing.T) {
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
		Log: LogOptions{Level: 2, Writer: &log, Color: true},
	}
	cfg := config.Default().Crawl
	cfg.Depth = 2

	_, err := scanner.Scan("https://origin.example/index.html", cfg)
	if err != nil {
		t.Fatal(err)
	}
	out := log.String()
	for _, want := range []string{
		"raw=\x1b[34mhttps://next.example/page.html\x1b[0m",
		"resolved=\x1b[34mhttps://next.example/page.html\x1b[0m",
		"host=\x1b[35mnext.example\x1b[0m",
		"document=\x1b[32mtrue\x1b[0m",
		"queued=\x1b[32mtrue\x1b[0m",
		"document=\x1b[31mfalse\x1b[0m",
		"queued=\x1b[31mfalse\x1b[0m",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing colored segment %q:\n%s", want, out)
		}
	}
}

func TestDialContextDialsResolvedIP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			conn.Close()
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	s := Scanner{Resolve: func(ctx context.Context, host string) (string, bool) {
		if host != "fake.invalid" {
			t.Fatalf("resolve called with host = %q, want fake.invalid", host)
		}
		return "127.0.0.1", true
	}}

	conn, err := s.dialContext(context.Background(), "tcp", fmt.Sprintf("fake.invalid:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}

func TestDialContextFallsBackWhenResolveDeclines(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			conn.Close()
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	s := Scanner{Resolve: func(ctx context.Context, host string) (string, bool) {
		return "", false
	}}

	conn, err := s.dialContext(context.Background(), "tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}

func TestDialContextSkipsResolveForIPLiteralAddr(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			conn.Close()
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	called := false
	s := Scanner{Resolve: func(ctx context.Context, host string) (string, bool) {
		called = true
		return "", false
	}}

	conn, err := s.dialContext(context.Background(), "tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if called {
		t.Fatal("Resolve should not be called for an IP-literal address")
	}
}

func TestScanUsesResolveToReachFakeHostname(t *testing.T) {
	var requests int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Write([]byte(`<html></html>`))
	}))
	defer srv.Close()

	port := srv.Listener.Addr().(*net.TCPAddr).Port
	scanner := Scanner{Resolve: func(ctx context.Context, host string) (string, bool) {
		if host == "mysite.invalid" {
			return "127.0.0.1", true
		}
		return "", false
	}}
	cfg := config.Default().Crawl
	cfg.Depth = 1

	result, err := scanner.Scan(fmt.Sprintf("http://mysite.invalid:%d/", port), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want 1 (fetch should have reached the test server via the resolved IP)", requests)
	}
	if !result.Hosts["mysite.invalid"] {
		t.Fatalf("hosts = %#v, want mysite.invalid", result.Hosts)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
