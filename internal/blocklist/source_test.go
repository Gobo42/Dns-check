package blocklist

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSourceFromLocalFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocked.txt")
	if err := os.WriteFile(path, []byte("*.nr-data.net\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadSource(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Local || loaded.LocalPath != path {
		t.Fatalf("loaded = %#v", loaded)
	}
	if got := loaded.List.Match("bam.nr-data.net"); len(got) != 1 {
		t.Fatalf("matches = %#v, want one", got)
	}
}

func TestLoadSourceExpandsHomeDirectory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, "blocked.txt")
	if err := os.WriteFile(path, []byte("*.home-example.test\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadSource("~/blocked.txt", false)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.LocalPath != path {
		t.Fatalf("local path = %q, want %q", loaded.LocalPath, path)
	}
	if got := loaded.List.Match("cdn.home-example.test"); len(got) != 1 {
		t.Fatalf("matches = %#v, want one", got)
	}
}

func TestNewHTTPClientHonorsInsecureTLSSetting(t *testing.T) {
	secure := newHTTPClient(false)
	secureTransport := secure.Transport.(*http.Transport)
	if secureTransport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("expected normal TLS verification by default")
	}

	insecure := newHTTPClient(true)
	insecureTransport := insecure.Transport.(*http.Transport)
	if !insecureTransport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("expected insecure TLS verification override")
	}
}
