package session

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-rod/rod/lib/proto"
	"github.com/ysmood/gson"
)

func TestApplyCookiesToJar(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "session.json")
	key := []byte("01234567890123456789012345678901")
	mgr := NewSessionManager(path, key)

	lock := sessionLock{
		Cookies: []*proto.NetworkCookieParam{
			{Name: "sid", Value: "abc", Domain: ".example.com", Path: "/", Secure: true},
			{Name: "fallback", Value: "yes", Path: "/"},
		},
	}
	if err := mgr.write(lock); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New failed: %v", err)
	}

	if err := mgr.ApplyCookiesToJar(jar, "https://example.com/path"); err != nil {
		t.Fatalf("ApplyCookiesToJar returned error: %v", err)
	}

	u, _ := url.Parse("https://example.com")
	cookies := jar.Cookies(u)
	if len(cookies) == 0 {
		t.Fatal("expected cookies in jar")
	}
}

func TestApplyCookiesToJar_NilJarAndMissingFile(t *testing.T) {
	t.Parallel()

	key := []byte("01234567890123456789012345678901")
	mgr := NewSessionManager(filepath.Join(t.TempDir(), "missing.json"), key)

	if err := mgr.ApplyCookiesToJar(nil, "https://example.com"); err != nil {
		t.Fatalf("expected nil jar path to return nil, got %v", err)
	}
	if err := mgr.ApplyCookiesToJar(&noopJar{}, "https://example.com"); err == nil {
		t.Fatal("expected read error for missing session file")
	}
}

func TestStorageScriptAndMapFromGson(t *testing.T) {
	t.Parallel()

	script, err := storageScript("localStorage", map[string]string{"token": "abc"})
	if err != nil {
		t.Fatalf("storageScript returned error: %v", err)
	}
	if !strings.Contains(script, "localStorage") || !strings.Contains(script, "token") {
		t.Fatalf("unexpected storage script: %q", script)
	}

	m := mapFromGson(gson.New(map[string]interface{}{"a": "b", "n": 1}))
	if m["a"] != "b" {
		t.Fatalf("unexpected gson map conversion: %+v", m)
	}
}

type noopJar struct{}

func (n *noopJar) SetCookies(_ *url.URL, _ []*http.Cookie) {}
func (n *noopJar) Cookies(_ *url.URL) []*http.Cookie      { return nil }
