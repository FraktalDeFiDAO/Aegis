package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoveryUsesOnlyValidLoopbackRuntimeAddresses(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	path := defaultRuntimeStatePath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ state, want string }{
		{`{"addr":"127.0.0.1:41234"}`, "ws://127.0.0.1:41234/ws?client=aegis"},
		{`{"addr":"[::1]:41234"}`, "ws://[::1]:41234/ws?client=aegis"},
		{`{"addr":"192.0.2.1:1234"}`, "ws://127.0.0.1:9876/ws?client=aegis"},
		{`{"addr":"localhost:1234"}`, "ws://127.0.0.1:9876/ws?client=aegis"},
		{`{"addr":"127.0.0.1:99999"}`, "ws://127.0.0.1:9876/ws?client=aegis"},
		{`invalid`, "ws://127.0.0.1:9876/ws?client=aegis"},
	} {
		if err := os.WriteFile(path, []byte(test.state), 0600); err != nil {
			t.Fatal(err)
		}
		if got := discoveredBridgeURL(); got != test.want {
			t.Errorf("state %s: got %s, want %s", test.state, got, test.want)
		}
	}
}

func TestDiscoveredBridgeTokenRequiresMatchingURLAndPrivateState(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	path := defaultRuntimeStatePath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	state := `{"addr":"127.0.0.1:41234","token":"private-test-token"}`
	if err := os.WriteFile(path, []byte(state), 0600); err != nil {
		t.Fatal(err)
	}
	matching := "ws://127.0.0.1:41234/ws?client=aegis"
	if got := discoveredBridgeToken(matching); got != "private-test-token" {
		t.Fatalf("matching discovery token = %q", got)
	}
	if got := discoveredBridgeToken("ws://127.0.0.1:41234/ws"); got != "private-test-token" {
		t.Fatal("equivalent controller URL without an explicit client query did not inherit the token")
	}
	if got := discoveredBridgeToken("ws://127.0.0.1:41235/ws?client=aegis"); got != "" {
		t.Fatal("token was reused for a different bridge")
	}
	if strings.Contains(discoveredBridgeURL(), "private-test-token") {
		t.Fatal("credential leaked into WebSocket URL")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if got := discoveredBridgeToken(matching); got != "" {
		t.Fatal("accepted credential from group/world-readable state")
	}
}
