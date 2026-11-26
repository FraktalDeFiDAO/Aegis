package main

import (
	"os"
	"path/filepath"
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
