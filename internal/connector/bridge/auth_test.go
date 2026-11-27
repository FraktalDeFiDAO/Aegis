package bridge

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestWebSocketHelloRequiresTokenForBothClientRoles(t *testing.T) {
	srv := NewServer(ServerConfig{Token: "test-token", RuntimePath: filepath.Join(t.TempDir(), "runtime.json")})
	addr, err := srv.StartNonBlocking(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Stop() })

	for _, test := range []struct {
		name   string
		client string
		token  string
		wantOK bool
	}{
		{name: "controller missing token", client: "aegis"},
		{name: "controller wrong token", client: "aegis", token: "wrong"},
		{name: "controller authenticated", client: "aegis", token: "test-token", wantOK: true},
		{name: "extension missing token", client: "extension"},
		{name: "extension wrong token", client: "extension", token: "wrong"},
		{name: "extension authenticated", client: "extension", token: "test-token", wantOK: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn, _, err := websocket.DefaultDialer.Dial("ws://"+addr+"/ws?client="+test.client, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			if err := conn.WriteJSON(Hello{Type: MsgHello, Client: test.client, Version: ProtocolVersion, Token: test.token}); err != nil {
				t.Fatal(err)
			}
			var ack HelloAck
			if err := conn.ReadJSON(&ack); err != nil {
				t.Fatal(err)
			}
			if ack.OK != test.wantOK {
				t.Fatalf("hello ok=%v, want %v (error: %+v)", ack.OK, test.wantOK, ack.Error)
			}
			if !test.wantOK && (ack.Error == nil || ack.Error.Code != ErrCodeDenied) {
				t.Fatalf("unauthenticated hello error=%+v, want %s", ack.Error, ErrCodeDenied)
			}
		})
	}
}

func TestUnauthenticatedConnectionCannotReplaceController(t *testing.T) {
	srv := NewServer(ServerConfig{Token: "test-token", RuntimePath: filepath.Join(t.TempDir(), "runtime.json")})
	addr, err := srv.StartNonBlocking(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Stop() })
	url := "ws://" + addr + "/ws?client=aegis"

	authenticated, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer authenticated.Close()
	if err := authenticated.WriteJSON(Hello{Type: MsgHello, Client: "aegis", Version: ProtocolVersion, Token: "test-token"}); err != nil {
		t.Fatal(err)
	}
	var ack HelloAck
	if err := authenticated.ReadJSON(&ack); err != nil || !ack.OK {
		t.Fatalf("authenticated hello: %+v, %v", ack, err)
	}

	attacker, _, err := websocket.DefaultDialer.Dial(url, http.Header{"Origin": []string{"http://127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer attacker.Close()
	if err := attacker.WriteJSON(Hello{Type: MsgHello, Client: "aegis", Version: ProtocolVersion}); err != nil {
		t.Fatal(err)
	}
	if err := attacker.ReadJSON(&ack); err != nil {
		t.Fatal(err)
	}
	if ack.OK {
		t.Fatal("unauthenticated local-origin connection was accepted")
	}

	if err := authenticated.WriteJSON(Ping{Type: MsgPing, ID: "still-connected"}); err != nil {
		t.Fatal(err)
	}
	var pong Pong
	_ = authenticated.SetReadDeadline(time.Now().Add(2 * time.Second))
	if err := authenticated.ReadJSON(&pong); err != nil {
		t.Fatal(err)
	}
	if pong.ID != "still-connected" {
		t.Fatalf("authenticated controller was replaced: %+v", pong)
	}
}

func TestInfoRequiresBearerToken(t *testing.T) {
	srv := NewServer(ServerConfig{Token: "test-token", RuntimePath: filepath.Join(t.TempDir(), "runtime.json")})
	addr, err := srv.StartNonBlocking(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Stop() })

	for _, test := range []struct {
		name  string
		token string
		want  int
	}{
		{name: "missing", want: http.StatusUnauthorized},
		{name: "wrong", token: "wrong", want: http.StatusUnauthorized},
		{name: "valid", token: "test-token", want: http.StatusOK},
	} {
		t.Run(test.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "http://"+addr+"/info", nil)
			if err != nil {
				t.Fatal(err)
			}
			if test.token != "" {
				req.Header.Set("Authorization", "Bearer "+test.token)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != test.want {
				t.Fatalf("status=%d, want %d", resp.StatusCode, test.want)
			}
		})
	}
	resp, err := http.Get("http://" + addr + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("non-sensitive discovery health status=%d", resp.StatusCode)
	}
}

func TestDiscoveryLockPreventsConcurrentCredentialOverwrite(t *testing.T) {
	runtimePath := filepath.Join(t.TempDir(), "runtime.json")
	first := NewServer(ServerConfig{Token: "first", RuntimePath: runtimePath})
	if _, err := first.StartNonBlocking(context.Background()); err != nil {
		t.Fatal(err)
	}
	second := NewServer(ServerConfig{Token: "second", RuntimePath: runtimePath})
	if _, err := second.StartNonBlocking(context.Background()); err == nil {
		_ = second.Stop()
		t.Fatal("second bridge overwrote the active discovery credential")
	}
	if err := first.Stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := second.StartNonBlocking(context.Background()); err != nil {
		t.Fatalf("bridge did not start after lock release: %v", err)
	}
	_ = second.Stop()
}

func TestStaleDiscoveryLockIsReclaimed(t *testing.T) {
	runtimePath := filepath.Join(t.TempDir(), "runtime.json")
	lockPath := runtimePath + ".lock"
	if err := os.MkdirAll(lockPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lockPath, "pid"), []byte("99999999"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(ServerConfig{Token: "test", RuntimePath: runtimePath})
	if _, err := srv.StartNonBlocking(context.Background()); err != nil {
		t.Fatalf("stale lock was not reclaimed: %v", err)
	}
	_ = srv.Stop()
}

func TestGeneratedTokenRotatesAcrossBridgeRestart(t *testing.T) {
	runtimePath := filepath.Join(t.TempDir(), "runtime.json")
	start := func() (*Server, string, struct{ Addr, Token string }) {
		t.Helper()
		srv := NewServer(ServerConfig{RuntimePath: runtimePath})
		addr, err := srv.StartNonBlocking(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(runtimePath)
		if err != nil {
			t.Fatal(err)
		}
		var state struct{ Addr, Token string }
		if err := json.Unmarshal(raw, &state); err != nil {
			t.Fatal(err)
		}
		if state.Addr != net.JoinHostPort(host, port) || state.Token == "" {
			t.Fatalf("runtime state does not contain private discovery credentials: %+v", state)
		}
		return srv, addr, state
	}

	first, _, firstState := start()
	if err := first.Stop(); err != nil {
		t.Fatal(err)
	}
	second, _, secondState := start()
	defer second.Stop()
	if firstState.Token == secondState.Token {
		t.Fatal("bridge restart reused its authentication token")
	}
}
