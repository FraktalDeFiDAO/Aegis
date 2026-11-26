package connector

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/coppertone/bug-hunter/app/aegis/internal/connector/bridge"
)

func TestConnectRejectsFailedAuthentication(t *testing.T) {
	srv := bridge.NewServer(bridge.ServerConfig{Token: "test-token", RuntimePath: filepath.Join(t.TempDir(), "runtime.json")})
	addr, err := srv.StartNonBlocking(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Stop() })

	url := "ws://" + addr + "/ws?client=aegis"
	conn, err := Connect(url)
	if err == nil {
		conn.Close()
		t.Fatal("connector accepted a failed hello authentication response")
	}
	authenticated, err := Connect(url, WithToken("test-token"))
	if err != nil {
		t.Fatalf("authenticated connector: %v", err)
	}
	if err := authenticated.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNewPage(t *testing.T) {
	c := &Connector{
		pages: make(map[int]*Page),
	}
	page := newPage(c, 123)

	if page.tabID != 123 {
		t.Errorf("expected tabID 123, got %d", page.tabID)
	}
	if page.connector != c {
		t.Error("expected connector reference")
	}
}

func TestPageSetInfo(t *testing.T) {
	c := &Connector{pages: make(map[int]*Page)}
	page := newPage(c, 1)

	page.setInfo("https://example.com", "Example")
	if page.url != "https://example.com" {
		t.Errorf("expected url %q, got %q", "https://example.com", page.url)
	}
	if page.title != "Example" {
		t.Errorf("expected title %q, got %q", "Example", page.title)
	}
}

func TestElement(t *testing.T) {
	c := &Connector{pages: make(map[int]*Page)}
	page := newPage(c, 1)
	elem := newPage(c, 1)
	_ = elem

	el := newElement(page, "#test")
	if el.selector != "#test" {
		t.Errorf("expected selector %q, got %q", "#test", el.selector)
	}
	if el.page != page {
		t.Error("expected page reference")
	}
}

func TestConnectorPagesEmpty(t *testing.T) {
	c := &Connector{
		pages:   make(map[int]*Page),
		pending: make(map[string]*pendingCall),
	}
	// Pages would fail without a bridge connection
	_, err := c.Pages()
	if err == nil {
		t.Fatal("expected error without bridge connection")
	}
}

func TestSessionBridge(t *testing.T) {
	c := &Connector{
		pages: make(map[int]*Page),
	}
	sb := NewSessionBridge(c)
	if sb == nil {
		t.Fatal("expected non-nil SessionBridge")
	}
	if sb.connector != c {
		t.Error("expected connector reference")
	}
	if sb.bridge == nil {
		t.Error("expected non-nil bridge SessionManager")
	}
}

func TestDecodeResult(t *testing.T) {
	data := json.RawMessage(`{"text":"hello","count":42}`)
	result := &bridge.Result{
		ID:      "test",
		Type:    bridge.MsgResult,
		Success: true,
		Data:    data,
	}

	var v struct {
		Text  string `json:"text"`
		Count int    `json:"count"`
	}
	if err := decodeResult(result, &v); err != nil {
		t.Fatalf("decodeResult: %v", err)
	}
	if v.Text != "hello" {
		t.Errorf("expected text %q, got %q", "hello", v.Text)
	}
	if v.Count != 42 {
		t.Errorf("expected count 42, got %d", v.Count)
	}
}

func TestDecodeResultNilData(t *testing.T) {
	result := &bridge.Result{
		ID:      "test",
		Type:    bridge.MsgResult,
		Success: true,
		Data:    nil,
	}

	var v struct {
		Text string `json:"text"`
	}
	if err := decodeResult(result, &v); err != nil {
		t.Fatalf("decodeResult with nil data: %v", err)
	}
}

func TestConnectorConfig(t *testing.T) {
	cfg := Config{
		BridgeURL: "ws://127.0.0.1:9999/ws",
	}
	if cfg.BridgeURL != "ws://127.0.0.1:9999/ws" {
		t.Errorf("unexpected BridgeURL: %s", cfg.BridgeURL)
	}
}

func TestSessionData(t *testing.T) {
	sd := SessionData{
		Cookies: map[int][]*bridge.CookieData{
			1: {{Name: "test", Value: "val", Domain: ".example.com", Path: "/"}},
		},
		Local: map[int]map[string]string{
			1: {"key": "value"},
		},
		Session: map[int]map[string]string{
			1: {"skey": "svalue"},
		},
	}

	data, err := json.Marshal(sd)
	if err != nil {
		t.Fatalf("marshal SessionData: %v", err)
	}

	var decoded SessionData
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal SessionData: %v", err)
	}

	if len(decoded.Cookies[1]) != 1 {
		t.Errorf("expected 1 cookie, got %d", len(decoded.Cookies[1]))
	}
	if decoded.Local[1]["key"] != "value" {
		t.Errorf("expected local storage key=value, got %q", decoded.Local[1]["key"])
	}
}
