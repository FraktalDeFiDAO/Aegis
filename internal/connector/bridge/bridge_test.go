package bridge

import (
	"encoding/json"
	"testing"
	"time"
)

func TestParseMessage_Command(t *testing.T) {
	cmd := NewCommand(CmdNavigate, json.RawMessage(`{"url":"https://example.com"}`), 0)
	data, err := json.Marshal(cmd)
	if err != nil {
		t.Fatalf("marshal command: %v", err)
	}

	msg, err := ParseMessage(data)
	if err != nil {
		t.Fatalf("parse message: %v", err)
	}

	parsed, ok := msg.(*Command)
	if !ok {
		t.Fatalf("expected *Command, got %T", msg)
	}

	if parsed.Command != CmdNavigate {
		t.Errorf("expected command %q, got %q", CmdNavigate, parsed.Command)
	}
	if parsed.Type != MsgCommand {
		t.Errorf("expected type %q, got %q", MsgCommand, parsed.Type)
	}
	if parsed.ID == "" {
		t.Error("expected non-empty ID")
	}
	if parsed.Timestamp == 0 {
		t.Error("expected non-zero timestamp")
	}
}

func TestParseMessage_Result(t *testing.T) {
	result := NewResult("test-id", true, json.RawMessage(`{"title":"Example"}`), "")
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}

	msg, err := ParseMessage(data)
	if err != nil {
		t.Fatalf("parse message: %v", err)
	}

	parsed, ok := msg.(*Result)
	if !ok {
		t.Fatalf("expected *Result, got %T", msg)
	}

	if parsed.ID != "test-id" {
		t.Errorf("expected ID %q, got %q", "test-id", parsed.ID)
	}
	if !parsed.Success {
		t.Error("expected success=true")
	}
	if parsed.Error != "" {
		t.Errorf("expected empty error, got %q", parsed.Error)
	}
}

func TestParseMessage_ResultWithError(t *testing.T) {
	result := NewResult("test-id", false, nil, "element not found")
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}

	msg, err := ParseMessage(data)
	if err != nil {
		t.Fatalf("parse message: %v", err)
	}

	parsed, ok := msg.(*Result)
	if !ok {
		t.Fatalf("expected *Result, got %T", msg)
	}

	if parsed.Success {
		t.Error("expected success=false")
	}
	if parsed.Error != "element not found" {
		t.Errorf("expected error %q, got %q", "element not found", parsed.Error)
	}
}

func TestParseMessage_Event(t *testing.T) {
	evt := NewEvent(EventTabCreated, json.RawMessage(`{"tabId":123}`))
	data, err := json.Marshal(evt)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}

	msg, err := ParseMessage(data)
	if err != nil {
		t.Fatalf("parse message: %v", err)
	}

	parsed, ok := msg.(*Event)
	if !ok {
		t.Fatalf("expected *Event, got %T", msg)
	}

	if parsed.Event != EventTabCreated {
		t.Errorf("expected event %q, got %q", EventTabCreated, parsed.Event)
	}
}

func TestParseMessage_PingPong(t *testing.T) {
	ping := &Ping{
		ID:        "ping-1",
		Type:      MsgPing,
		Timestamp: nowMs(),
	}
	data, err := json.Marshal(ping)
	if err != nil {
		t.Fatalf("marshal ping: %v", err)
	}

	msg, err := ParseMessage(data)
	if err != nil {
		t.Fatalf("parse message: %v", err)
	}

	parsed, ok := msg.(*Ping)
	if !ok {
		t.Fatalf("expected *Ping, got %T", msg)
	}

	if parsed.Type != MsgPing {
		t.Errorf("expected type %q, got %q", MsgPing, parsed.Type)
	}
}

func TestParseMessage_InvalidJSON(t *testing.T) {
	_, err := ParseMessage([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseMessage_UnknownType(t *testing.T) {
	data := []byte(`{"id":"test","type":"unknown","timestamp":123}`)
	msg, err := ParseMessage(data)
	if err != nil {
		t.Fatalf("parse message: %v", err)
	}

	// Should return the raw envelope
	envelope, ok := msg.(*Message)
	if !ok {
		t.Fatalf("expected *Message for unknown type, got %T", msg)
	}
	if envelope.Type != "unknown" {
		t.Errorf("expected type %q, got %q", "unknown", envelope.Type)
	}
}

func TestNewCommand_Fields(t *testing.T) {
	params := json.RawMessage(`{"key":"value"}`)
	cmd := NewCommand(CmdClick, params, 42)

	if cmd.ID == "" {
		t.Error("expected non-empty ID")
	}
	if cmd.Type != MsgCommand {
		t.Errorf("expected type %q, got %q", MsgCommand, cmd.Type)
	}
	if cmd.Command != CmdClick {
		t.Errorf("expected command %q, got %q", CmdClick, cmd.Command)
	}
	if cmd.TabID != 42 {
		t.Errorf("expected tabID 42, got %d", cmd.TabID)
	}
	if string(cmd.Params) != `{"key":"value"}` {
		t.Errorf("expected params %q, got %q", `{"key":"value"}`, string(cmd.Params))
	}
	if cmd.Timestamp == 0 {
		t.Error("expected non-zero timestamp")
	}
}

func TestNewResult_Fields(t *testing.T) {
	data := json.RawMessage(`{"text":"hello"}`)
	result := NewResult("cmd-123", true, data, "")

	if result.ID != "cmd-123" {
		t.Errorf("expected ID %q, got %q", "cmd-123", result.ID)
	}
	if result.Type != MsgResult {
		t.Errorf("expected type %q, got %q", MsgResult, result.Type)
	}
	if !result.Success {
		t.Error("expected success=true")
	}
	if string(result.Data) != `{"text":"hello"}` {
		t.Errorf("expected data %q, got %q", `{"text":"hello"}`, string(result.Data))
	}
	if result.Error != "" {
		t.Errorf("expected empty error, got %q", result.Error)
	}
}

func TestCommandConstants(t *testing.T) {
	// Verify all command constants are unique
	commands := []string{
		CmdNavigate, CmdGoBack, CmdGoForward, CmdReload,
		CmdGetCurrentURL, CmdGetTitle,
		CmdListTabs, CmdNewTab, CmdCloseTab, CmdSwitchTab, CmdGetTabInfo,
		CmdQuerySelector, CmdQuerySelectorAll,
		CmdGetElementText, CmdGetElementAttr, CmdGetElementHTML,
		CmdClick, CmdDoubleClick, CmdRightClick, CmdHover,
		CmdType, CmdFill, CmdClear, CmdPress, CmdSelect,
		CmdScroll, CmdScrollIntoView,
		CmdWaitForSelector, CmdWaitForNav, CmdWaitForLoad,
		CmdEvaluate, CmdEvaluateAll,
		CmdScreenshot, CmdScreenshotElem, CmdCaptureVisible,
		CmdGetCookies, CmdSetCookie, CmdDeleteCookie, CmdClearCookies,
		CmdGetLocalStorage, CmdSetLocalStorage,
		CmdGetSessionStore, CmdSetSessionStore,
		CmdSwitchFrame, CmdSwitchMain,
		CmdAcceptDialog, CmdDismissDialog,
		CmdExtractData,
	}

	seen := make(map[string]bool)
	for _, cmd := range commands {
		if cmd == "" {
			t.Error("found empty command constant")
			continue
		}
		if seen[cmd] {
			t.Errorf("duplicate command constant: %q", cmd)
		}
		seen[cmd] = true
	}
}

func TestSessionManager_UpdateCookies(t *testing.T) {
	sm := NewSessionManager()

	cookies := []*CookieData{
		{Name: "session", Value: "abc123", Domain: ".example.com", Path: "/"},
		{Name: "pref", Value: "dark", Domain: ".example.com", Path: "/"},
	}

	sm.UpdateCookies(1, cookies)

	session := sm.GetSession(1)
	if len(session.Cookies) != 2 {
		t.Fatalf("expected 2 cookies, got %d", len(session.Cookies))
	}
	if session.Cookies[0].Name != "session" {
		t.Errorf("expected cookie name %q, got %q", "session", session.Cookies[0].Name)
	}
	if session.Cookies[0].Value != "abc123" {
		t.Errorf("expected cookie value %q, got %q", "abc123", session.Cookies[0].Value)
	}
}

func TestSessionManager_MergeCookies(t *testing.T) {
	sm := NewSessionManager()

	// Initial cookies
	sm.UpdateCookies(1, []*CookieData{
		{Name: "session", Value: "old", Domain: ".example.com", Path: "/"},
		{Name: "old_cookie", Value: "kept", Domain: ".example.com", Path: "/"},
	})

	// Merge new cookies (overwrite session, add new_cookie)
	sm.MergeCookies(1, []*CookieData{
		{Name: "session", Value: "new", Domain: ".example.com", Path: "/"},      // overwrite
		{Name: "new_cookie", Value: "added", Domain: ".example.com", Path: "/"}, // add
	})

	session := sm.GetSession(1)
	// Merge adds/updates, doesn't remove — old_cookie stays
	if len(session.Cookies) != 3 {
		t.Fatalf("expected 3 cookies after merge (old_cookie retained), got %d", len(session.Cookies))
	}

	// Check overwritten cookie
	for _, c := range session.Cookies {
		if c.Name == "session" {
			if c.Value != "new" {
				t.Errorf("expected session cookie value %q, got %q", "new", c.Value)
			}
			return
		}
	}
	t.Error("session cookie not found after merge")
}

func TestSessionManager_ExportImport(t *testing.T) {
	sm := NewSessionManager()

	// Add some data
	sm.UpdateCookies(1, []*CookieData{
		{Name: "test", Value: "value", Domain: ".example.com", Path: "/"},
	})
	sm.UpdateLocalStorage(1, map[string]string{"key": "value"})
	sm.UpdateSessionStorage(1, map[string]string{"skey": "svalue"})

	// Export
	data, err := sm.ExportAll()
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	// Import into new manager
	sm2 := NewSessionManager()
	if err := sm2.ImportAll(data); err != nil {
		t.Fatalf("import: %v", err)
	}

	// Verify
	session := sm2.GetSession(1)
	if len(session.Cookies) != 1 {
		t.Errorf("expected 1 cookie, got %d", len(session.Cookies))
	}
	if session.LocalStorage["key"] != "value" {
		t.Errorf("expected localStorage key=value, got %q", session.LocalStorage["key"])
	}
	if session.SessionStorage["skey"] != "svalue" {
		t.Errorf("expected sessionStorage skey=svalue, got %q", session.SessionStorage["skey"])
	}
}

func TestSessionManager_RemoveSession(t *testing.T) {
	sm := NewSessionManager()

	sm.UpdateCookies(1, []*CookieData{
		{Name: "test", Value: "value", Domain: ".example.com", Path: "/"},
	})

	if sm.TabCount() != 1 {
		t.Fatalf("expected 1 tab, got %d", sm.TabCount())
	}

	sm.RemoveSession(1)

	if sm.TabCount() != 0 {
		t.Errorf("expected 0 tabs after remove, got %d", sm.TabCount())
	}
}

func TestSessionManager_TabCount(t *testing.T) {
	sm := NewSessionManager()

	if sm.TabCount() != 0 {
		t.Errorf("expected 0 tabs initially, got %d", sm.TabCount())
	}

	sm.UpdateCookies(1, []*CookieData{})
	sm.UpdateCookies(2, []*CookieData{})
	sm.UpdateCookies(3, []*CookieData{})

	if sm.TabCount() != 3 {
		t.Errorf("expected 3 tabs, got %d", sm.TabCount())
	}
}

func TestCommandConstants_Unique(t *testing.T) {
	commands := map[string]bool{}
	constants := []string{
		CmdNavigate, CmdGoBack, CmdGoForward, CmdReload,
		CmdGetCurrentURL, CmdGetTitle,
		CmdListTabs, CmdNewTab, CmdCloseTab, CmdSwitchTab, CmdGetTabInfo,
		CmdClick, CmdDoubleClick, CmdRightClick, CmdHover,
		CmdType, CmdFill, CmdClear, CmdPress, CmdSelect,
	}

	for _, c := range constants {
		if commands[c] {
			t.Errorf("duplicate command constant: %s", c)
		}
		commands[c] = true
	}
}

func TestNowMs(t *testing.T) {
	before := time.Now().UnixMilli()
	ms := nowMs()
	after := time.Now().UnixMilli()

	if ms < before || ms > after {
		t.Errorf("nowMs() = %d, expected between %d and %d", ms, before, after)
	}
}

func TestGenerateID_Unique(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := generateID()
		if ids[id] {
			t.Errorf("duplicate ID generated: %s", id)
		}
		ids[id] = true
	}
}
