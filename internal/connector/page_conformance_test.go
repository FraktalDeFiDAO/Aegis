package connector

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/coppertone/bug-hunter/app/aegis/internal/connector/bridge"
	"github.com/gorilla/websocket"
)

func TestScreenshotRoutesFullPageAndRejectsInvalidEncoding(t *testing.T) {
	commands := make(chan bridge.Command, 3)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		var hello bridge.Hello
		if conn.ReadJSON(&hello) != nil {
			return
		}
		if conn.WriteJSON(bridge.HelloAck{Type: bridge.MsgHelloAck, OK: true, Version: bridge.ProtocolVersion}) != nil {
			return
		}
		for n := 0; n < 3; n++ {
			var command bridge.Command
			if conn.ReadJSON(&command) != nil {
				return
			}
			commands <- command
			screenshot := base64.StdEncoding.EncodeToString([]byte("fixture PNG bytes"))
			if n == 2 {
				screenshot = "not-base64!"
			}
			if err := conn.WriteJSON(map[string]interface{}{"id": command.ID, "type": "result", "success": true, "data": map[string]string{"screenshot": screenshot}}); err != nil {
				return
			}
		}
	}))
	defer server.Close()
	c, err := Connect("ws" + strings.TrimPrefix(server.URL, "http") + "/ws")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p := newPage(c, 42)
	for _, full := range []bool{false, true} {
		bytes, err := p.Screenshot(full, nil)
		if err != nil || string(bytes) != "fixture PNG bytes" {
			t.Fatalf("capture: %q %v", bytes, err)
		}
		command := <-commands
		want := bridge.CmdCaptureVisible
		if full {
			want = bridge.CmdScreenshotFullPage
		}
		if command.Command != want || command.TabID != 42 {
			t.Fatalf("wrong routing: %+v", command)
		}
	}
	if _, err := p.Screenshot(true, nil); err == nil {
		t.Fatal("invalid encoded image returned as successful bytes")
	}
}

func TestUnsupportedDocumentInjectionReturnsError(t *testing.T) {
	p := newPage(&Connector{}, 42)
	if id, err := p.EvalOnNewDocument("alert(1)"); err == nil || id != nil {
		t.Fatalf("script injection falsely succeeded: %+v %v", id, err)
	}
}
