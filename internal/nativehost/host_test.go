package nativehost

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/coppertone/bug-hunter/app/aegis/internal/connector/bridge"
)

func TestFrames(t *testing.T) {
	var b bytes.Buffer
	if err := writeMessage(&b, Request{Type: "start", Port: 9876}); err != nil {
		t.Fatal(err)
	}
	var req Request
	if err := readMessage(&b, &req); err != nil || req.Port != 9876 {
		t.Fatalf("round trip: %+v %v", req, err)
	}
	for _, size := range []uint32{0, maxMessage + 1} {
		b.Reset()
		_ = binary.Write(&b, binary.NativeEndian, size)
		if readMessage(&b, &req) == nil {
			t.Fatalf("accepted size %d", size)
		}
	}
	if readMessage(bytes.NewReader([]byte{1, 0}), &req) == nil {
		t.Fatal("accepted truncated header")
	}
}

func runHost(t *testing.T, req Request) (Response, func()) {
	t.Helper()
	in, input := io.Pipe()
	output, out := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	done := make(chan error, 1)
	go func() { done <- Run(ctx, in, out); _ = out.Close() }()
	t.Cleanup(func() { cancel(); _ = input.Close(); _ = output.Close() })
	if err := writeMessage(input, req); err != nil {
		t.Fatal(err)
	}
	var res Response
	if err := readMessage(output, &res); err != nil {
		t.Fatal(err)
	}
	return res, func() {
		_ = input.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("host did not exit after EOF")
		}
	}
}

func TestOwnedBridgeStopsOnEOFAndReportsFallbackPort(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	port := busy.Addr().(*net.TCPAddr).Port
	res, stop := runHost(t, Request{Type: "start", Port: port})
	if res.Type != "ready" || res.Host != "127.0.0.1" || res.Port == port || res.Reused {
		t.Fatalf("unexpected response: %+v", res)
	}
	addr := net.JoinHostPort(res.Host, strconv.Itoa(res.Port))
	if !existingBridge(context.Background(), addr) {
		t.Fatal("reported bridge is unavailable")
	}
	stop()
	if existingBridge(context.Background(), addr) {
		t.Fatal("owned bridge survived native port EOF")
	}
}

func TestReusedBridgeSurvivesEOF(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	srv := bridge.NewServer(bridge.ServerConfig{Port: 9876})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr, err := srv.StartNonBlocking(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()
	_, p, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(p)
	res, stop := runHost(t, Request{Type: "start", Port: port})
	if !res.Reused || res.Port != port {
		t.Fatalf("did not reuse existing bridge: %+v", res)
	}
	stop()
	if !existingBridge(ctx, addr) {
		t.Fatal("native host stopped a bridge it did not own")
	}
}

func TestInvalidRequestDoesNotStartBridge(t *testing.T) {
	for _, req := range []Request{{Type: "exec", Port: 9876}, {Type: "start", Port: -1}, {Type: "start", Port: 65536}} {
		res, stop := runHost(t, req)
		if res.Type != "error" || res.Error == "" {
			t.Fatalf("accepted invalid request: %+v", req)
		}
		stop()
	}
}

// An arbitrary HTTP service must not be mistaken for an Aegis bridge.
func TestDiscoveryRejectsOtherServices(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, `{"status":"ok"}`) })}
	go srv.Serve(listener)
	defer srv.Close()
	if existingBridge(context.Background(), listener.Addr().String()) {
		t.Fatal("accepted unrelated HTTP service")
	}
}
