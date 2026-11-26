// Package nativehost implements Chrome's length-prefixed native messaging protocol.
// Its only operation is starting (or discovering) the local Aegis bridge.
package nativehost

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/coppertone/bug-hunter/app/aegis/internal/connector/bridge"
)

const Name = "com.aegis.bridge"
const maxMessage = 64 * 1024

type Request struct {
	Type string `json:"type"`
	Port int    `json:"port"`
}

type Response struct {
	Type   string `json:"type"`
	Host   string `json:"host,omitempty"`
	Port   int    `json:"port,omitempty"`
	Token  string `json:"token,omitempty"`
	Reused bool   `json:"reused,omitempty"`
	Error  string `json:"error,omitempty"`
}

func readMessage(r io.Reader, dst any) error {
	var size uint32
	if err := binary.Read(r, binary.NativeEndian, &size); err != nil {
		return err
	}
	if size == 0 || size > maxMessage {
		return fmt.Errorf("invalid native message size: %d", size)
	}
	b := make([]byte, size)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	return json.Unmarshal(b, dst)
}

func writeMessage(w io.Writer, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if err := binary.Write(w, binary.NativeEndian, uint32(len(b))); err != nil {
		return err
	}
	_, err = io.Copy(w, bytes.NewReader(b))
	return err
}

// Run owns the bridge for the lifetime of the native port. EOF closes only a
// bridge started here; an already running bridge is left intact.
func Run(ctx context.Context, in io.Reader, out io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type incoming struct {
		request Request
		err     error
	}
	requests := make(chan incoming)
	go func() {
		for {
			var req Request
			err := readMessage(in, &req)
			select {
			case requests <- incoming{req, err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	var owned *bridge.Server
	defer func() {
		if owned != nil {
			_ = owned.Stop()
		}
	}()
	var ready *Response
	for {
		select {
		case <-ctx.Done():
			return nil
		case msg := <-requests:
			if msg.err == io.EOF {
				return nil
			}
			if msg.err != nil {
				return msg.err
			}
			req := msg.request
			if req.Port == 0 {
				req.Port = 9876
			}
			if req.Type != "start" || req.Port < 1 || req.Port > 65535 {
				if err := writeMessage(out, Response{Type: "error", Error: "expected start with a port between 1 and 65535"}); err != nil {
					return err
				}
				continue
			}
			if ready != nil {
				if err := writeMessage(out, ready); err != nil {
					return err
				}
				continue
			}
			address := net.JoinHostPort("127.0.0.1", strconv.Itoa(req.Port))
			if existingBridge(ctx, address) {
				token, err := runtimeToken(address)
				if err != nil {
					if e := writeMessage(out, Response{Type: "error", Error: err.Error()}); e != nil {
						return e
					}
					continue
				}
				ready = &Response{Type: "ready", Host: "127.0.0.1", Port: req.Port, Token: token, Reused: true}
			} else {
				owned = bridge.NewServer(bridge.ServerConfig{Addr: "127.0.0.1", Port: req.Port})
				addr, err := owned.StartNonBlocking(ctx)
				if err != nil {
					if e := writeMessage(out, Response{Type: "error", Error: err.Error()}); e != nil {
						return e
					}
					return err
				}
				_, p, err := net.SplitHostPort(addr)
				if err != nil {
					return err
				}
				port, err := strconv.Atoi(p)
				if err != nil {
					return err
				}
				ready = &Response{Type: "ready", Host: "127.0.0.1", Port: port, Token: owned.Token()}
			}
			if err := writeMessage(out, ready); err != nil {
				return err
			}
		}
	}
}

func runtimeToken(address string) (string, error) {
	var path string
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		path = filepath.Join(xdg, "aegis", "connector", "runtime.json")
	} else if home, err := os.UserHomeDir(); err == nil && home != "" {
		path = filepath.Join(home, ".config", "aegis", "connector", "runtime.json")
	}
	if path == "" {
		return "", fmt.Errorf("existing bridge has no readable authentication state")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("existing bridge authentication state is missing or not private; restart the bridge")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read bridge authentication state: %w", err)
	}
	var state bridge.RuntimeState
	if err := json.Unmarshal(data, &state); err != nil || state.Addr != address || state.Token == "" {
		return "", fmt.Errorf("existing bridge authentication state does not match %s; restart the bridge", address)
	}
	return state.Token, nil
}

func existingBridge(ctx context.Context, addr string) bool {
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/info", nil)
	if err != nil {
		return false
	}
	res, err := client.Do(req)
	if err != nil {
		return false
	}
	defer res.Body.Close()
	var info struct {
		ProtocolVersion int  `json:"protocolVersion"`
		PendingCommands *int `json:"pendingCommands"`
	}
	return res.StatusCode == http.StatusOK && json.NewDecoder(io.LimitReader(res.Body, maxMessage)).Decode(&info) == nil && info.ProtocolVersion == bridge.ProtocolVersion && info.PendingCommands != nil
}
