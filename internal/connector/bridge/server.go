package bridge

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

// Server is the WebSocket bridge server that connects Aegis to the browser extension.
type Server struct {
	addr     string
	port     int
	upgrader websocket.Upgrader

	extension   *websocket.Conn
	extensionMu sync.Mutex
	aegis       *websocket.Conn
	aegisMu     sync.Mutex

	pending   map[string]*pendingCommand
	pendingMu sync.Mutex

	logger *slog.Logger
	server *http.Server

	events   []Event
	eventsMu sync.Mutex
	eventSeq int64

	extCaps   *Capabilities
	extCapsMu sync.RWMutex
	token     string

	runtimePath   string
	discoveryLock string
	tokenErr      error
	stopOnce      sync.Once
}

// pendingCommand tracks a command sent to the extension awaiting its result.
type pendingCommand struct {
	Command   *Command
	ResultCh  chan *Result
	CreatedAt time.Time
}

// ServerConfig holds configuration for the bridge server.
type ServerConfig struct {
	Addr        string
	Port        int
	Logger      *slog.Logger
	Token       string // shared secret for discovery/handshake; generated when empty
	RuntimePath string // optional path to persist runtime/discovery state
}

var defaultUpgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		// localhost-only server; accept local origins and extension contexts
		return true
	},
}

// NewServer creates a new bridge server.
func NewServer(cfg ServerConfig) *Server {
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1"
	}
	if cfg.Port == 0 {
		cfg.Port = 9876
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	var tokenErr error
	if cfg.Token == "" {
		cfg.Token, tokenErr = randomToken(32)
	}
	return &Server{
		addr:        cfg.Addr,
		port:        cfg.Port,
		upgrader:    defaultUpgrader,
		pending:     make(map[string]*pendingCommand),
		logger:      cfg.Logger,
		events:      make([]Event, 0, 256),
		token:       cfg.Token,
		runtimePath: cfg.RuntimePath,
		tokenErr:    tokenErr,
	}
}

// Token returns the credential required by the hello handshake.
func (s *Server) Token() string {
	return s.token
}

// Start begins listening for connections. It blocks until ctx is cancelled.
func (s *Server) Start(ctx context.Context) (string, error) {
	addr, err := s.startHTTP(ctx)
	if err != nil {
		return "", err
	}
	<-ctx.Done()
	return addr, s.Stop()
}

// StartNonBlocking starts the server without blocking. Returns the address.
func (s *Server) StartNonBlocking(ctx context.Context) (string, error) {
	return s.startHTTP(ctx)
}

func (s *Server) startHTTP(ctx context.Context) (string, error) {
	if s.tokenErr != nil {
		return "", fmt.Errorf("generate bridge authentication token: %w", s.tokenErr)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", s.handleWebSocket)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/info", s.handleInfo)

	// Enforce localhost-only binding for safety.
	host := s.addr
	if host == "" || host == "localhost" {
		host = "127.0.0.1"
	}
	if host != "127.0.0.1" && host != "::1" {
		s.logger.Warn("overriding non-local bind address to 127.0.0.1", "requested", host)
		host = "127.0.0.1"
	}
	s.addr = host

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", s.addr, s.port))
	if err != nil {
		s.logger.Warn("configured port unavailable, using random port", "port", s.port, "error", err)
		listener, err = net.Listen("tcp", fmt.Sprintf("%s:0", s.addr))
		if err != nil {
			return "", fmt.Errorf("listen: %w", err)
		}
	}

	s.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	addr := listener.Addr().String()
	runtimePath := s.discoveryPath()
	if runtimePath == "" {
		_ = listener.Close()
		return "", fmt.Errorf("bridge discovery path is unavailable")
	}
	lock, err := acquireDiscoveryLock(runtimePath)
	if err != nil {
		_ = listener.Close()
		return "", err
	}
	s.discoveryLock = lock
	if err := s.persistRuntimeState(addr); err != nil {
		_ = listener.Close()
		_ = s.removeRuntimeState()
		s.releaseDiscoveryLock()
		return "", fmt.Errorf("persist bridge discovery: %w", err)
	}

	go s.pingLoop(ctx)
	s.logger.Info("bridge server listening", "addr", addr)
	go func() {
		if err := s.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			s.logger.Error("server error", "error", err)
		}
	}()
	return addr, nil
}

// Stop gracefully shuts down the server.
func (s *Server) Stop() error {
	var stopErr error
	s.stopOnce.Do(func() {
		s.logger.Info("bridge server shutting down")
		s.failAllPending(NewStructuredResult("", false, nil, &ErrorInfo{Code: ErrCodeDisconnected, Message: "bridge server shutting down"}))

		s.extensionMu.Lock()
		if s.extension != nil {
			_ = s.extension.Close()
		}
		s.extension = nil
		s.extensionMu.Unlock()

		s.aegisMu.Lock()
		if s.aegis != nil {
			_ = s.aegis.Close()
		}
		s.aegis = nil
		s.aegisMu.Unlock()

		if s.server != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			stopErr = s.server.Shutdown(ctx)
		}
		if err := s.removeRuntimeState(); stopErr == nil {
			stopErr = err
		}
		s.releaseDiscoveryLock()
	})
	return stopErr
}

func (s *Server) failAllPending(template *Result) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	for id, pc := range s.pending {
		r := *template
		r.ID = id
		r.RequestID = id
		select {
		case pc.ResultCh <- &r:
		default:
		}
		close(pc.ResultCh)
		delete(s.pending, id)
	}
}

// SendCommand sends a command to the extension and waits for the result.
func (s *Server) SendCommand(cmd *Command) (*Result, error) {
	if cmd == nil {
		return nil, fmt.Errorf("nil command")
	}
	if cmd.ID == "" {
		cmd.ID = generateID()
	}
	if cmd.RequestID == "" {
		cmd.RequestID = cmd.ID
	}
	if cmd.Version == 0 {
		cmd.Version = ProtocolVersion
	}
	if cmd.Timestamp == 0 {
		cmd.Timestamp = nowMs()
	}

	s.extensionMu.Lock()
	ext := s.extension
	s.extensionMu.Unlock()
	if ext == nil {
		return nil, fmt.Errorf("extension not connected")
	}

	timeout := DefaultCommandTimeout
	if cmd.Timeout > 0 {
		timeout = time.Duration(cmd.Timeout) * time.Millisecond
	}
	resultCh := make(chan *Result, 4)
	s.pendingMu.Lock()
	s.pending[cmd.RequestID] = &pendingCommand{Command: cmd, ResultCh: resultCh, CreatedAt: time.Now()}
	s.pendingMu.Unlock()

	if err := s.writeJSONToExtension(cmd); err != nil {
		s.pendingMu.Lock()
		delete(s.pending, cmd.RequestID)
		s.pendingMu.Unlock()
		return nil, fmt.Errorf("send command: %w", err)
	}

	select {
	case result, ok := <-resultCh:
		if !ok || result == nil {
			return NewStructuredResult(cmd.RequestID, false, nil, &ErrorInfo{Code: ErrCodeDisconnected, Message: "command channel closed"}), nil
		}
		return result, nil
	case <-time.After(timeout):
		s.pendingMu.Lock()
		if pc, ok := s.pending[cmd.RequestID]; ok {
			delete(s.pending, cmd.RequestID)
			close(pc.ResultCh)
		}
		s.pendingMu.Unlock()
		return NewStructuredResult(cmd.RequestID, false, nil, &ErrorInfo{Code: ErrCodeTimeout, Message: fmt.Sprintf("command timed out after %v", timeout)}), nil
	}
}

func (s *Server) writeJSONToExtension(v interface{}) error {
	s.extensionMu.Lock()
	defer s.extensionMu.Unlock()
	if s.extension == nil {
		return fmt.Errorf("extension not connected")
	}
	_ = s.extension.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return s.extension.WriteJSON(v)
}

func (s *Server) writeJSONToAegis(v interface{}) error {
	s.aegisMu.Lock()
	defer s.aegisMu.Unlock()
	if s.aegis == nil {
		return fmt.Errorf("aegis not connected")
	}
	_ = s.aegis.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return s.aegis.WriteJSON(v)
}

// BroadcastEvent records and sends an event to the Aegis connection.
func (s *Server) BroadcastEvent(evt *Event) {
	if evt == nil {
		return
	}
	evt.Seq = atomic.AddInt64(&s.eventSeq, 1)
	if evt.Timestamp == 0 {
		evt.Timestamp = nowMs()
	}
	if evt.Version == 0 {
		evt.Version = ProtocolVersion
	}
	s.eventsMu.Lock()
	s.events = append(s.events, *evt)
	if len(s.events) > 1000 {
		s.events = append([]Event(nil), s.events[len(s.events)-500:]...)
	}
	s.eventsMu.Unlock()

	_ = s.writeJSONToAegis(evt)
}

// IsExtensionConnected returns true if the browser extension is connected.
func (s *Server) IsExtensionConnected() bool {
	s.extensionMu.Lock()
	defer s.extensionMu.Unlock()
	return s.extension != nil
}

// ExtensionAddr returns the extension's remote address if connected.
func (s *Server) ExtensionAddr() string {
	s.extensionMu.Lock()
	defer s.extensionMu.Unlock()
	if s.extension == nil {
		return ""
	}
	return s.extension.RemoteAddr().String()
}

// Capabilities returns last known extension capabilities.
func (s *Server) Capabilities() *Capabilities {
	s.extCapsMu.RLock()
	defer s.extCapsMu.RUnlock()
	if s.extCaps == nil {
		return nil
	}
	c := *s.extCaps
	return &c
}

// handleWebSocket upgrades HTTP connections to WebSocket.
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Basic localhost-origin hardening: allow empty/localhost origins and extension contexts.
	if o := r.Header.Get("Origin"); o != "" && !isLocalOrigin(o) && !isExtensionOrigin(o) {
		s.logger.Warn("rejecting non-local websocket origin", "origin", o)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	clientType := r.URL.Query().Get("client")
	if clientType == "" {
		clientType = "aegis"
	}
	if clientType != "aegis" && clientType != "extension" {
		http.Error(w, "invalid client role", http.StatusBadRequest)
		return
	}
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.Error("websocket upgrade failed", "error", err)
		return
	}
	hello, ok := s.authenticate(conn, clientType)
	if !ok {
		return
	}
	switch clientType {
	case "extension":
		s.extCapsMu.Lock()
		s.extCaps = hello.Capabilities
		s.extCapsMu.Unlock()
		s.handleExtension(conn)
	case "aegis":
		s.handleAegis(conn)
	}
}

// authenticate requires a valid hello before a connection can replace or use a
// registered controller/extension session. Failed authentication is inert.
func (s *Server) authenticate(conn *websocket.Conn, clientType string) (*Hello, bool) {
	ack := HelloAck{Type: MsgHelloAck, Version: ProtocolVersion, OK: false, LastSeq: atomic.LoadInt64(&s.eventSeq), Timestamp: nowMs()}
	if clientType == "extension" {
		ack.Capabilities = &Capabilities{Commands: []string{CmdHello, CmdCancel}}
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, data, err := conn.ReadMessage()
	if err != nil {
		_ = conn.Close()
		return nil, false
	}
	msg, err := ParseMessage(data)
	hello, isHello := msg.(*Hello)
	if isHello {
		ack.ID = hello.ID
	}
	if err != nil || !isHello || hello.Client != clientType {
		ack.Error = &ErrorInfo{Code: ErrCodeInvalid, Message: "first message must be a hello for the requested client role"}
	} else if subtle.ConstantTimeCompare([]byte(hello.Token), []byte(s.token)) != 1 {
		ack.Error = &ErrorInfo{Code: ErrCodeDenied, Message: "authentication failed"}
	} else {
		ack.OK = true
	}
	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := conn.WriteJSON(ack); err != nil || !ack.OK {
		_ = conn.Close()
		return nil, false
	}
	if hello.ResumeFrom > 0 {
		s.replayEventsTo(conn, hello.ResumeFrom)
	}
	return hello, true
}

func isLocalOrigin(o string) bool {
	u, err := url.Parse(o)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}
func isExtensionOrigin(o string) bool {
	u, err := url.Parse(o)
	return err == nil && (u.Scheme == "chrome-extension" || u.Scheme == "moz-extension") && u.Host != "" && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == ""
}

// handleExtension manages the connection from the browser extension.
func (s *Server) handleExtension(conn *websocket.Conn) {
	s.extensionMu.Lock()
	if s.extension != nil {
		s.logger.Warn("replacing existing extension connection")
		_ = s.extension.Close()
	}
	s.extension = conn
	s.extensionMu.Unlock()

	s.logger.Info("browser extension connected", "remote", conn.RemoteAddr())
	s.BroadcastEvent(NewEvent(EventTask, mustRaw(map[string]interface{}{"state": "extension_connected", "addr": conn.RemoteAddr().String()})))

	defer func() {
		s.extensionMu.Lock()
		if s.extension == conn {
			s.extension = nil
		}
		s.extensionMu.Unlock()
		_ = conn.Close()
		s.logger.Info("browser extension disconnected")
		s.failAllPending(NewStructuredResult("", false, nil, &ErrorInfo{Code: ErrCodeDisconnected, Message: "extension disconnected"}))
		s.BroadcastEvent(NewEvent(EventTask, mustRaw(map[string]interface{}{"state": "extension_disconnected"})))
	}()

	_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				s.logger.Error("extension read error", "error", err)
			}
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		s.handleExtensionMessage(conn, data)
	}
}

// handleAegis manages the connection from Aegis/controller.
func (s *Server) handleAegis(conn *websocket.Conn) {
	s.aegisMu.Lock()
	if s.aegis != nil {
		s.logger.Warn("replacing existing aegis connection")
		_ = s.aegis.Close()
	}
	s.aegis = conn
	s.aegisMu.Unlock()

	s.logger.Info("aegis connected", "remote", conn.RemoteAddr())
	defer func() {
		s.aegisMu.Lock()
		if s.aegis == conn {
			s.aegis = nil
		}
		s.aegisMu.Unlock()
		_ = conn.Close()
		s.logger.Info("aegis disconnected")
	}()

	_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				s.logger.Error("aegis read error", "error", err)
			}
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		s.handleAegisMessage(conn, data)
	}
}

func (s *Server) handleExtensionMessage(conn *websocket.Conn, data []byte) {
	msg, err := ParseMessage(data)
	if err != nil {
		s.logger.Error("failed to parse extension message", "error", err)
		return
	}
	switch m := msg.(type) {
	case *Hello:
		// Hello is accepted only once, before the connection is registered.
	case *Result:
		id := CorrelationID(m.ID, m.RequestID)
		if m.Progress {
			// forward progress to controller without resolving
			_ = s.writeJSONToAegis(m)
			return
		}
		s.pendingMu.Lock()
		pc, ok := s.pending[id]
		if ok {
			delete(s.pending, id)
		}
		s.pendingMu.Unlock()
		if ok {
			select {
			case pc.ResultCh <- m:
			default:
			}
			close(pc.ResultCh)
		} else {
			// may be a progress-like late result; forward best-effort
			_ = s.writeJSONToAegis(m)
		}
	case *Progress:
		_ = s.writeJSONToAegis(m)
	case *Event:
		s.BroadcastEvent(m)
	case *Pong:
		// keepalive ack
	default:
		// ignore unknown for forward-compat
	}
}

func (s *Server) handleAegisMessage(conn *websocket.Conn, data []byte) {
	msg, err := ParseMessage(data)
	if err != nil {
		s.logger.Error("failed to parse aegis message", "error", err)
		return
	}
	switch m := msg.(type) {
	case *Hello:
		// Hello is accepted only once, before the connection is registered.
	case *Command:
		if m.Command == CmdCancel {
			// cancel by target in params or RequestID
			target := ""
			if len(m.Params) > 0 {
				var p struct{ TargetID, RequestID, ID string }
				if json.Unmarshal(m.Params, &p) == nil {
					if p.TargetID != "" {
						target = p.TargetID
					} else if p.RequestID != "" {
						target = p.RequestID
					} else {
						target = p.ID
					}
				}
			}
			if target != "" {
				s.cancelPending(target)
				// forward cancel to extension best-effort
				_ = s.writeJSONToExtension(&Cancel{Type: MsgCancel, TargetID: target, RequestID: target, Timestamp: nowMs()})
				_ = s.writeJSONToAegis(NewStructuredResult(CorrelationID(m.ID, m.RequestID), true, mustRaw(map[string]any{"canceled": target}), nil))
				return
			}
		}
		result, err := s.SendCommand(m)
		if err != nil {
			_ = s.writeJSONToAegis(NewStructuredResult(CorrelationID(m.ID, m.RequestID), false, nil, &ErrorInfo{Code: ErrCodeNotConnected, Message: err.Error()}))
			return
		}
		_ = s.writeJSONToAegis(result)
	case *Cancel:
		target := CorrelationID(m.RequestID, m.TargetID)
		if target != "" {
			s.cancelPending(target)
			_ = s.writeJSONToExtension(m)
		}
	case *Ping:
		pong := &Pong{ID: m.ID, Type: MsgPong, Timestamp: nowMs()}
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		_ = conn.WriteJSON(pong)
	default:
	}
}

func (s *Server) cancelPending(id string) {
	s.pendingMu.Lock()
	pc, ok := s.pending[id]
	if ok {
		delete(s.pending, id)
	}
	s.pendingMu.Unlock()
	if ok {
		select {
		case pc.ResultCh <- NewStructuredResult(id, false, nil, &ErrorInfo{Code: ErrCodeCanceled, Message: "command canceled"}):
		default:
		}
		close(pc.ResultCh)
	}
}

func (s *Server) replayEventsTo(conn *websocket.Conn, fromSeq int64) {
	s.eventsMu.Lock()
	events := append([]Event(nil), s.events...)
	s.eventsMu.Unlock()
	for _, e := range events {
		if e.Seq >= fromSeq {
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_ = conn.WriteJSON(e)
		}
	}
}

// pingLoop sends periodic pings to detect disconnection.
func (s *Server) pingLoop(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ping := &Ping{ID: generateID(), Type: MsgPing, Timestamp: nowMs()}
			s.extensionMu.Lock()
			ext := s.extension
			if ext != nil {
				_ = ext.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := ext.WriteJSON(ping); err != nil {
					s.logger.Warn("ping extension failed", "error", err)
				}
			}
			s.extensionMu.Unlock()
		}
	}
}

// handleHealth returns the health status of the bridge server.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	connected := s.IsExtensionConnected()
	status := map[string]interface{}{
		"status":             "ok",
		"extensionConnected": connected,
		"pendingCommands":    s.pendingCount(),
		"protocolVersion":    ProtocolVersion,
		"lastEventSeq":       atomic.LoadInt64(&s.eventSeq),
	}
	if !connected {
		status["status"] = "waiting_for_extension"
	}
	_ = json.NewEncoder(w).Encode(status)
}

// handleInfo returns detailed information to an authenticated local controller.
func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	authorization := r.Header.Get("Authorization")
	token := strings.TrimPrefix(authorization, "Bearer ")
	if authorization == token || subtle.ConstantTimeCompare([]byte(token), []byte(s.token)) != 1 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="aegis-bridge"`)
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	info := map[string]interface{}{
		"extensionConnected": s.IsExtensionConnected(),
		"extensionAddr":      s.ExtensionAddr(),
		"pendingCommands":    s.pendingCount(),
		"protocolVersion":    ProtocolVersion,
		"lastEventSeq":       atomic.LoadInt64(&s.eventSeq),
		"capabilities":       s.Capabilities(),
	}
	s.eventsMu.Lock()
	if len(s.events) > 0 {
		n := 5
		if len(s.events) < n {
			n = len(s.events)
		}
		info["recentEvents"] = s.events[len(s.events)-n:]
	}
	s.eventsMu.Unlock()
	_ = json.NewEncoder(w).Encode(info)
}

func (s *Server) pendingCount() int {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	return len(s.pending)
}

// RuntimeState is persisted for local discovery.
type RuntimeState struct {
	Addr      string    `json:"addr"`
	Port      int       `json:"port,omitempty"`
	Token     string    `json:"token"`
	TokenSet  bool      `json:"tokenSet"`
	Version   int       `json:"version"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func (s *Server) discoveryPath() string {
	if s.runtimePath != "" {
		return s.runtimePath
	}
	return defaultRuntimePath()
}

func (s *Server) persistRuntimeState(addr string) error {
	path := s.discoveryPath()
	if path == "" {
		return fmt.Errorf("discovery path is unavailable")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	st := RuntimeState{Addr: addr, Token: s.token, TokenSet: true, Version: ProtocolVersion, UpdatedAt: time.Now()}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func acquireDiscoveryLock(path string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	lock := path + ".lock"
	for attempt := 0; attempt < 2; attempt++ {
		err := os.Mkdir(lock, 0o700)
		if err == nil {
			pid := []byte(strconv.Itoa(os.Getpid()))
			if err := os.WriteFile(filepath.Join(lock, "pid"), pid, 0o600); err != nil {
				_ = os.RemoveAll(lock)
				return "", err
			}
			return lock, nil
		}
		if !os.IsExist(err) {
			return "", err
		}
		raw, readErr := os.ReadFile(filepath.Join(lock, "pid"))
		pid, parseErr := strconv.Atoi(string(raw))
		if readErr == nil && parseErr == nil && discoveryProcessAlive(pid) {
			return "", fmt.Errorf("another live bridge holds the discovery lock; stop it before starting a second bridge")
		}
		if err := os.RemoveAll(lock); err != nil {
			return "", fmt.Errorf("reclaim stale discovery lock: %w", err)
		}
	}
	return "", fmt.Errorf("could not acquire discovery lock")
}

func discoveryProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = process.Signal(syscall.Signal(0))
	if err == nil || err == syscall.EPERM {
		return true
	}
	// Unknown Windows signal errors are treated as live so a running lock is
	// never reclaimed underneath another process. Unix ESRCH is not live.
	return runtime.GOOS == "windows"
}

func (s *Server) releaseDiscoveryLock() {
	if s.discoveryLock != "" {
		_ = os.RemoveAll(s.discoveryLock)
		s.discoveryLock = ""
	}
}

func (s *Server) removeRuntimeState() error {
	path := s.discoveryPath()
	if path == "" {
		return nil
	}
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func defaultRuntimePath() string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "aegis", "connector", "runtime.json")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".config", "aegis", "connector", "runtime.json")
}

func mustRaw(v interface{}) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
