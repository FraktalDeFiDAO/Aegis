// Package connector provides a rod.Browser-compatible interface that
// communicates with the user's live browser via the Aegis Extension Bridge,
// instead of launching a separate Chromium instance.
package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coppertone/bug-hunter/app/aegis/internal/connector/bridge"
	"github.com/coppertone/bug-hunter/app/aegis/internal/session"
	"github.com/go-rod/rod"
	"github.com/gorilla/websocket"
)

// EventHandler receives unsolicited bridge events.
type EventHandler func(*bridge.Event)

type pendingCall struct {
	ch     chan *bridge.Result
	cancel context.CancelFunc
}

// Connector wraps a WebSocket connection to the bridge server and provides
// a rod.Browser-compatible API so existing Aegis code works with minimal changes.
type Connector struct {
	wsURL   string
	wsConn  *websocket.Conn
	logger  *slog.Logger
	token   string
	writeMu sync.Mutex

	mu       sync.RWMutex
	pages    map[int]*Page
	activeID int
	closed   bool

	pendingMu sync.Mutex
	pending   map[string]*pendingCall

	eventsMu sync.RWMutex
	handlers []EventHandler

	lastSeq   int64
	helloDone chan struct{}
	helloOnce sync.Once
	helloErr  error

	// Session import/export
	sessionMgr *session.SessionManager
}

// Config holds configuration for the connector.
type Config struct {
	BridgeURL string // ws://127.0.0.1:<port>/ws
	Logger    *slog.Logger
	Token     string
}

// Option configures the connector.
type Option func(*Config)

// WithLogger sets a custom logger.
func WithLogger(l *slog.Logger) Option {
	return func(c *Config) { c.Logger = l }
}

// WithToken sets the shared credential used during the hello handshake.
func WithToken(token string) Option {
	return func(c *Config) { c.Token = token }
}

// Connect creates a Connector and connects to the bridge server.
func Connect(wsURL string, opts ...Option) (*Connector, error) {
	cfg := Config{BridgeURL: wsURL}
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("connect to bridge: %w", err)
	}

	c := &Connector{
		wsURL:     wsURL,
		wsConn:    conn,
		logger:    cfg.Logger,
		token:     cfg.Token,
		pages:     make(map[int]*Page),
		pending:   make(map[string]*pendingCall),
		helloDone: make(chan struct{}),
	}

	go c.readLoop()
	if err := c.sendHello(0); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("bridge authentication: %w", err)
	}
	cfg.Logger.Info("connected to bridge", "url", wsURL)
	return c, nil
}

// ConnectWithBridge starts the bridge server and connects to it.
// Returns the connector and the bridge address.
func ConnectWithBridge(addr string, opts ...Option) (*Connector, string, error) {
	if addr == "" {
		addr = "127.0.0.1"
	}
	srv := bridge.NewServer(bridge.ServerConfig{Addr: addr, Port: 9876})
	bridgeAddr, err := srv.StartNonBlocking(context.Background())
	if err != nil {
		return nil, "", fmt.Errorf("start bridge: %w", err)
	}
	wsURL := fmt.Sprintf("ws://%s/ws?client=aegis", bridgeAddr)
	opts = append(opts, WithToken(srv.Token()))
	conn, err := Connect(wsURL, opts...)
	if err != nil {
		return nil, "", fmt.Errorf("connect to bridge: %w", err)
	}
	return conn, bridgeAddr, nil
}

// SubscribeEvents registers a handler for unsolicited events.
func (c *Connector) SubscribeEvents(h EventHandler) {
	c.eventsMu.Lock()
	c.handlers = append(c.handlers, h)
	c.eventsMu.Unlock()
}

// readLoop is the single reader/dispatcher for inbound frames.
func (c *Connector) readLoop() {
	for {
		c.mu.RLock()
		ws := c.wsConn
		closed := c.closed
		c.mu.RUnlock()
		if closed || ws == nil {
			return
		}
		_, data, err := ws.ReadMessage()
		if err != nil {
			c.mu.RLock()
			closed = c.closed
			c.mu.RUnlock()
			if closed {
				return
			}
			c.logger.Error("bridge read error", "error", err)
			c.failAllPending(&bridge.ErrorInfo{Code: bridge.ErrCodeDisconnected, Message: err.Error()})
			go c.reconnectLoop()
			return
		}
		msg, err := bridge.ParseMessage(data)
		if err != nil {
			continue
		}
		switch m := msg.(type) {
		case *bridge.Result:
			id := bridge.CorrelationID(m.ID, m.RequestID)
			if m.Progress {
				c.dispatchEvent(&bridge.Event{Type: bridge.MsgEvent, Event: "progress", Data: m.Data, Timestamp: m.Timestamp})
				continue
			}
			c.resolvePending(id, m)
		case *bridge.Progress:
			c.dispatchEvent(&bridge.Event{Type: bridge.MsgEvent, Event: "progress", Data: m.Data, Timestamp: m.Timestamp})
		case *bridge.Event:
			if m.Seq > 0 {
				atomic.StoreInt64(&c.lastSeq, m.Seq)
			}
			c.handleEvent(m)
		case *bridge.Ping:
			_ = c.writeJSON(bridge.Pong{ID: m.ID, Type: bridge.MsgPong, Timestamp: time.Now().UnixMilli()})
		case *bridge.HelloAck:
			c.mu.Lock()
			if !m.OK {
				c.helloErr = errors.New("bridge rejected authentication")
				if m.Error != nil && m.Error.Message != "" {
					c.helloErr = errors.New(m.Error.Message)
				}
			}
			c.mu.Unlock()
			c.helloOnce.Do(func() { close(c.helloDone) })
		case *bridge.ErrorMessage:
			id := bridge.CorrelationID(m.ID, m.RequestID)
			if id != "" {
				errInfo := m.Err
				if errInfo == nil {
					errInfo = &bridge.ErrorInfo{Code: bridge.ErrCodeInternal, Message: m.Error}
				}
				c.resolvePending(id, bridge.NewStructuredResult(id, false, nil, errInfo))
			}
		}
	}
}

func (c *Connector) writeJSON(v interface{}) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.mu.RLock()
	ws := c.wsConn
	closed := c.closed
	c.mu.RUnlock()
	if closed || ws == nil {
		return fmt.Errorf("not connected")
	}
	_ = ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return ws.WriteJSON(v)
}

func (c *Connector) sendHello(resumeFrom int64) error {
	hello := bridge.Hello{Type: bridge.MsgHello, Client: "aegis", Version: bridge.ProtocolVersion, ResumeFrom: resumeFrom, Token: c.token, Timestamp: time.Now().UnixMilli(), Capabilities: &bridge.Capabilities{Commands: []string{}}}
	if err := c.writeJSON(hello); err != nil {
		return err
	}
	select {
	case <-c.helloDone:
		c.mu.RLock()
		err := c.helloErr
		c.mu.RUnlock()
		return err
	case <-time.After(2 * time.Second):
		return fmt.Errorf("hello ack timeout")
	}
}

func (c *Connector) resolvePending(id string, r *bridge.Result) {
	c.pendingMu.Lock()
	p, ok := c.pending[id]
	if ok {
		delete(c.pending, id)
	}
	c.pendingMu.Unlock()
	if ok {
		select {
		case p.ch <- r:
		default:
		}
		if p.cancel != nil {
			p.cancel()
		}
	}
}

func (c *Connector) failAllPending(err *bridge.ErrorInfo) {
	c.pendingMu.Lock()
	ids := make([]string, 0, len(c.pending))
	for id := range c.pending {
		ids = append(ids, id)
	}
	c.pendingMu.Unlock()
	for _, id := range ids {
		c.resolvePending(id, bridge.NewStructuredResult(id, false, nil, err))
	}
}

func (c *Connector) dispatchEvent(evt *bridge.Event) {
	c.eventsMu.RLock()
	handlers := append([]EventHandler(nil), c.handlers...)
	c.eventsMu.RUnlock()
	for _, h := range handlers {
		h(evt)
	}
}

func (c *Connector) handleEvent(evt *bridge.Event) {
	switch evt.Event {
	case bridge.EventTabClosed:
		var d struct {
			TabID int `json:"tabId"`
		}
		if json.Unmarshal(evt.Data, &d) == nil {
			c.mu.Lock()
			delete(c.pages, d.TabID)
			if c.activeID == d.TabID {
				c.activeID = 0
			}
			c.mu.Unlock()
		}
	case bridge.EventTabUpdated:
		var d struct {
			TabID  int    `json:"tabId"`
			URL    string `json:"url"`
			Title  string `json:"title"`
			Status string `json:"status"`
		}
		if json.Unmarshal(evt.Data, &d) == nil && d.TabID != 0 {
			c.mu.Lock()
			if p, ok := c.pages[d.TabID]; ok {
				if d.URL != "" {
					p.url = d.URL
				}
				if d.Title != "" {
					p.title = d.Title
				}
			}
			c.mu.Unlock()
		}
	}
	c.dispatchEvent(evt)
}

func (c *Connector) reconnectLoop() {
	delay := 1 * time.Second
	for i := 0; i < 8; i++ {
		c.mu.RLock()
		closed := c.closed
		c.mu.RUnlock()
		if closed {
			return
		}
		time.Sleep(jitter(delay))
		conn, _, err := websocket.DefaultDialer.Dial(c.wsURL, nil)
		if err != nil {
			delay *= 2
			if delay > 15*time.Second {
				delay = 15 * time.Second
			}
			continue
		}
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			_ = conn.Close()
			return
		}
		if c.wsConn != nil {
			_ = c.wsConn.Close()
		}
		c.wsConn = conn
		c.helloDone = make(chan struct{})
		c.helloOnce = sync.Once{}
		c.helloErr = nil
		c.mu.Unlock()
		go c.readLoop()
		if err := c.sendHello(atomic.LoadInt64(&c.lastSeq)); err != nil {
			c.logger.Error("reconnect authentication failed", "error", err)
			_ = c.Close()
			return
		}
		c.logger.Info("reconnected to bridge")
		return
	}
	c.logger.Error("reconnect attempts exhausted")
}

func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	// +/-20%
	j := 0.8 + rand.Float64()*0.4
	return time.Duration(float64(d) * j)
}

// sendCommand sends a command to the bridge and waits for the result.
func (c *Connector) sendCommand(command string, params interface{}, tabID int) (*bridge.Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), bridge.DefaultCommandTimeout)
	defer cancel()
	return c.sendCommandCtx(ctx, command, params, tabID)
}

func (c *Connector) sendCommandCtx(ctx context.Context, command string, params interface{}, tabID int) (*bridge.Result, error) {
	cmd := bridge.NewCommand(command, nil, tabID)
	if deadline, ok := ctx.Deadline(); ok {
		cmd.Timeout = max(1, time.Until(deadline).Milliseconds())
	}
	if params != nil {
		data, err := json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("marshal params: %w", err)
		}
		cmd.Params = data
	}
	id := bridge.CorrelationID(cmd.ID, cmd.RequestID)
	ch := make(chan *bridge.Result, 4)
	ctx2, cancel := context.WithCancel(ctx)
	// register pending before write to avoid races with fast responses
	c.pendingMu.Lock()
	if c.pending == nil {
		c.pending = make(map[string]*pendingCall)
	}
	c.pending[id] = &pendingCall{ch: ch, cancel: cancel}
	c.pendingMu.Unlock()
	if err := c.writeJSON(cmd); err != nil {
		c.pendingMu.Lock()
		delete(c.pending, id)
		c.pendingMu.Unlock()
		cancel()
		return nil, fmt.Errorf("send command: %w", err)
	}
	select {
	case res, ok := <-ch:
		if !ok || res == nil {
			return nil, errors.New("command canceled or disconnected")
		}
		return res, nil
	case <-ctx2.Done():
		c.pendingMu.Lock()
		delete(c.pending, id)
		c.pendingMu.Unlock()
		// best-effort cancel to bridge
		_ = c.writeJSON(&bridge.Cancel{Type: bridge.MsgCancel, TargetID: id, RequestID: id, Timestamp: time.Now().UnixMilli()})
		if errors.Is(ctx2.Err(), context.Canceled) {
			return nil, context.Canceled
		}
		return nil, fmt.Errorf("command timed out: %s", command)
	}
}

// sendCommandAsync sends a command without waiting for the result.
func (c *Connector) sendCommandAsync(command string, params interface{}, tabID int) error {
	cmd := bridge.NewCommand(command, nil, tabID)
	if params != nil {
		data, err := json.Marshal(params)
		if err != nil {
			return fmt.Errorf("marshal params: %w", err)
		}
		cmd.Params = data
	}
	return c.writeJSON(cmd)
}

// ─── rod.Browser-compatible API ──────────────────────────────────────────────

// ConnectorPages returns connector page wrappers for all open tabs.
func (c *Connector) ConnectorPages() ([]*Page, error) {
	result, err := c.sendCommand(bridge.CmdListTabs, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("list tabs: %w", err)
	}

	var data struct {
		Tabs []struct {
			ID     int    `json:"id"`
			URL    string `json:"url"`
			Title  string `json:"title"`
			Active bool   `json:"active"`
		} `json:"tabs"`
	}
	if err := json.Unmarshal(result.Data, &data); err != nil {
		return nil, fmt.Errorf("parse tabs: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	pages := make([]*Page, 0, len(data.Tabs))
	for _, t := range data.Tabs {
		page, ok := c.pages[t.ID]
		if !ok {
			page = newPage(c, t.ID)
			c.pages[t.ID] = page
		}
		page.setInfo(t.URL, t.Title)
		if t.Active {
			c.activeID = t.ID
		}
		pages = append(pages, page)
	}
	return pages, nil
}

// Pages returns all open tabs (rod-compatible placeholder; prefer ConnectorPages in connector mode).
func (c *Connector) Pages() ([]*rod.Page, error) {
	ps, err := c.ConnectorPages()
	if err != nil {
		return nil, err
	}
	out := make([]*rod.Page, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.page)
	}
	return out, nil
}

// ConnectorPage creates or returns a connector page wrapper.
func (c *Connector) ConnectorPage(url string) (*Page, error) {
	if url == "" {
		return c.ActiveConnectorPage()
	}

	result, err := c.sendCommand(bridge.CmdNewTab, map[string]string{"url": url}, 0)
	if err != nil {
		return nil, fmt.Errorf("new tab: %w", err)
	}

	var data struct {
		TabID int    `json:"tabId"`
		URL   string `json:"url"`
	}
	if err := json.Unmarshal(result.Data, &data); err != nil {
		return nil, fmt.Errorf("parse new tab: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	page := newPage(c, data.TabID)
	if data.URL != "" {
		page.setInfo(data.URL, "")
	} else {
		page.setInfo(url, "")
	}
	c.pages[data.TabID] = page
	c.activeID = data.TabID
	return page, nil
}

// Page creates or returns a page. If url is empty, returns the active page.
func (c *Connector) Page(url string) (*rod.Page, error) {
	p, err := c.ConnectorPage(url)
	if err != nil {
		return nil, err
	}
	return p.page, nil
}

// MustPage is like Page but panics on error.
func (c *Connector) MustPage(url ...string) *rod.Page {
	u := ""
	if len(url) > 0 {
		u = url[0]
	}
	p, err := c.Page(u)
	if err != nil {
		panic(fmt.Errorf("must page: %w", err))
	}
	return p
}

// ActiveConnectorPage returns the current active connector page.
func (c *Connector) ActiveConnectorPage() (*Page, error) {
	c.mu.Lock()
	id := c.activeID
	page := c.pages[id]
	c.mu.Unlock()
	if id > 0 && page != nil {
		return page, nil
	}

	result, err := c.sendCommand(bridge.CmdGetTabInfo, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("get active tab: %w", err)
	}

	var data struct {
		TabID int    `json:"tabId"`
		URL   string `json:"url"`
		Title string `json:"title"`
	}
	if err := json.Unmarshal(result.Data, &data); err != nil {
		return nil, fmt.Errorf("parse tab info: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.pages[data.TabID]
	if !ok {
		p = newPage(c, data.TabID)
		c.pages[data.TabID] = p
	}
	p.setInfo(data.URL, data.Title)
	c.activeID = data.TabID
	return p, nil
}

// activePage returns the current active page.
func (c *Connector) activePage() (*rod.Page, error) {
	p, err := c.ActiveConnectorPage()
	if err != nil {
		return nil, err
	}
	return p.page, nil
}

// Close disconnects from the bridge.
func (c *Connector) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	if c.wsConn != nil {
		return c.wsConn.Close()
	}
	return nil
}

// Send sends a raw command through the bridge (public wrapper for advanced/phase features).
func (c *Connector) Send(command string, params interface{}, tabID int) (*bridge.Result, error) {
	return c.sendCommand(command, params, tabID)
}

// SendContext applies the caller's deadline to both client and bridge waits.
func (c *Connector) SendContext(ctx context.Context, command string, params interface{}, tabID int) (*bridge.Result, error) {
	return c.sendCommandCtx(ctx, command, params, tabID)
}

// SendAsync sends a raw command without waiting for result.
func (c *Connector) SendAsync(command string, params interface{}, tabID int) error {
	return c.sendCommandAsync(command, params, tabID)
}

// GetRuntimeStateInfo returns basic connector state for diagnostics.
func (c *Connector) GetRuntimeStateInfo() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return map[string]interface{}{
		"connected": c.wsConn != nil && !c.closed,
		"wsURL":     c.wsURL,
		"tabs":      len(c.pages),
		"activeTab": c.activeID,
	}
}

// Browser returns a rod.Browser-compatible interface.
// Since rod.Browser is a concrete type, we return nil in connector mode.
// Callers should use c.Pages(), c.Page(), etc. directly.
func (c *Connector) Browser() *rod.Browser {
	return nil
}

// ActivePage returns the current active page as a rod.Page.
func (c *Connector) ActivePage() *rod.Page {
	p, err := c.activePage()
	if err != nil {
		return nil
	}
	return p
}

// ─── Session integration ─────────────────────────────────────────────────────

// ImportSession loads an existing Aegis session into the user's browser.
func (c *Connector) ImportSession(mgr *session.SessionManager) error {
	page, err := c.activePage()
	if err != nil {
		return fmt.Errorf("get active page: %w", err)
	}

	// Use rod.Page directly with the session manager
	return mgr.Load(page)
}

// ExportSession saves the user's current browser state to an Aegis session.
func (c *Connector) ExportSession(mgr *session.SessionManager) error {
	page, err := c.activePage()
	if err != nil {
		return fmt.Errorf("get active page: %w", err)
	}

	return mgr.Save(page)
}
