# Browser Extension Connector — Implementation Plan

**Date:** 2026-07-18
**Status:** IMPLEMENTED
**Scope:** Allow Aegis to control the user's existing browser session (Chrome/Chromium/Brave/Firefox) via a WebExtension, similar to Playwright's `connectOverCDP` but using the user's live browser.

---

## 1. Problem Statement

Aegis currently launches its own headless Chromium instance via `go-rod`. This means:

- The user must re-authenticate in Aegis's separate browser (session capture is a two-step process)
- Existing browser tabs, extensions, saved passwords, and profile settings are unavailable
- Some sites block headless browsers or require human-like browser fingerprints
- Multi-tab workflows with existing context are impossible

**Goal:** Let Aegis connect to the user's **running, authenticated browser** and control it directly — navigating, extracting, clicking, screenshotting — without launching a separate Chromium.

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    User's Browser                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │   Aegis       │  │  Content     │  │  User's      │  │
│  │   Extension   │  │  Script      │  │  Other Tabs  │  │
│  │  (Background) │  │  (per-tab)   │  │              │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────────┘  │
│         │                 │                              │
│         └────────┬────────┘                              │
│                  │ chrome.runtime / port                 │
└──────────────────┼──────────────────────────────────────┘
                   │ WebSocket (ws://127.0.0.1:<port>)
                   │
┌──────────────────┼──────────────────────────────────────┐
│  Bridge Server   │  (Go binary, runs locally)           │
│  ┌───────────────┴──────────────────────────────────┐   │
│  │  WebSocket Server + HTTP Server                   │   │
│  │  - Relays commands <-> extension                   │   │
│  │  - Exposes CDP-like REST/WS API for Aegis         │   │
│  │  - Session state management                       │   │
│  └───────────────┬──────────────────────────────────┘   │
│                  │                                       │
└──────────────────┼───────────────────────────────────────┘
                   │ internal Go interface
┌──────────────────┼───────────────────────────────────────┐
│  Aegis Connector │  (internal/connector/)                │
│  ┌───────────────┴──────────────────────────────────┐   │
│  │  Implements rod.Browser-compatible interface      │   │
│  │  - Connects to Bridge Server                      │   │
│  │  - Translates rod calls -> bridge commands        │   │
│  │  - Transparent to rest of Aegis                   │   │
│  └──────────────────────────────────────────────────┘   │
│                                                         │
│  Existing Aegis: crawler, exploit, scan, etc.           │
└─────────────────────────────────────────────────────────┘
```

### Key Design Decisions

1. **WebSocket bridge** (not Native Messaging): Native Messaging is one-message-at-a-time and limited to 1MB. WebSocket is full-duplex, no size limit, and supports streaming.

2. **Extension communicates via `chrome.runtime.connect`** between background and content scripts, and **WebSocket** to the bridge server. Content scripts execute DOM operations in the page context.

3. **Aegis Connector wraps `rod.Browser`** so existing code (crawler, injector, automation) works with minimal changes — just swap the browser constructor.

4. **Bridge server runs as a subcommand** (`aegis connect`) or automatically when `--connector` flag is used.

---

## 3. Components

### 3.1 Browser Extension (`extension/`)

A WebExtension v3 (Manifest V3 for Chrome/Brave/Chromium, Manifest V2 for Firefox with compat layer).

```
extension/
├── manifest.chrome.json      # MV3 for Chrome/Brave/Chromium
├── manifest.firefox.json     # MV2 for Firefox
├── background.js             # Service worker (MV3) / background script (MV2)
├── content.js                # Content script injected into all tabs
├── popup.html                # Simple control panel UI
├── popup.js                  # Popup logic (connect/disconnect/status)
├── icons/                    # Extension icons
│   ├── icon16.png
│   ├── icon48.png
│   └── icon128.png
└── _locales/en/messages.json # Internationalization
```

#### 3.1.1 Background Script (`background.js`)

Responsibilities:
- Maintain WebSocket connection to bridge server
- Route commands from bridge to content scripts
- Manage tab lifecycle (list tabs, create, close, switch)
- Handle cookies/storage operations via `chrome.cookies` API
- Capture screenshots via `chrome.tabs.captureVisibleTab`
- Handle navigation commands

Key APIs used:
- `chrome.tabs.*` — tab management
- `chrome.cookies.*` — cookie access
- `chrome.storage.*` — extension state
- `chrome.runtime.connect` — content script communication
- `WebSocket` — bridge server connection

Message protocol (JSON over WebSocket):

Command (Aegis -> Bridge -> Extension):
```json
{
  "id": "uuid",
  "type": "command",
  "command": "navigate",
  "params": { "url": "https://example.com", "tabId": 123 },
  "timestamp": 1692000000000
}
```

Response (Extension -> Bridge -> Aegis):
```json
{
  "id": "uuid",
  "type": "result",
  "success": true,
  "data": { "title": "Example", "url": "https://example.com" },
  "timestamp": 1692000000100
}
```

#### 3.1.2 Content Script (`content.js`)

Responsibilities:
- Execute DOM queries (querySelector, querySelectorAll, XPath)
- Extract text, attributes, HTML content
- Click, type, fill, hover, scroll elements
- Wait for elements (visibility, attachment)
- Report DOM mutations

Injected into pages via `chrome.scripting.executeScript` (MV3) or `tabs.executeScript` (MV2).

#### 3.1.3 Commands Supported

| Category | Commands |
|----------|----------|
| **Navigation** | `navigate`, `goBack`, `goForward`, `reload`, `getCurrentUrl`, `getTitle` |
| **Tabs** | `listTabs`, `newTab`, `closeTab`, `switchTab`, `getTabInfo` |
| **Element** | `querySelector`, `querySelectorAll`, `getElementText`, `getElementAttribute`, `getElementHtml`, `getElementBoundingBox` |
| **Interaction** | `click`, `doubleClick`, `rightClick`, `hover`, `type`, `fill`, `clear`, `press`, `select`, `check`, `uncheck`, `scroll`, `scrollIntoView` |
| **Wait** | `waitForSelector`, `waitForNavigation`, `waitForLoad`, `waitForIdle`, `waitForTimeout` |
| **JavaScript** | `evaluate`, `evaluateAll` |
| **Screenshot** | `screenshot`, `screenshotElement`, `captureVisibleTab` |
| **Cookies** | `getCookies`, `setCookie`, `deleteCookie`, `clearCookies` |
| **Storage** | `getLocalStorage`, `setLocalStorage`, `getSessionStorage`, `setSessionStorage` |
| **Frame** | `switchFrame`, `switchMain`, `listFrames` |
| **Dialog** | `acceptDialog`, `dismissDialog` |
| **Extract** | `extractData` (structured extraction with rules) |

### 3.2 Bridge Server (`internal/connector/bridge/`)

A Go HTTP/WebSocket server that runs locally and bridges Aegis <-> Extension.

```
internal/connector/bridge/
├── server.go       # WebSocket server + HTTP health endpoint
├── handler.go      # Command routing and dispatch
├── session.go      # Active session/tab state management
├── protocol.go     # Message types and serialization
└── bridge_test.go  # Tests
```

#### 3.2.1 Server Details

- Listens on `127.0.0.1:<port>` (default: random available port)
- WebSocket endpoint: `ws://127.0.0.1:<port>/ws`
- Health endpoint: `http://127.0.0.1:<port>/health`
- Info endpoint: `http://127.0.0.1:<port>/info` (returns extension connection status, browser info)
- Single client connection (only one Aegis instance connects at a time)
- Command timeout: 30s default, configurable per command

#### 3.2.2 Protocol Types

All messages are JSON. Two message types:

```go
// Command sent from Aegis through bridge to extension
type Command struct {
    ID        string          `json:"id"`
    Command   string          `json:"command"`
    Params    json.RawMessage `json:"params,omitempty"`
    Timeout   time.Duration   `json:"timeout,omitempty"`
    TabID     int             `json:"tabId,omitempty"`
}

// Result returned from extension through bridge to Aegis
type Result struct {
    ID      string          `json:"id"`
    Success bool            `json:"success"`
    Data    json.RawMessage `json:"data,omitempty"`
    Error   string          `json:"error,omitempty"`
}
```

### 3.3 Aegis Connector (`internal/connector/`)

The Go package that provides a rod.Browser-compatible interface to the rest of Aegis.

```
internal/connector/
├── connector.go      # Main Connector type (wraps rod.Browser)
├── page.go           # Page wrapper (wraps rod.Page)
├── element.go        # Element wrapper (wraps rod.Element)
├── session.go        # Session import/export from existing session files
├── connector_test.go # Tests
└── bridge/           # Bridge server (see 3.2)
```

#### 3.3.1 Connector API

```go
// Connector provides a rod.Browser-compatible interface that communicates
// with the user's browser via the Aegis Extension Bridge.
type Connector struct {
    bridgeURL    string
    wsConn       *websocket.Conn
    tabID        int
    sessions     map[int]*TabSession
    mu           sync.Mutex
}

// Connect establishes a connection to a running bridge server.
func Connect(bridgeURL string) (*Connector, error)

// ConnectWithBridge starts the bridge server and connects.
func ConnectWithBridge(opts ...BridgeOption) (*Connector, error)

// Pages returns all open tabs as rod.Page-compatible objects.
func (c *Connector) Pages() ([]*rod.Page, error)

// Page returns the current active tab.
func (c *Connector) Page(url string) (*rod.Page, error)

// MustPage navigates to a URL and returns the page.
func (c *Connector) MustPage(url string) *rod.Page

// Close disconnects from the bridge.
func (c *Connector) Close() error
```

#### 3.3.2 Session Integration

The connector integrates with Aegis's existing session manager:

```go
// ImportSession loads an existing Aegis session into the user's browser.
func (c *Connector) ImportSession(mgr *session.SessionManager) error

// ExportSession saves the user's current browser state to an Aegis session.
func (c *Connector) ExportSession(mgr *session.SessionManager) error
```

This allows:
1. `aegis auth --connector` -> captures user's live browser session
2. `aegis crawl --connector` -> crawls using user's authenticated browser
3. `aegis exploit --connector` -> tests exploits in user's real browser context

---

## 4. Integration with Existing Aegis Code

### 4.1 CLI Changes (`cmd/aegis/main.go`)

Add `--connector` flag to commands that use the browser:

```bash
# Use user's existing browser instead of launching Chromium
aegis auth --connector --target-url https://target.example
aegis crawl --connector --config configs/config.yaml --dump ./dump
aegis exploit --connector --config configs/exploit.yaml
```

The `--connector` flag:
- Starts the bridge server if not already running
- Waits for the extension to connect
- Uses the connector instead of launching Chromium
- Falls back to go-rod if extension is not available (with warning)

### 4.2 Crawler Integration (`internal/crawler/crawler.go`)

The crawler currently calls `browser.NewLauncher()` and `rod.New().ControlURL(u).Connect()`. With the connector:

```go
func (c *Crawler) getBrowser() (*rod.Browser, error) {
    if c.config.ConnectorMode {
        // Use user's existing browser via extension
        conn, err := connector.Connect(c.config.BridgeURL)
        if err != nil {
            return nil, fmt.Errorf("connect to browser: %w", err)
        }
        return conn.Browser(), nil
    }
    // Existing go-rod launcher code...
}
```

### 4.3 Session Manager Integration

The session manager currently uses `rod.Page` directly. The connector wraps this so the same `Save`/`Load` methods work:

```go
// Save captures the current state from the user's live browser
func (m *SessionManager) SaveFromConnector(conn *connector.Connector) error {
    page := conn.CurrentPage()
    return m.Save(page)
}

// Load replays stored session into the user's browser
func (m *SessionManager) LoadToConnector(conn *connector.Connector) error {
    page := conn.CurrentPage()
    return m.Load(page)
}
```

### 4.4 Browser Automation Scripts

The automation engine (`internal/browser/automation.go`) uses `rod.Page` directly. Since the connector wraps `rod.Page`, automation scripts work without changes when running in connector mode.

---

## 5. Implementation Phases

### Phase 1: Bridge Server (Go)
**Files:** `internal/connector/bridge/`
**Effort:** ~2-3 days

1. Create `protocol.go` with message types
2. Create `server.go` with WebSocket server
3. Create `handler.go` with command routing
4. Create `session.go` for state management
5. Write tests for bridge server
6. Add `aegis connect` subcommand to start bridge standalone

### Phase 2: Browser Extension
**Files:** `extension/`
**Effort:** ~3-4 days

1. Create Manifest V3 for Chrome/Brave/Chromium
2. Create Manifest V2 for Firefox
3. Implement `background.js` with WebSocket connection and command routing
4. Implement `content.js` with DOM operations
5. Create popup UI for connection status
6. Test with Chrome, Brave, and Firefox

### Phase 3: Aegis Connector Package
**Files:** `internal/connector/`
**Effort:** ~2-3 days

1. Create `connector.go` with bridge client
2. Create `page.go` wrapping rod.Page methods
3. Create `element.go` wrapping rod.Element methods
4. Create `session.go` for session import/export
5. Write comprehensive tests

### Phase 4: Integration
**Files:** `cmd/aegis/main.go`, `internal/crawler/crawler.go`
**Effort:** ~1-2 days

1. Add `--connector` and `--bridge-url` CLI flags
2. Modify crawler to support connector mode
3. Modify auth command for connector mode
4. Modify exploit command for connector mode
5. Add fallback logic (extension not available -> go-rod)

### Phase 5: Polish & Documentation
**Effort:** ~1 day

1. Extension packaging scripts (zip for Chrome Web Store, .xpi for Firefox)
2. Installation documentation
3. Update CLAUDE.md and SPEC.md
4. Error handling and reconnection logic
5. Graceful degradation when extension disconnects mid-operation

---

## 6. Security Considerations

1. **Localhost only**: Bridge server binds to `127.0.0.1` — no network exposure
2. **No authentication needed** for bridge (local process, same machine)
3. **Extension permissions**: Minimal — only `activeTab`, `tabs`, `cookies`, `storage`, `scripting`
4. **Content Security Policy**: Extension uses `connect-src ws://127.0.0.1` for bridge
5. **Command sandboxing**: Extension only executes commands from the bridge (localhost verified)
6. **No credential logging**: Cookies/tokens never written to logs

---

## 7. Browser Compatibility

| Browser | Manifest | Status |
|---------|----------|--------|
| Chrome 88+ | MV3 | Primary target |
| Brave 1.28+ | MV3 | Primary target (Chromium-based) |
| Chromium 88+ | MV3 | Primary target |
| Firefox 109+ | MV2 | Secondary target |
| Edge 88+ | MV3 | Should work (Chromium-based, untested) |

---

## 8. File Tree (New Files)

```
Aegis/
├── extension/                          # Browser extension
│   ├── manifest.chrome.json
│   ├── manifest.firefox.json
│   ├── background.js
│   ├── content.js
│   ├── popup.html
│   ├── popup.js
│   └── icons/
│       ├── icon16.png
│       ├── icon48.png
│       └── icon128.png
├── internal/
│   └── connector/                      # Go connector package
│       ├── connector.go
│       ├── page.go
│       ├── element.go
│       ├── session.go
│       ├── connector_test.go
│       └── bridge/
│           ├── server.go
│           ├── handler.go
│           ├── session.go
│           ├── protocol.go
│           └── bridge_test.go
├── cmd/aegis/
│   └── main.go                         # Modified: --connector flag
├── internal/crawler/
│   └── crawler.go                      # Modified: connector mode
└── docs/plans/
    └── 2026-07-18-browser-extension-connector.md  # This file
```

---

## 9. Dependencies

### Go (new)
- `github.com/gorilla/websocket` — WebSocket server/client (mature, well-audited)
- No other new dependencies required

### Extension (no build tools)
- Pure JavaScript (no TypeScript, no bundler — keeps it auditable and simple)
- Chrome/Firefox WebExtension APIs (standard, no polyfills needed)

---

## 10. Testing Strategy

1. **Bridge server unit tests**: Mock WebSocket clients, test command routing
2. **Extension integration tests**: Load unpacked extension, connect to test bridge
3. **Connector unit tests**: Mock bridge responses, verify rod-compatible interface
4. **End-to-end test**: Start bridge -> load extension -> use connector -> verify page actions
5. **Browser matrix**: Test on Chrome, Brave, Firefox (at least smoke test each)

---

## 11. Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Extension MV3 service worker killed by browser | Bridge disconnects | Auto-reconnect with exponential backoff; service worker ping/pong |
| Content script injection fails on chrome:// pages | Commands fail | Graceful error with clear message; skip internal pages |
| User closes extension popup | No visible status | Background script maintains connection; popup is optional |
| Bridge port conflict | Server won't start | Use random available port; write port to temp file for extension discovery |
| Firefox MV2 deprecation | Future breakage | Monitor Firefox MV3 timeline; plan migration when stable |
| Sites with strict CSP | Content script blocked | Use `chrome.scripting.executeScript` with world: "MAIN" for JS eval |
