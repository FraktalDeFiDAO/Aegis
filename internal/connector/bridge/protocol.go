// Package bridge provides a WebSocket bridge server that relays commands
// between Aegis and the browser extension.
//
// Protocol v1 (additive, backward-tolerant): versioned handshake/capabilities,
// request correlation (id/requestId), structured errors/progress/cancel, and
// event sequencing for best-effort replay.
package bridge

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"sync/atomic"
	"time"
)

// ProtocolVersion is the current bridge protocol version.
const ProtocolVersion = 1

// MessageType identifies the direction and purpose of a message.
type MessageType string

const (
	MsgCommand  MessageType = "command"
	MsgResult   MessageType = "result"
	MsgEvent    MessageType = "event"
	MsgPing     MessageType = "ping"
	MsgPong     MessageType = "pong"
	MsgError    MessageType = "error"
	MsgHello    MessageType = "hello"
	MsgHelloAck MessageType = "hello_ack"
	MsgProgress MessageType = "progress"
	MsgCancel   MessageType = "cancel"
)

// Structured error codes (stable, additive).
const (
	ErrCodeInvalid      = "invalid_request"
	ErrCodeNotConnected = "extension_not_connected"
	ErrCodeTimeout      = "timeout"
	ErrCodeCanceled     = "canceled"
	ErrCodeUnsupported  = "unsupported"
	ErrCodeInternal     = "internal_error"
	ErrCodeDenied       = "permission_denied"
	ErrCodeDisconnected = "disconnected"
	ErrCodeConflict     = "conflict"
)

// ErrorInfo is a structured error payload.
type ErrorInfo struct {
	Code    string      `json:"code,omitempty"`
	Message string      `json:"message"`
	Details interface{} `json:"details,omitempty"`
}

// Message is the top-level envelope for all WebSocket communication.
type Message struct {
	ID        string      `json:"id,omitempty"`
	RequestID string      `json:"requestId,omitempty"`
	Type      MessageType `json:"type"`
	Timestamp int64       `json:"timestamp,omitempty"`
	Version   int         `json:"version,omitempty"`
	Seq       int64       `json:"seq,omitempty"`
}

// Capabilities describes supported commands/features.
type Capabilities struct {
	Commands      []string `json:"commands,omitempty"`
	Events        []string `json:"events,omitempty"`
	TabGroups     bool     `json:"tabGroups,omitempty"`
	Debugger      bool     `json:"debugger,omitempty"`
	Downloads     bool     `json:"downloads,omitempty"`
	Alarms        bool     `json:"alarms,omitempty"`
	Notifications bool     `json:"notifications,omitempty"`
	MV            int      `json:"manifestVersion,omitempty"`
	Browser       string   `json:"browser,omitempty"`
	Platform      string   `json:"platform,omitempty"`
}

// Hello is exchanged on connect (both directions).
type Hello struct {
	ID           string        `json:"id,omitempty"`
	Type         MessageType   `json:"type"`
	Client       string        `json:"client,omitempty"` // "extension" | "aegis"
	Version      int           `json:"version"`
	Capabilities *Capabilities `json:"capabilities,omitempty"`
	ResumeFrom   int64         `json:"resumeFrom,omitempty"` // request event replay from seq
	Token        string        `json:"token,omitempty"`      // optional shared-secret
	Timestamp    int64         `json:"timestamp,omitempty"`
}

// HelloAck acknowledges handshake.
type HelloAck struct {
	ID           string        `json:"id,omitempty"`
	Type         MessageType   `json:"type"`
	Version      int           `json:"version"`
	Capabilities *Capabilities `json:"capabilities,omitempty"`
	OK           bool          `json:"ok"`
	Error        *ErrorInfo    `json:"error,omitempty"`
	ResumeFrom   int64         `json:"resumeFrom,omitempty"`
	LastSeq      int64         `json:"lastSeq,omitempty"`
	Timestamp    int64         `json:"timestamp,omitempty"`
}

// Command is sent from Aegis through the bridge to the extension.
type Command struct {
	ID        string          `json:"id"`
	RequestID string          `json:"requestId,omitempty"`
	Type      MessageType     `json:"type"`
	Command   string          `json:"command"`
	Params    json.RawMessage `json:"params,omitempty"`
	Timeout   int64           `json:"timeout,omitempty"` // milliseconds, 0 = default
	TabID     int             `json:"tabId,omitempty"`
	Timestamp int64           `json:"timestamp,omitempty"`
	Version   int             `json:"version,omitempty"`
}

// Result is returned from the extension through the bridge to Aegis.
type Result struct {
	ID        string          `json:"id"`
	RequestID string          `json:"requestId,omitempty"`
	Type      MessageType     `json:"type"`
	Success   bool            `json:"success"`
	Data      json.RawMessage `json:"data,omitempty"`
	Error     string          `json:"error,omitempty"`    // legacy/simple
	Err       *ErrorInfo      `json:"err,omitempty"`      // structured
	Progress  bool            `json:"progress,omitempty"` // streaming partial
	Timestamp int64           `json:"timestamp,omitempty"`
	Version   int             `json:"version,omitempty"`
}

// Event is an unsolicited message from the extension.
type Event struct {
	ID        string          `json:"id,omitempty"`
	Type      MessageType     `json:"type"`
	Event     string          `json:"event"`
	Data      json.RawMessage `json:"data,omitempty"`
	Seq       int64           `json:"seq,omitempty"`
	Timestamp int64           `json:"timestamp,omitempty"`
	Version   int             `json:"version,omitempty"`
}

// Progress is a streaming progress update for a request.
type Progress struct {
	ID        string          `json:"id"`
	RequestID string          `json:"requestId,omitempty"`
	Type      MessageType     `json:"type"`
	Data      json.RawMessage `json:"data,omitempty"`
	Message   string          `json:"message,omitempty"`
	Timestamp int64           `json:"timestamp,omitempty"`
}

// Cancel requests cancellation of an in-flight command.
type Cancel struct {
	ID        string      `json:"id,omitempty"`
	RequestID string      `json:"requestId,omitempty"` // target
	TargetID  string      `json:"targetId,omitempty"`  // alias for target
	Type      MessageType `json:"type"`
	Timestamp int64       `json:"timestamp,omitempty"`
}

// Ping is a keepalive message.
type Ping struct {
	ID        string      `json:"id,omitempty"`
	Type      MessageType `json:"type"`
	Timestamp int64       `json:"timestamp,omitempty"`
}

// Pong is the response to a ping.
type Pong struct {
	ID        string      `json:"id,omitempty"`
	Type      MessageType `json:"type"`
	Timestamp int64       `json:"timestamp,omitempty"`
}

// ErrorMessage is sent when a protocol-level error occurs.
type ErrorMessage struct {
	ID        string      `json:"id,omitempty"`
	RequestID string      `json:"requestId,omitempty"`
	Type      MessageType `json:"type"`
	Error     string      `json:"error,omitempty"` // legacy/simple
	Err       *ErrorInfo  `json:"err,omitempty"`
	Code      int         `json:"code,omitempty"` // legacy
	Timestamp int64       `json:"timestamp,omitempty"`
}

// Command names used by the extension.
const (
	CmdNavigate         = "navigate"
	CmdGoBack           = "goBack"
	CmdGoForward        = "goForward"
	CmdReload           = "reload"
	CmdGetCurrentURL    = "getCurrentUrl"
	CmdGetTitle         = "getTitle"
	CmdListTabs         = "listTabs"
	CmdNewTab           = "newTab"
	CmdCloseTab         = "closeTab"
	CmdSwitchTab        = "switchTab"
	CmdGetTabInfo       = "getTabInfo"
	CmdQuerySelector    = "querySelector"
	CmdQuerySelectorAll = "querySelectorAll"
	CmdGetElementText   = "getElementText"
	CmdGetElementAttr   = "getElementAttribute"
	CmdGetElementHTML   = "getElementHtml"
	CmdClick            = "click"
	CmdDoubleClick      = "doubleClick"
	CmdRightClick       = "rightClick"
	CmdHover            = "hover"
	CmdType             = "type"
	CmdFill             = "fill"
	CmdClear            = "clear"
	CmdPress            = "press"
	CmdSelect           = "select"
	CmdScroll           = "scroll"
	CmdScrollIntoView   = "scrollIntoView"
	CmdWaitForSelector  = "waitForSelector"
	CmdWaitForNav       = "waitForNavigation"
	CmdWaitForLoad      = "waitForLoad"
	CmdWaitForIdle      = "waitForIdle"
	CmdEvaluate         = "evaluate"
	CmdEvaluateAll      = "evaluateAll"
	CmdScreenshot       = "screenshot"
	CmdScreenshotElem   = "screenshotElement"
	CmdCaptureVisible   = "captureVisibleTab"
	CmdGetCookies       = "getCookies"
	CmdSetCookie        = "setCookie"
	CmdDeleteCookie     = "deleteCookie"
	CmdClearCookies     = "clearCookies"
	CmdGetLocalStorage  = "getLocalStorage"
	CmdSetLocalStorage  = "setLocalStorage"
	CmdGetSessionStore  = "getSessionStorage"
	CmdSetSessionStore  = "setSessionStorage"
	CmdSwitchFrame      = "switchFrame"
	CmdSwitchMain       = "switchMain"
	CmdAcceptDialog     = "acceptDialog"
	CmdDismissDialog    = "dismissDialog"
	CmdExtractData      = "extractData"
	CmdFocus            = "focus"
	CmdBlur             = "blur"

	// Phase 0+ additions (additive)
	CmdHello  = "hello"
	CmdCancel = "cancel"

	// Phase 1 observability (capability-gated)
	CmdDebugAttach       = "debug.attach"
	CmdDebugDetach       = "debug.detach"
	CmdDebugGetConsole   = "debug.getConsole"
	CmdDebugGetNetwork   = "debug.getNetwork"
	CmdDebugGetPageState = "debug.getPageState"
	CmdPageSnapshot      = "page.snapshot"

	// Phase 2 multi-tab/groups
	CmdCreateTabGroup  = "createTabGroup"
	CmdAddTabToGroup   = "addTabToGroup"
	CmdRemoveFromGroup = "removeTabFromGroup"
	CmdListTabGroups   = "listTabGroups"
	CmdFocusTabGroup   = "focusTabGroup"
	CmdListFrames      = "listFrames"

	// Phase 3 recording/workflows
	CmdRecordStart    = "record.start"
	CmdRecordStop     = "record.stop"
	CmdRecordPause    = "record.pause"
	CmdWorkflowRun    = "workflow.run"
	CmdWorkflowList   = "workflow.list"
	CmdWorkflowGet    = "workflow.get"
	CmdWorkflowSave   = "workflow.save"
	CmdWorkflowDelete = "workflow.delete"

	// Phase 4 scheduling/tasks
	CmdScheduleCreate = "schedule.create"
	CmdScheduleList   = "schedule.list"
	CmdScheduleDelete = "schedule.delete"
	CmdScheduleRuns   = "schedule.runs"

	// Phase 5 downloads/uploads/visuals
	CmdDownloadWait       = "download.wait"
	CmdDownloadList       = "download.list"
	CmdUploadFile         = "upload.file"
	CmdScreenshotFullPage = "screenshot.fullPage"

	// Phase 6 policy
	CmdPolicyGet       = "policy.get"
	CmdPolicySet       = "policy.set"
	CmdApprovalRespond = "approval.respond"
	CmdAuditList       = "audit.list"
)

// Event names emitted by the extension.
const (
	EventTabCreated   = "tabCreated"
	EventTabClosed    = "tabClosed"
	EventTabUpdated   = "tabUpdated"
	EventNavigated    = "navigated"
	EventDialogOpened = "dialogOpened"
	EventConsoleError = "consoleError"
	EventConsole      = "console"
	EventNetwork      = "network"
	EventPageError    = "pageError"
	EventDownload     = "download"
	EventRecording    = "recording"
	EventTask         = "task"
	EventPermission   = "permissionPrompt"
)

// DefaultCommandTimeout is the default time to wait for a command response.
const DefaultCommandTimeout = 30 * time.Second

func nowMs() int64 { return time.Now().UnixMilli() }

var idCounter uint64

// NewCommand creates a new command with a generated ID and timestamp.
func NewCommand(command string, params json.RawMessage, tabID int) *Command {
	id := generateID()
	return &Command{
		ID:        id,
		RequestID: id,
		Type:      MsgCommand,
		Command:   command,
		Params:    params,
		TabID:     tabID,
		Timestamp: nowMs(),
		Version:   ProtocolVersion,
	}
}

// NewResult creates a result message for a given command ID.
func NewResult(id string, success bool, data json.RawMessage, errMsg string) *Result {
	r := &Result{
		ID:        id,
		RequestID: id,
		Type:      MsgResult,
		Success:   success,
		Data:      data,
		Timestamp: nowMs(),
		Version:   ProtocolVersion,
	}
	if errMsg != "" {
		r.Error = errMsg
		r.Err = &ErrorInfo{Code: ErrCodeInternal, Message: errMsg}
		if !success && (errMsg == "extension not connected" || errMsg == "bridge server shutting down") {
			r.Err.Code = ErrCodeNotConnected
		}
	}
	return r
}

// NewStructuredResult creates a result with structured error info.
func NewStructuredResult(id string, success bool, data json.RawMessage, err *ErrorInfo) *Result {
	r := &Result{
		ID:        id,
		RequestID: id,
		Type:      MsgResult,
		Success:   success,
		Data:      data,
		Err:       err,
		Timestamp: nowMs(),
		Version:   ProtocolVersion,
	}
	if err != nil {
		r.Error = err.Message
	}
	return r
}

// NewEvent creates an unsolicited event message.
func NewEvent(event string, data json.RawMessage) *Event {
	return &Event{
		ID:        generateID(),
		Type:      MsgEvent,
		Event:     event,
		Data:      data,
		Timestamp: nowMs(),
		Version:   ProtocolVersion,
	}
}

// NewProgress creates a progress message for a request.
func NewProgress(requestID, message string, data json.RawMessage) *Progress {
	return &Progress{
		ID:        generateID(),
		RequestID: requestID,
		Type:      MsgProgress,
		Data:      data,
		Message:   message,
		Timestamp: nowMs(),
	}
}

// CorrelationID returns the best correlation id for a message/result.
func CorrelationID(id, requestID string) string {
	if requestID != "" {
		return requestID
	}
	return id
}

// ParseMessage parses raw bytes into the appropriate message type.
func ParseMessage(data []byte) (interface{}, error) {
	var envelope Message
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, err
	}
	switch envelope.Type {
	case MsgCommand:
		var cmd Command
		if err := json.Unmarshal(data, &cmd); err != nil {
			return nil, err
		}
		if cmd.RequestID == "" {
			cmd.RequestID = cmd.ID
		}
		if cmd.ID == "" {
			cmd.ID = cmd.RequestID
		}
		return &cmd, nil
	case MsgResult:
		var res Result
		if err := json.Unmarshal(data, &res); err != nil {
			return nil, err
		}
		if res.RequestID == "" {
			res.RequestID = res.ID
		}
		if res.ID == "" {
			res.ID = res.RequestID
		}
		return &res, nil
	case MsgEvent:
		var evt Event
		if err := json.Unmarshal(data, &evt); err != nil {
			return nil, err
		}
		return &evt, nil
	case MsgPing:
		var p Ping
		if err := json.Unmarshal(data, &p); err != nil {
			return nil, err
		}
		return &p, nil
	case MsgPong:
		var p Pong
		if err := json.Unmarshal(data, &p); err != nil {
			return nil, err
		}
		return &p, nil
	case MsgError:
		var e ErrorMessage
		if err := json.Unmarshal(data, &e); err != nil {
			return nil, err
		}
		if e.RequestID == "" {
			e.RequestID = e.ID
		}
		return &e, nil
	case MsgHello:
		var h Hello
		if err := json.Unmarshal(data, &h); err != nil {
			return nil, err
		}
		return &h, nil
	case MsgHelloAck:
		var h HelloAck
		if err := json.Unmarshal(data, &h); err != nil {
			return nil, err
		}
		return &h, nil
	case MsgProgress:
		var p Progress
		if err := json.Unmarshal(data, &p); err != nil {
			return nil, err
		}
		if p.RequestID == "" {
			p.RequestID = p.ID
		}
		return &p, nil
	case MsgCancel:
		var c Cancel
		if err := json.Unmarshal(data, &c); err != nil {
			return nil, err
		}
		if c.RequestID == "" {
			c.RequestID = c.TargetID
		}
		return &c, nil
	default:
		return &envelope, nil
	}
}

// generateID produces a unique ID for messages.
func generateID() string {
	n := atomic.AddUint64(&idCounter, 1)
	b := make([]byte, 4)
	if _, err := rand.Read(b); err == nil {
		return time.Now().Format("20060102150405.000") + "-" + hex.EncodeToString(b) + "-" + uitoa(n)
	}
	return time.Now().Format("20060102150405.000000000") + "-" + uitoa(n)
}

func uitoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
