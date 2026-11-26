package bridge

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Handler processes commands from Aegis and routes them to the extension.
// It also manages extension-side state like active tab, cookies, etc.
type Handler struct {
	server  *Server
	logger  *slog.Logger
	state   *HandlerState
	stateMu sync.RWMutex
}

// HandlerState tracks the state managed by the bridge handler.
type HandlerState struct {
	ActiveTabID int              `json:"activeTabId"`
	Tabs        map[int]*TabInfo `json:"tabs"`
	BrowserInfo *BrowserInfo     `json:"browserInfo,omitempty"`
}

// TabInfo holds metadata about a browser tab.
type TabInfo struct {
	ID    int    `json:"id"`
	URL   string `json:"url"`
	Title string `json:"title"`
}

// BrowserInfo holds information about the connected browser.
type BrowserInfo struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Platform string `json:"platform"`
}

// NewHandler creates a new command handler for the bridge server.
func NewHandler(server *Server, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		server: server,
		logger: logger,
		state: &HandlerState{
			Tabs: make(map[int]*TabInfo),
		},
	}
}

// HandleCommand processes a command and returns the result.
// This is used when Aegis sends commands directly through the handler
// rather than through the server's SendCommand method.
func (h *Handler) HandleCommand(cmd *Command) *Result {
	start := time.Now()

	h.logger.Debug("handling command",
		"command", cmd.Command,
		"id", cmd.ID,
		"tabId", cmd.TabID,
	)

	// Validate command
	if cmd.Command == "" {
		return NewResult(cmd.ID, false, nil, "empty command")
	}

	// Route command to extension via server
	result, err := h.server.SendCommand(cmd)
	if err != nil {
		h.logger.Error("command failed",
			"command", cmd.Command,
			"error", err,
			"duration", time.Since(start),
		)
		return NewResult(cmd.ID, false, nil, fmt.Sprintf("command failed: %v", err))
	}

	// Update state based on result
	h.updateStateFromResult(cmd, result)

	h.logger.Debug("command completed",
		"command", cmd.Command,
		"success", result.Success,
		"duration", time.Since(start),
	)

	return result
}

// updateStateFromResult updates the handler state based on command results.
func (h *Handler) updateStateFromResult(cmd *Command, result *Result) {
	if !result.Success {
		return
	}

	h.stateMu.Lock()
	defer h.stateMu.Unlock()

	switch cmd.Command {
	case CmdNavigate, CmdReload, CmdGoBack, CmdGoForward:
		// These change the current page, may need tab info update
		if cmd.TabID > 0 {
			if tab, ok := h.state.Tabs[cmd.TabID]; ok {
				// Extract URL from result if available
				var data struct {
					URL string `json:"url"`
				}
				if json.Unmarshal(result.Data, &data) == nil && data.URL != "" {
					tab.URL = data.URL
				}
			}
		}

	case CmdNewTab:
		var data struct {
			TabID int `json:"tabId"`
		}
		if json.Unmarshal(result.Data, &data) == nil && data.TabID > 0 {
			h.state.Tabs[data.TabID] = &TabInfo{ID: data.TabID}
			h.state.ActiveTabID = data.TabID
		}

	case CmdCloseTab:
		if cmd.TabID > 0 {
			delete(h.state.Tabs, cmd.TabID)
			if h.state.ActiveTabID == cmd.TabID {
				// Reset to first available tab
				for id := range h.state.Tabs {
					h.state.ActiveTabID = id
					break
				}
			}
		}

	case CmdSwitchTab:
		var data struct {
			TabID int `json:"tabId"`
		}
		if json.Unmarshal(cmd.Params, &data) == nil {
			h.state.ActiveTabID = data.TabID
		}

	case CmdGetTabInfo:
		var data struct {
			TabID int    `json:"tabId"`
			URL   string `json:"url"`
			Title string `json:"title"`
		}
		if json.Unmarshal(result.Data, &data) == nil {
			tabID := data.TabID
			if tabID == 0 {
				tabID = h.state.ActiveTabID
			}
			if tab, ok := h.state.Tabs[tabID]; ok {
				tab.URL = data.URL
				tab.Title = data.Title
			} else {
				h.state.Tabs[tabID] = &TabInfo{
					ID:    tabID,
					URL:   data.URL,
					Title: data.Title,
				}
			}
		}
	}
}

// GetState returns a copy of the current handler state.
func (h *Handler) GetState() *HandlerState {
	h.stateMu.RLock()
	defer h.stateMu.RUnlock()

	// Deep copy
	state := &HandlerState{
		ActiveTabID: h.state.ActiveTabID,
		Tabs:        make(map[int]*TabInfo, len(h.state.Tabs)),
	}
	for id, tab := range h.state.Tabs {
		state.Tabs[id] = &TabInfo{
			ID:    tab.ID,
			URL:   tab.URL,
			Title: tab.Title,
		}
	}
	if h.state.BrowserInfo != nil {
		state.BrowserInfo = &BrowserInfo{
			Name:     h.state.BrowserInfo.Name,
			Version:  h.state.BrowserInfo.Version,
			Platform: h.state.BrowserInfo.Platform,
		}
	}
	return state
}

// SetBrowserInfo updates the browser information from the extension.
func (h *Handler) SetBrowserInfo(info *BrowserInfo) {
	h.stateMu.Lock()
	defer h.stateMu.Unlock()
	h.state.BrowserInfo = info
}

// SetActiveTab updates the active tab ID.
func (h *Handler) SetActiveTab(tabID int) {
	h.stateMu.Lock()
	defer h.stateMu.Unlock()
	h.state.ActiveTabID = tabID
}

// GetActiveTab returns the active tab ID.
func (h *Handler) GetActiveTab() int {
	h.stateMu.RLock()
	defer h.stateMu.RUnlock()
	return h.state.ActiveTabID
}

// BuildCommand is a helper to create commands with common parameters.
func BuildCommand(command string, params interface{}, tabID int) (*Command, error) {
	var rawParams json.RawMessage
	if params != nil {
		var err error
		rawParams, err = json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("marshal params: %w", err)
		}
	}
	return NewCommand(command, rawParams, tabID), nil
}

// MustBuildCommand is like BuildCommand but panics on error.
func MustBuildCommand(command string, params interface{}, tabID int) *Command {
	cmd, err := BuildCommand(command, params, tabID)
	if err != nil {
		panic(err)
	}
	return cmd
}

// NavigateCommand creates a navigate command.
func NavigateCommand(url string, tabID int) *Command {
	return MustBuildCommand(CmdNavigate, map[string]string{"url": url}, tabID)
}

// ClickCommand creates a click command.
func ClickCommand(selector string, tabID int) *Command {
	return MustBuildCommand(CmdClick, map[string]string{"selector": selector}, tabID)
}

// TypeCommand creates a type command.
func TypeCommand(selector string, value string, tabID int) *Command {
	return MustBuildCommand(CmdType, map[string]string{
		"selector": selector,
		"value":    value,
	}, tabID)
}

// EvaluateCommand creates an evaluate command.
func EvaluateCommand(script string, tabID int) *Command {
	return MustBuildCommand(CmdEvaluate, map[string]string{"script": script}, tabID)
}

// ScreenshotCommand creates a screenshot command.
func ScreenshotCommand(fullPage bool, tabID int) *Command {
	return MustBuildCommand(CmdScreenshot, map[string]bool{"fullPage": fullPage}, tabID)
}

// GetCookiesCommand creates a getCookies command.
func GetCookiesCommand(urls []string, tabID int) *Command {
	return MustBuildCommand(CmdGetCookies, map[string][]string{"urls": urls}, tabID)
}

// SetCookieCommand creates a setCookie command.
func SetCookieCommand(name, value, domain, path string, tabID int) *Command {
	return MustBuildCommand(CmdSetCookie, map[string]string{
		"name":   name,
		"value":  value,
		"domain": domain,
		"path":   path,
	}, tabID)
}
