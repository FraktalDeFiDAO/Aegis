package connector

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/coppertone/bug-hunter/app/aegis/internal/connector/bridge"
	"github.com/coppertone/bug-hunter/app/aegis/internal/session"
)

// SessionBridge extends the bridge's SessionManager with Aegis session file integration.
type SessionBridge struct {
	connector *Connector
	bridge    *bridge.SessionManager
}

// NewSessionBridge creates a session bridge for the connector.
func NewSessionBridge(connector *Connector) *SessionBridge {
	return &SessionBridge{
		connector: connector,
		bridge:    bridge.NewSessionManager(),
	}
}

// ExportFromBrowser captures the current browser state and saves to an Aegis session file.
func (sb *SessionBridge) ExportFromBrowser(mgr *session.SessionManager) error {
	page, err := sb.connector.activePage()
	if err != nil {
		return fmt.Errorf("get active page: %w", err)
	}
	return mgr.Save(page)
}

// ImportToBrowser loads an Aegis session file into the user's browser.
func (sb *SessionBridge) ImportToBrowser(mgr *session.SessionManager) error {
	page, err := sb.connector.activePage()
	if err != nil {
		return fmt.Errorf("get active page: %w", err)
	}
	return mgr.Load(page)
}

// CaptureCookies captures cookies from all tabs.
func (sb *SessionBridge) CaptureCookies() error {
	result, err := sb.connector.sendCommand(bridge.CmdListTabs, nil, 0)
	if err != nil {
		return err
	}

	var data struct {
		Tabs []struct {
			ID  int    `json:"id"`
			URL string `json:"url"`
		} `json:"tabs"`
	}
	if err := json.Unmarshal(result.Data, &data); err != nil {
		return err
	}

	for _, tab := range data.Tabs {
		cookieResult, err := sb.connector.sendCommand(bridge.CmdGetCookies, map[string]interface{}{
			"urls": []string{tab.URL},
		}, tab.ID)
		if err != nil {
			continue
		}

		var cookieData struct {
			Cookies []*bridge.CookieData `json:"cookies"`
		}
		if err := json.Unmarshal(cookieResult.Data, &cookieData); err != nil {
			continue
		}

		sb.bridge.UpdateCookies(tab.ID, cookieData.Cookies)
	}

	return nil
}

// RestoreCookies restores cookies to all tabs.
func (sb *SessionBridge) RestoreCookies() error {
	result, err := sb.connector.sendCommand(bridge.CmdListTabs, nil, 0)
	if err != nil {
		return err
	}

	var data struct {
		Tabs []struct {
			ID int `json:"id"`
		} `json:"tabs"`
	}
	if err := json.Unmarshal(result.Data, &data); err != nil {
		return err
	}

	for _, tab := range data.Tabs {
		session := sb.bridge.GetSession(tab.ID)
		for _, cookie := range session.Cookies {
			params := map[string]interface{}{
				"name":     cookie.Name,
				"value":    cookie.Value,
				"domain":   cookie.Domain,
				"path":     cookie.Path,
				"secure":   cookie.Secure,
				"httpOnly": cookie.HttpOnly,
			}
			if cookie.Expires > 0 {
				params["expires"] = cookie.Expires
			}
			sb.connector.sendCommand(bridge.CmdSetCookie, params, tab.ID)
		}
	}

	return nil
}

// CaptureLocalStorage captures localStorage from a tab.
func (sb *SessionBridge) CaptureLocalStorage(tabID int) error {
	result, err := sb.connector.sendCommand(bridge.CmdGetLocalStorage, nil, tabID)
	if err != nil {
		return err
	}

	var data struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(result.Data, &data); err != nil {
		return err
	}

	sb.bridge.UpdateLocalStorage(tabID, data.Data)
	return nil
}

// RestoreLocalStorage restores localStorage to a tab.
func (sb *SessionBridge) RestoreLocalStorage(tabID int) error {
	session := sb.bridge.GetSession(tabID)
	if len(session.LocalStorage) == 0 {
		return nil
	}

	result, err := sb.connector.sendCommand(bridge.CmdSetLocalStorage, map[string]interface{}{
		"data": session.LocalStorage,
	}, tabID)
	if err != nil {
		return err
	}
	if !result.Success {
		return fmt.Errorf("set localStorage: %s", result.Error)
	}
	return nil
}

// CaptureSessionStorage captures sessionStorage from a tab.
func (sb *SessionBridge) CaptureSessionStorage(tabID int) error {
	result, err := sb.connector.sendCommand(bridge.CmdGetSessionStore, nil, tabID)
	if err != nil {
		return err
	}

	var data struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(result.Data, &data); err != nil {
		return err
	}

	sb.bridge.UpdateSessionStorage(tabID, data.Data)
	return nil
}

// RestoreSessionStorage restores sessionStorage to a tab.
func (sb *SessionBridge) RestoreSessionStorage(tabID int) error {
	session := sb.bridge.GetSession(tabID)
	if len(session.SessionStorage) == 0 {
		return nil
	}

	result, err := sb.connector.sendCommand(bridge.CmdSetSessionStore, map[string]interface{}{
		"data": session.SessionStorage,
	}, tabID)
	if err != nil {
		return err
	}
	if !result.Success {
		return fmt.Errorf("set sessionStorage: %s", result.Error)
	}
	return nil
}

// ExportAll exports all session data as JSON.
func (sb *SessionBridge) ExportAll() ([]byte, error) {
	if err := sb.CaptureCookies(); err != nil {
		return nil, err
	}
	return sb.bridge.ExportAll()
}

// ImportAll imports session data from JSON and restores to browser.
func (sb *SessionBridge) ImportAll(data []byte) error {
	if err := sb.bridge.ImportAll(data); err != nil {
		return err
	}
	return sb.RestoreCookies()
}

// SessionData holds all session state for serialization.
type SessionData struct {
	Cookies   map[int][]*bridge.CookieData `json:"cookies"`
	Local     map[int]map[string]string    `json:"localStorage"`
	Session   map[int]map[string]string    `json:"sessionStorage"`
	Timestamp time.Time                    `json:"timestamp"`
}
