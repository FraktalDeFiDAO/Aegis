package bridge

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// SessionManager manages browser session state across the bridge.
// It tracks cookies, localStorage, sessionStorage per tab and
// handles import/export for Aegis session files.
type SessionManager struct {
	sessions map[int]*TabSession
	mu       sync.RWMutex
}

// TabSession holds session data for a single tab.
type TabSession struct {
	TabID          int               `json:"tabId"`
	Cookies        []*CookieData     `json:"cookies,omitempty"`
	LocalStorage   map[string]string `json:"localStorage,omitempty"`
	SessionStorage map[string]string `json:"sessionStorage,omitempty"`
	LastUpdated    time.Time         `json:"lastUpdated"`
}

// CookieData represents a browser cookie.
type CookieData struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain"`
	Path     string `json:"path"`
	Secure   bool   `json:"secure"`
	HttpOnly bool   `json:"httpOnly"`
	SameSite string `json:"sameSite,omitempty"`
	Expires  int64  `json:"expires,omitempty"`
}

// StorageData holds localStorage or sessionStorage data.
type StorageData struct {
	Origin string            `json:"origin"`
	Data   map[string]string `json:"data"`
}

// NewSessionManager creates a new session manager.
func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[int]*TabSession),
	}
}

// GetSession returns the session for a tab, or creates a new one.
func (sm *SessionManager) GetSession(tabID int) *TabSession {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, ok := sm.sessions[tabID]
	if !ok {
		session = &TabSession{
			TabID:          tabID,
			Cookies:        make([]*CookieData, 0),
			LocalStorage:   make(map[string]string),
			SessionStorage: make(map[string]string),
			LastUpdated:    time.Now(),
		}
		sm.sessions[tabID] = session
	}
	return session
}

// UpdateCookies updates the cookies for a tab.
func (sm *SessionManager) UpdateCookies(tabID int, cookies []*CookieData) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, ok := sm.sessions[tabID]
	if !ok {
		session = &TabSession{
			TabID:          tabID,
			Cookies:        cookies,
			LocalStorage:   make(map[string]string),
			SessionStorage: make(map[string]string),
			LastUpdated:    time.Now(),
		}
		sm.sessions[tabID] = session
		return
	}

	session.Cookies = cookies
	session.LastUpdated = time.Now()
}

// UpdateLocalStorage updates the localStorage for a tab.
func (sm *SessionManager) UpdateLocalStorage(tabID int, data map[string]string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, ok := sm.sessions[tabID]
	if !ok {
		session = &TabSession{
			TabID:          tabID,
			Cookies:        make([]*CookieData, 0),
			LocalStorage:   data,
			SessionStorage: make(map[string]string),
			LastUpdated:    time.Now(),
		}
		sm.sessions[tabID] = session
		return
	}

	session.LocalStorage = data
	session.LastUpdated = time.Now()
}

// UpdateSessionStorage updates the sessionStorage for a tab.
func (sm *SessionManager) UpdateSessionStorage(tabID int, data map[string]string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, ok := sm.sessions[tabID]
	if !ok {
		session = &TabSession{
			TabID:          tabID,
			Cookies:        make([]*CookieData, 0),
			LocalStorage:   make(map[string]string),
			SessionStorage: data,
			LastUpdated:    time.Now(),
		}
		sm.sessions[tabID] = session
		return
	}

	session.SessionStorage = data
	session.LastUpdated = time.Now()
}

// RemoveSession removes the session for a tab.
func (sm *SessionManager) RemoveSession(tabID int) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.sessions, tabID)
}

// ExportAll exports all session data as JSON.
func (sm *SessionManager) ExportAll() ([]byte, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	sessions := make([]*TabSession, 0, len(sm.sessions))
	for _, session := range sm.sessions {
		sessions = append(sessions, session)
	}

	return json.Marshal(sessions)
}

// ImportAll imports session data from JSON.
func (sm *SessionManager) ImportAll(data []byte) error {
	var sessions []*TabSession
	if err := json.Unmarshal(data, &sessions); err != nil {
		return fmt.Errorf("unmarshal sessions: %w", err)
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	for _, session := range sessions {
		sm.sessions[session.TabID] = session
	}

	return nil
}

// ExportCookies exports cookies for a specific tab as JSON.
func (sm *SessionManager) ExportCookies(tabID int) ([]byte, error) {
	sm.mu.RLock()
	session, ok := sm.sessions[tabID]
	sm.mu.RUnlock()

	if !ok {
		return json.Marshal([]*CookieData{})
	}
	return json.Marshal(session.Cookies)
}

// ImportCookies imports cookies for a specific tab from JSON.
func (sm *SessionManager) ImportCookies(tabID int, data []byte) error {
	var cookies []*CookieData
	if err := json.Unmarshal(data, &cookies); err != nil {
		return fmt.Errorf("unmarshal cookies: %w", err)
	}

	sm.UpdateCookies(tabID, cookies)
	return nil
}

// ExportLocalStorage exports localStorage for a specific tab as JSON.
func (sm *SessionManager) ExportLocalStorage(tabID int) ([]byte, error) {
	sm.mu.RLock()
	session, ok := sm.sessions[tabID]
	sm.mu.RUnlock()

	if !ok {
		return json.Marshal(map[string]string{})
	}
	return json.Marshal(session.LocalStorage)
}

// ImportLocalStorage imports localStorage for a specific tab from JSON.
func (sm *SessionManager) ImportLocalStorage(tabID int, data []byte) error {
	var storage map[string]string
	if err := json.Unmarshal(data, &storage); err != nil {
		return fmt.Errorf("unmarshal localStorage: %w", err)
	}

	sm.UpdateLocalStorage(tabID, storage)
	return nil
}

// ExportSessionStorage exports sessionStorage for a specific tab as JSON.
func (sm *SessionManager) ExportSessionStorage(tabID int) ([]byte, error) {
	sm.mu.RLock()
	session, ok := sm.sessions[tabID]
	sm.mu.RUnlock()

	if !ok {
		return json.Marshal(map[string]string{})
	}
	return json.Marshal(session.SessionStorage)
}

// ImportSessionStorage imports sessionStorage for a specific tab from JSON.
func (sm *SessionManager) ImportSessionStorage(tabID int, data []byte) error {
	var storage map[string]string
	if err := json.Unmarshal(data, &storage); err != nil {
		return fmt.Errorf("unmarshal sessionStorage: %w", err)
	}

	sm.UpdateSessionStorage(tabID, storage)
	return nil
}

// MergeCookies merges cookies from source into the session for a tab.
// Existing cookies with the same name+domain+path are overwritten.
func (sm *SessionManager) MergeCookies(tabID int, source []*CookieData) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, ok := sm.sessions[tabID]
	if !ok {
		session = &TabSession{
			TabID:          tabID,
			Cookies:        source,
			LocalStorage:   make(map[string]string),
			SessionStorage: make(map[string]string),
			LastUpdated:    time.Now(),
		}
		sm.sessions[tabID] = session
		return
	}

	// Build index of existing cookies
	type cookieKey struct {
		Name   string
		Domain string
		Path   string
	}
	existing := make(map[cookieKey]int, len(session.Cookies))
	for i, c := range session.Cookies {
		existing[cookieKey{c.Name, c.Domain, c.Path}] = i
	}

	// Merge
	for _, src := range source {
		key := cookieKey{src.Name, src.Domain, src.Path}
		if idx, ok := existing[key]; ok {
			session.Cookies[idx] = src
		} else {
			session.Cookies = append(session.Cookies, src)
			existing[key] = len(session.Cookies) - 1
		}
	}

	session.LastUpdated = time.Now()
}

// TabCount returns the number of tracked tabs.
func (sm *SessionManager) TabCount() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.sessions)
}
