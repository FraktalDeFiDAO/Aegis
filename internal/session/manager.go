// Package session manages browser session state, including cookies and
// local storage, using encrypted persistence.
package session

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/ysmood/gson"
)

// SessionManager handles the marshalling and unmarshalling of browser state
// (cookies, localStorage, sessionStorage) to and from encrypted disk storage.
type SessionManager struct {
	path string
	key  []byte // Encryption key (32 bytes for AES-256)
}

// Path returns the configured storage path for the session file.
func (m *SessionManager) Path() string {
	return m.path
}

// NewSessionManager creates a session manager that persists state to the specified path.
// If path is empty, it defaults to "session_lock.json".
// It requires a 32-byte key for AES-256 encryption.
func NewSessionManager(path string, key []byte) *SessionManager {
	if path == "" {
		path = "session_lock.json"
	}
	return &SessionManager{path: path, key: key}
}

// Save captures the current state of a rod.Page and writes it to disk.
// It includes all accessible cookies, localStorage, and sessionStorage.
func (m *SessionManager) Save(page *rod.Page) error {
	data := sessionLock{}

	// Get cookies for the current frame
	cookies, err := page.Cookies([]string{})
	if err != nil {
		return fmt.Errorf("get cookies: %w", err)
	}
	data.Cookies = proto.CookiesToParams(cookies)

	if data.LocalStorage, err = readStorage(page, "localStorage"); err != nil {
		return fmt.Errorf("dump localStorage: %w", err)
	}
	if data.SessionStorage, err = readStorage(page, "sessionStorage"); err != nil {
		return fmt.Errorf("dump sessionStorage: %w", err)
	}

	return m.write(data)
}

// Load replays the stored session into the provided page. It registers scripts that
// hydrate the storage objects before every navigation.
func (m *SessionManager) Load(page *rod.Page) error {
	data, err := m.read()
	if err != nil {
		return err
	}

	if len(data.Cookies) > 0 {
		// Set cookies for the current frame
		for _, cookieParam := range data.Cookies {
			err := page.SetCookies([]*proto.NetworkCookieParam{cookieParam})
			if err != nil {
				return fmt.Errorf("set cookie: %w", err)
			}
		}
	}

	if err := m.hydrateStorage(page, "localStorage", data.LocalStorage); err != nil {
		return err
	}

	if err := m.hydrateStorage(page, "sessionStorage", data.SessionStorage); err != nil {
		return err
	}

	return nil
}

type sessionLock struct {
	Cookies        []*proto.NetworkCookieParam `json:"cookies"`
	LocalStorage   map[string]string           `json:"localStorage"`
	SessionStorage map[string]string           `json:"sessionStorage"`
}

func readStorage(page *rod.Page, storage string) (map[string]string, error) {
	script := fmt.Sprintf(`(() => {
		const store = window.%s;
		if (!store) {
			return {};
		}
		const data = {};
		for (let i = 0; i < store.length; i++) {
			const key = store.key(i);
			data[key] = store.getItem(key);
		}
		return data;
	})()`, storage)

	res, err := page.Evaluate(rod.Eval(script))
	if err != nil {
		return nil, err
	}

	payload, err := page.ObjectToJSON(res)
	if err != nil {
		return nil, err
	}

	return mapFromGson(payload), nil
}

func mapFromGson(value gson.JSON) map[string]string {
	result := map[string]string{}
	for k, v := range value.Map() {
		result[k] = v.Str()
	}
	return result
}

func (m *SessionManager) write(data sessionLock) error {
	dir := filepath.Dir(m.path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create dir %s: %w", dir, err)
		}
	}

	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}

	encrypted, err := encrypt(raw, m.key)
	if err != nil {
		return fmt.Errorf("encrypt session: %w", err)
	}

	return os.WriteFile(m.path, encrypted, 0o600)
}

func (m *SessionManager) read() (sessionLock, error) {
	var data sessionLock

	encrypted, err := os.ReadFile(m.path)
	if err != nil {
		return data, err
	}
	if len(encrypted) == 0 {
		return data, nil
	}

	decrypted, err := decrypt(encrypted, m.key)
	if err != nil {
		return data, fmt.Errorf("decrypt session: %w", err)
	}

	if err := json.Unmarshal(decrypted, &data); err != nil {
		return data, fmt.Errorf("decode session lock: %w", err)
	}

	return data, nil
}

func (m *SessionManager) hydrateStorage(page *rod.Page, name string, values map[string]string) error {
	if len(values) == 0 {
		return nil
	}

	script, err := storageScript(name, values)
	if err != nil {
		return err
	}

	if _, err := page.EvalOnNewDocument(script); err != nil {
		return fmt.Errorf("inject %s: %w", name, err)
	}

	if _, err := page.Evaluate(rod.Eval(script)); err != nil {
		return fmt.Errorf("seed %s: %w", name, err)
	}

	return nil
}

func storageScript(name string, data map[string]string) (string, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("marshal storage %s: %w", name, err)
	}

	return fmt.Sprintf(`(() => {
		const store = window.%s;
		if (!store) {
			return {};
		}
		store.clear();
		const payload = %s;
		for (const [key, value] of Object.entries(payload)) {
			store.setItem(key, value);
		}
	})()`, name, raw), nil
}

func encrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

func decrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
