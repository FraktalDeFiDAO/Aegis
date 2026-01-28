package session

import (
	"path/filepath"
	"testing"
)

func TestSessionManagerInitialization(t *testing.T) {
	tempDir := t.TempDir()
	sessionPath := filepath.Join(tempDir, "session.json")
	
	key := []byte("01234567890123456789012345678901")
	mgr := NewSessionManager(sessionPath, key)
	
	if mgr.Path() != sessionPath {
		t.Errorf("Expected path to be '%s', got '%s'", sessionPath, mgr.Path())
	}
}

func TestSessionManagerWithEmptyPath(t *testing.T) {
	mgr := NewSessionManager("", nil)

	expectedPath := "session_lock.json"
	if mgr.Path() != expectedPath {
		t.Errorf("Expected default path to be '%s', got '%s'", expectedPath, mgr.Path())
	}
}

func TestEncryptionDecryption(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	data := []byte("secret message")

	encrypted, err := encrypt(data, key)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := decrypt(encrypted, key)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if string(decrypted) != string(data) {
		t.Errorf("Decrypted data mismatch: got %s, want %s", string(decrypted), string(data))
	}

	// Test short ciphertext error branch
	_, err = decrypt([]byte("too short"), key)
	if err == nil {
		t.Error("Expected error for short ciphertext, got nil")
	}
}
