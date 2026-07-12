package validator

import (
	"net/http"
	"testing"
)

func TestValidateURL(t *testing.T) {
	tests := []struct {
		url     string
		wantErr bool
	}{
		{"https://google.com", false},
		{"http://localhost:8080", false},
		{"ftp://insecure.com", true},
		{"not-a-url", true},
		{"", true},
		{"https://", true},
		{"javascript:alert(1)", true},
		{"data:text/html,<html>", true},
		{"//relative-url", true},
	}

	for _, tt := range tests {
		err := ValidateURL(tt.url)
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidateURL(%s) error = %v, wantErr %v", tt.url, err, tt.wantErr)
		}
	}
}

func TestValidateTargetURL(t *testing.T) {
	tests := []struct {
		url     string
		wantErr bool
	}{
		{"https://example.com", false},
		{"http://localhost:8080", true},
		{"http://127.0.0.1", true},
		{"http://10.0.0.1", true},
		{"http://192.168.1.10", true},
		{"http://172.16.0.5", true},
		{"http://[::1]", true},
		{"https://", true},
	}

	for _, tt := range tests {
		err := ValidateTargetURL(tt.url)
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidateTargetURL(%s) error = %v, wantErr %v", tt.url, err, tt.wantErr)
		}
	}
}

func TestValidateTargetHost(t *testing.T) {
	tests := []struct {
		host    string
		wantErr bool
	}{
		{"example.com", false},
		{"localhost", true},
		{"app.localhost", true},
		{"127.0.0.1", true},
		{"::1", true},
	}

	for _, tt := range tests {
		err := ValidateTargetHost(tt.host)
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidateTargetHost(%s) error = %v, wantErr %v", tt.host, err, tt.wantErr)
		}
	}
}

func TestRedirectPolicyRejectsPrivateRedirectTarget(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1/admin", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	if err := RedirectPolicy(false)(req, nil); err == nil {
		t.Fatal("expected redirect policy to reject private target")
	}
}

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"safe.html", "safe.html"},
		{"../../etc/passwd", "____etc_passwd"},
		{"file$name|", "file_name_"},
		{"", ""},
		{"/root/path", "_root_path"},
		{"test&dir|pipe", "test_dir_pipe"},
	}

	for _, tt := range tests {
		got := SanitizeFilename(tt.input)
		if got != tt.expected {
			t.Errorf("SanitizeFilename(%s) = %s; want %s", tt.input, got, tt.expected)
		}
	}
}
