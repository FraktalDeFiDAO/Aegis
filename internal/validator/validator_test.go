package validator

import "testing"

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
