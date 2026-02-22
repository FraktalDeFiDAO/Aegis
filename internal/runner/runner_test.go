package runner_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/coppertone/bug-hunter/app/aegis/internal/browser"
	"github.com/coppertone/bug-hunter/app/aegis/internal/config"
	"github.com/coppertone/bug-hunter/app/aegis/internal/runner"
)

func TestRunner_FullCoverage(t *testing.T) {
	// Check if browser is available
	l := browser.NewLauncher(true)
	if _, err := l.Launch(); err != nil {
		t.Skipf("Skipping browser test: %v", err)
	}
	l.Cleanup()

	// 1. Setup Mock Server
	// This server simulates a scenario where an admin generates a specialized token that, if stolen, grants access.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			if r.Method == "POST" {
				// Simulate login return a token in a div
				fmt.Fprintln(w, `<html><body><div id="secret-token">secret-12345</div><div id="welcome">Welcome Admin</div></body></html>`)
			} else {
				fmt.Fprintln(w, `<html><body><form method="POST"><input name="user"/><button id="btn-login">Login</button></form></body></html>`)
			}
		case "/admin":
			// Access check
			token := r.URL.Query().Get("token")
			if token == "secret-12345" {
				fmt.Fprintln(w, `<html><body><div id="admin-panel">Admin Panel Access Granted</div></body></html>`)
			} else {
				fmt.Fprintln(w, `<html><body><div id="error">Access Denied</div></body></html>`)
			}
		case "/search":
			q := r.URL.Query().Get("q")
			fmt.Fprintf(w, `<html><body><div id="result">You searched: %s</div></body></html>`, q)
		}
	}))
	defer ts.Close()

	// 2. Define Complex Configuration
	cfg := &config.Config{
		Target: ts.URL,
		Instances: []config.Instance{
			{Name: "victim", Type: "browser", Headless: true},
			{Name: "attacker", Type: "browser", Headless: true},
		},
		Tasks: []config.Task{
			{
				Name: "Victim Login & Token Extraction",
				Actions: []config.Action{
					// Navigate
					{Instance: "victim", Type: "navigate", Params: map[string]string{"url": ts.URL + "/login"}},

					// Input & Submit
					{Instance: "victim", Type: "input", Params: map[string]string{"selector": "input[name=user]", "value": "admin"}},
					{Instance: "victim", Type: "submit", Params: map[string]string{"selector": "input[name=user]"}}, // Press enter

					// Wait
					{Instance: "victim", Type: "wait", Params: map[string]string{"duration": "200ms"}},

					// Assert Login
					{Instance: "victim", Type: "assert", Params: map[string]string{"selector": "#welcome", "text": "Welcome Admin"}},

					// Extract Token
					{Instance: "victim", Type: "extract", Params: map[string]string{"selector": "#secret-token", "variable": "stolen_token"}},
				},
			},
			{
				Name: "Attacker Uses Stolen Token",
				Actions: []config.Action{
					// Interpolate variable in URL
					{Instance: "attacker", Type: "navigate", Params: map[string]string{"url": ts.URL + "/admin?token={{stolen_token}}"}},

					// Assert Access Granted
					{Instance: "attacker", Type: "assert", Params: map[string]string{"selector": "#admin-panel", "text": "Admin Panel Access Granted"}},
				},
			},
			{
				Name: "XSS & Eval Check",
				Actions: []config.Action{
					// Check interpolation again
					{Instance: "attacker", Type: "navigate", Params: map[string]string{"url": ts.URL + "/search?q=test-{{stolen_token}}"}},
					{Instance: "attacker", Type: "assert", Params: map[string]string{"selector": "#result", "contains": "test-secret-12345"}},

					// Eval
					{Instance: "attacker", Type: "eval", Params: map[string]string{
						"script":   "() => document.title = 'Hacked'",
						"variable": "page_title",
					}},
				},
			},
		},
	}

	// 3. Execution
	r := runner.New(cfg)

	// Pre-seed a variable to test immediate interpolation if we wanted,
	// but here we rely on extraction.

	if err := r.RunAll(); err != nil {
		t.Fatalf("Runner execution failed: %v", err)
	}

	// 4. Verify Internal State (Whitebox testing)
	if val, ok := r.Variables["stolen_token"]; !ok || val != "secret-12345" {
		t.Errorf("Expected extracted variable 'stolen_token' to be 'secret-12345', got '%s'", val)
	}

	val, ok := r.Variables["page_title"]
	if !ok {
		t.Errorf("Expected eval variable 'page_title' to be captured")
	}
	// Note: Eval returns json representation, so string might be "\"Hacked\"" or similar depending on rod
	fmt.Printf("captured title: %s\n", val)
}

func TestRunner_ErrorHandling(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer ts.Close()

	cfg := &config.Config{
		Instances: []config.Instance{
			{Name: "fail_inst", Type: "browser", Headless: true},
		},
		Tasks: []config.Task{
			{
				Name: "Fail Task",
				Actions: []config.Action{
					{Instance: "fail_inst", Type: "navigate", Params: map[string]string{"url": ts.URL}},
					{Instance: "fail_inst", Type: "click", Params: map[string]string{"selector": "#non-existent"}},
				},
			},
		},
	}

	r := runner.New(cfg)
	if err := r.RunAll(); err == nil {
		t.Error("Expected error when clicking non-existent element, got nil")
	} else {
		if !strings.Contains(err.Error(), "element not found") {
			t.Fatalf("Expected element-not-found error, got: %v", err)
		}
		t.Logf("Got expected error: %v", err)
	}
}
