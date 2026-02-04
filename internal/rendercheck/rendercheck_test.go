package rendercheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNeedsRenderingHeuristic(t *testing.T) {
	tests := []struct {
		name         string
		html         string
		wantRendered bool
	}{
		{
			name:         "static content",
			html:         `<html><body><h1>Hello</h1><p>Visible content here.</p></body></html>`,
			wantRendered: false,
		},
		{
			name:         "empty root with scripts",
			html:         `<html><body><div id="root"></div><script src="/app.js"></script><script src="/chunk.js"></script></body></html>`,
			wantRendered: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				_, _ = w.Write([]byte(tc.html))
			}))
			defer server.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			res, err := NeedsRendering(ctx, server.URL, Options{
				Verify:  VerifyNever,
				Timeout: 5 * time.Second,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.NeedsRendering != tc.wantRendered {
				t.Fatalf("needs rendering=%v want %v", res.NeedsRendering, tc.wantRendered)
			}
		})
	}
}
