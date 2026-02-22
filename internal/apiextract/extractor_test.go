package apiextract

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtract_Success(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`
<html>
<script>
  fetch('/api/users');
  fetch('/api/users');
  const v1 = "https://api.example.com/v1/orders";
  const gql = "/graphql";
  const ws = "wss://ws.example.com/socket";
</script>
</html>`))
	}))
	defer ts.Close()

	e := NewExtractor()
	result, err := e.Extract(ts.URL, nil)
	if err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}

	if result.TotalCount == 0 {
		t.Fatal("expected at least one endpoint")
	}
	if len(result.REST) == 0 {
		t.Fatal("expected REST endpoints")
	}
	if len(result.GraphQL) == 0 {
		t.Fatal("expected GraphQL endpoints")
	}
	if len(result.WebSocket) == 0 {
		t.Fatal("expected WebSocket endpoints")
	}
}

func TestExtract_HTTPError(t *testing.T) {
	t.Parallel()

	e := NewExtractor()
	if _, err := e.Extract("http://127.0.0.1:1", nil); err == nil {
		t.Fatal("expected request error")
	}
}

func TestResolveURL(t *testing.T) {
	t.Parallel()

	base := "https://example.com/app/index.html"
	if got := resolveURL(base, "/api/users"); got != "https://example.com/api/users" {
		t.Fatalf("unexpected resolved URL: %q", got)
	}
	if got := resolveURL(base, "https://other.example/api"); got != "https://other.example/api" {
		t.Fatalf("unexpected absolute URL: %q", got)
	}
	if got := resolveURL(base, "wss://ws.example/socket"); got != "wss://ws.example/socket" {
		t.Fatalf("unexpected websocket URL: %q", got)
	}
}

func TestGenerateReport(t *testing.T) {
	t.Parallel()

	e := NewExtractor()
	data, err := e.GenerateReport(&ExtractResult{
		BaseURL: "https://example.com",
		Endpoints: []APIEndpoint{
			{URL: "https://example.com/api", Method: "GET", Source: "html"},
		},
		TotalCount: 1,
	})
	if err != nil {
		t.Fatalf("GenerateReport returned error: %v", err)
	}

	var parsed ExtractResult
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("report is not valid JSON: %v", err)
	}
	if parsed.TotalCount != 1 {
		t.Fatalf("unexpected total_count: %d", parsed.TotalCount)
	}
}
