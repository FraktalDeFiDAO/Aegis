// Package api provides a RESTful interface for interacting with Aegis's
// crawling and scanning capabilities.
package api

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/coppertone/bug-hunter/app/aegis/internal/crawler"
	"github.com/coppertone/bug-hunter/app/aegis/internal/logger"
)

// Server represents the HTTP API server instance.
type Server struct {
	logger *logger.Logger
	token  string
}

// NewServer initializes a new API server with default logging.
func NewServer() *Server {
	return &Server{
		logger: logger.New(),
		token:  firstNonEmpty(os.Getenv("AEGIS_API_TOKEN"), os.Getenv("API_TOKEN")),
	}
}

// Start begins listening for HTTP requests on the specified address.
//
// Registered Endpoints:
//   - POST /crawl: Start a new crawl job with provided configuration.
//   - GET /health: Check server status.
func (s *Server) Start(addr string) error {
	mux := http.NewServeMux()
	mux.Handle("/crawl", s.authMiddleware(http.HandlerFunc(s.handleCrawl)))
	mux.HandleFunc("/health", s.handleHealth)

	s.logger.Info("Starting API server", "addr", addr)
	return http.ListenAndServe(addr, mux)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) handleCrawl(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var cfg crawler.Config
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	normalized, err := cfg.Normalize()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cfg = normalized

	// In a real app, we'd run this in the background and return a job ID
	go func() {
		dumpPath := "api_dump"
		if cfg.EnableScreenshot {
			cfg.ScreenshotPath = filepath.Join(dumpPath, "screenshots")
		}
		if cfg.EnableDownload {
			cfg.DownloadPath = filepath.Join(dumpPath, "downloads")
		}

		c := crawler.NewCrawler(cfg, "")
		if err := c.Run(dumpPath); err != nil {
			s.logger.Error("API Crawl failed", "error", err)
		}
	}()

	w.WriteHeader(http.StatusAccepted)
	w.Write([]byte(`{"message":"Crawl started"}`))
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	if s.token == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(r) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authorized(r *http.Request) bool {
	token := ""
	if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	}
	if token == "" {
		token = r.Header.Get("X-API-Key")
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(s.token)) == 1
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
