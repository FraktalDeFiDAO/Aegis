// Package api provides a RESTful interface for interacting with Aegis's
// crawling and scanning capabilities.
package api

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coppertone/bug-hunter/app/aegis/internal/crawler"
	"github.com/coppertone/bug-hunter/app/aegis/internal/logger"
)

// Server represents the HTTP API server instance.
type Server struct {
	logger               *logger.Logger
	token                string
	allowUnauthenticated bool
	crawlRunner          func(crawler.Config, string) error

	// Rate limiting
	rateMu       sync.Mutex
	rateBuckets  map[string]*clientBucket
	ratePerMin   int
	rateWindow   time.Duration
	rateMaxBurst int

	// Rate-limit map eviction to prevent unbounded memory growth.
	// A bucket is evicted when it is older than this TTL OR when the
	// total bucket count exceeds maxBuckets (LRU-style: oldest lastRefill first).
	bucketTTL   time.Duration
	maxBuckets  int
	lastSweepAt time.Time
	sweepEvery  time.Duration
}

type clientBucket struct {
	tokens     float64
	lastRefill time.Time
}

// NewServer initializes a new API server with default logging.
func NewServer() *Server {
	return &Server{
		logger:               logger.New(),
		token:                firstNonEmpty(os.Getenv("AEGIS_API_TOKEN"), os.Getenv("API_TOKEN")),
		allowUnauthenticated: parseBoolEnv("AEGIS_API_ALLOW_UNAUTH"),
		rateBuckets:          make(map[string]*clientBucket),
		ratePerMin:           parseIntEnv("AEGIS_API_RATE_PER_MIN", 60),
		rateWindow:           time.Minute,
		rateMaxBurst:         parseIntEnv("AEGIS_API_RATE_BURST", 10),
		bucketTTL:            time.Duration(parseIntEnv("AEGIS_API_BUCKET_TTL_SEC", 600)) * time.Second,
		maxBuckets:           parseIntEnv("AEGIS_API_MAX_BUCKETS", 10000),
		lastSweepAt:          time.Now(),
		sweepEvery:           time.Duration(parseIntEnv("AEGIS_API_SWEEP_EVERY_SEC", 60)) * time.Second,
	}
}

// Start begins listening for HTTP requests on the specified address.
//
// Registered Endpoints:
//   - POST /crawl: Start a new crawl job with provided configuration.
//   - GET /health: Check server status.
func (s *Server) Start(addr string) error {
	if s.token == "" && !s.allowUnauthenticated {
		return fmt.Errorf("AEGIS_API_TOKEN is required unless AEGIS_API_ALLOW_UNAUTH=true")
	}

	mux := http.NewServeMux()
	mux.Handle("/crawl", s.rateLimitMiddleware(s.authMiddleware(http.HandlerFunc(s.handleCrawl))))
	mux.HandleFunc("/health", s.handleHealth)

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	s.logger.Info("Starting API server", "addr", addr)
	return srv.ListenAndServe()
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
		s.logger.Warn("Rejected invalid crawl config", "error", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	cfg = normalized

	// In a real app, we'd run this in the background and return a job ID
	go func() {
		dumpPath, err := prepareCrawlDumpDir()
		if err != nil {
			s.logger.Error("Failed to prepare crawl dump directory", "error", err)
			return
		}
		if cfg.EnableScreenshot {
			cfg.ScreenshotPath = filepath.Join(dumpPath, "screenshots")
		}
		if cfg.EnableDownload {
			cfg.DownloadPath = filepath.Join(dumpPath, "downloads")
		}

		runner := s.crawlRunner
		if runner == nil {
			runner = func(config crawler.Config, path string) error {
				return crawler.NewCrawler(config, "").Run(path)
			}
		}
		if err := runner(cfg, dumpPath); err != nil {
			s.logger.Error("API Crawl failed", "error", err)
		}
	}()

	w.WriteHeader(http.StatusAccepted)
	w.Write([]byte(`{"message":"Crawl started"}`))
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	if s.token == "" && s.allowUnauthenticated {
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

func parseBoolEnv(name string) bool {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return false
	}
	parsed, err := strconv.ParseBool(value)
	return err == nil && parsed
}

func parseIntEnv(name string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

// rateLimitMiddleware applies a per-client token bucket rate limit.
// The token bucket is keyed on client IP and refills at ratePerMin tokens/minute
// up to rateMaxBurst tokens. Excess requests are rejected with 429 Too Many Requests.
func (s *Server) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.allowRequest(r.RemoteAddr) {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) allowRequest(remoteAddr string) bool {
	if s.ratePerMin <= 0 {
		return true
	}
	clientKey := clientKey(remoteAddr)

	s.rateMu.Lock()
	defer s.rateMu.Unlock()

	now := time.Now()
	if now.Sub(s.lastSweepAt) > s.sweepEvery {
		s.sweepStaleBuckets(now)
		s.lastSweepAt = now
	}

	if len(s.rateBuckets) >= s.maxBuckets {
		s.evictOldestLocked(now)
	}

	bucket, ok := s.rateBuckets[clientKey]
	if !ok {
		s.rateBuckets[clientKey] = &clientBucket{
			tokens:     float64(s.rateMaxBurst - 1),
			lastRefill: now,
		}
		return true
	}

	elapsed := now.Sub(bucket.lastRefill).Seconds()
	refill := elapsed * (float64(s.ratePerMin) / 60.0)
	bucket.tokens += refill
	if bucket.tokens > float64(s.rateMaxBurst) {
		bucket.tokens = float64(s.rateMaxBurst)
	}
	bucket.lastRefill = now

	if bucket.tokens < 1 {
		return false
	}
	bucket.tokens--
	return true
}

// sweepStaleBuckets removes buckets whose lastRefill is older than bucketTTL.
// Must be called with s.rateMu held.
func (s *Server) sweepStaleBuckets(now time.Time) {
	if s.bucketTTL <= 0 {
		return
	}
	for k, b := range s.rateBuckets {
		if now.Sub(b.lastRefill) > s.bucketTTL {
			delete(s.rateBuckets, k)
		}
	}
}

// evictOldestLocked removes the bucket with the oldest lastRefill.
// Must be called with s.rateMu held and only when len >= maxBuckets.
func (s *Server) evictOldestLocked(now time.Time) {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, b := range s.rateBuckets {
		if first || b.lastRefill.Before(oldestTime) {
			oldestKey = k
			oldestTime = b.lastRefill
			first = false
		}
	}
	if oldestKey != "" {
		delete(s.rateBuckets, oldestKey)
	}
}

// clientKey extracts a stable identifier from a remote address.
// Returns "unknown" for malformed addresses so they share a single bucket.
func clientKey(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return "unknown"
	}
	return host
}

// Crawl-dump directory management. Each /crawl invocation creates a
// timestamped directory under api_dump/. To prevent unbounded disk
// growth we cap the number of retained directories (configurable via
// AEGIS_API_DUMP_MAX_DIRS) and prune the oldest ones before creating
// a new dump directory. The sweep runs synchronously per request
// so the cap is enforced even under bursts.

const (
	apiDumpRoot        = "api_dump"
	defaultMaxDumpDirs = 16
)

var crawlDumpMu sync.Mutex

// parseIntEnv (defined earlier) provides safe integer env parsing.

func prepareCrawlDumpDir() (string, error) {
	crawlDumpMu.Lock()
	defer crawlDumpMu.Unlock()
	maxDirs := parseIntEnv("AEGIS_API_DUMP_MAX_DIRS", defaultMaxDumpDirs)
	root := os.Getenv("AEGIS_API_DUMP_ROOT")
	if root == "" {
		root = apiDumpRoot
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return "", fmt.Errorf("create dump root %s: %w", root, err)
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		return "", fmt.Errorf("read dump root: %w", err)
	}
	// Subtract the new directory we're about to create.
	if len(entries) >= maxDirs {
		// Sort by name (lexical = chronological for our format).
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		toDelete := len(entries) - maxDirs + 1
		for i := 0; i < toDelete; i++ {
			_ = os.RemoveAll(filepath.Join(root, entries[i].Name()))
		}
	}

	dumpPath := filepath.Join(root, time.Now().UTC().Format("20060102_150405.000000000"))
	if err := os.MkdirAll(dumpPath, 0o755); err != nil {
		return "", fmt.Errorf("create dump dir: %w", err)
	}
	return dumpPath, nil
}
