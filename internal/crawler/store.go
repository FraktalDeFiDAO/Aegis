package crawler

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/coppertone/bug-hunter/app/aegis/internal/rendercheck"
	_ "github.com/mattn/go-sqlite3"
)

type crawlStore struct {
	db  *sql.DB
	log *slog.Logger
}

func newCrawlStore(path string, log *slog.Logger) (*crawlStore, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("open crawl db: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	store := &crawlStore{db: db, log: log}
	if err := store.init(); err != nil {
		_ = db.Close()
		return nil, err
	}

	return store, nil
}

func (s *crawlStore) init() error {
	if _, err := s.db.Exec(`PRAGMA journal_mode = WAL;`); err != nil {
		return fmt.Errorf("init crawl db: %w", err)
	}
	if _, err := s.db.Exec(`PRAGMA busy_timeout = 5000;`); err != nil {
		return fmt.Errorf("init crawl db: %w", err)
	}

	statements := []string{
		`CREATE TABLE IF NOT EXISTS pages (
			url TEXT PRIMARY KEY,
			depth INTEGER NOT NULL,
			html_path TEXT,
			fetched_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS links (
			from_url TEXT NOT NULL,
			to_url TEXT NOT NULL,
			UNIQUE(from_url, to_url)
		);`,
		`CREATE TABLE IF NOT EXISTS assets (
			url TEXT NOT NULL,
			kind TEXT NOT NULL,
			from_page TEXT NOT NULL,
			local_path TEXT,
			UNIQUE(url, kind, from_page)
		);`,
		`CREATE TABLE IF NOT EXISTS errors (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			url TEXT,
			stage TEXT,
			error TEXT NOT NULL,
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS render_checks (
			url TEXT PRIMARY KEY,
			needs_rendering INTEGER NOT NULL,
			method TEXT NOT NULL,
			score INTEGER NOT NULL,
			confidence TEXT NOT NULL,
			signals TEXT,
			metrics TEXT,
			checked_at TEXT NOT NULL
		);`,
	}

	for _, stmt := range statements {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("init crawl db: %w", err)
		}
	}
	return nil
}

func (s *crawlStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *crawlStore) RecordPage(url string, depth int, htmlPath string) error {
	if s == nil || s.db == nil {
		return nil
	}
	_, err := s.db.Exec(
		`INSERT INTO pages (url, depth, html_path, fetched_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(url) DO UPDATE SET
		 depth=excluded.depth,
		 html_path=excluded.html_path,
		 fetched_at=excluded.fetched_at`,
		url, depth, htmlPath, time.Now().UTC().Format(time.RFC3339),
	)
	return err
}

func (s *crawlStore) RecordLink(fromURL string, toURL string) error {
	if s == nil || s.db == nil {
		return nil
	}
	_, err := s.db.Exec(
		`INSERT OR IGNORE INTO links (from_url, to_url) VALUES (?, ?)`,
		fromURL, toURL,
	)
	return err
}

func (s *crawlStore) RecordAsset(url string, kind string, fromPage string, localPath string) error {
	if s == nil || s.db == nil {
		return nil
	}
	_, err := s.db.Exec(
		`INSERT OR IGNORE INTO assets (url, kind, from_page, local_path) VALUES (?, ?, ?, ?)`,
		url, kind, fromPage, localPath,
	)
	return err
}

func (s *crawlStore) UpdateAssetLocalPath(url string, localPath string) error {
	if s == nil || s.db == nil {
		return nil
	}
	_, err := s.db.Exec(
		`UPDATE assets SET local_path = ? WHERE url = ?`,
		localPath, url,
	)
	return err
}

func (s *crawlStore) RecordError(urlStr string, stage string, err error) error {
	if s == nil || s.db == nil || err == nil {
		return nil
	}
	_, dbErr := s.db.Exec(
		`INSERT INTO errors (url, stage, error, created_at) VALUES (?, ?, ?, ?)`,
		urlStr, stage, err.Error(), time.Now().UTC().Format(time.RFC3339),
	)
	return dbErr
}

func (s *crawlStore) RecordRenderCheck(urlStr string, res *rendercheck.Result) error {
	if s == nil || s.db == nil || res == nil {
		return nil
	}

	signals, _ := json.Marshal(res.Signals)
	metrics, _ := json.Marshal(res.Metrics)

	needs := 0
	if res.NeedsRendering {
		needs = 1
	}

	_, err := s.db.Exec(
		`INSERT INTO render_checks (url, needs_rendering, method, score, confidence, signals, metrics, checked_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(url) DO UPDATE SET
		 needs_rendering=excluded.needs_rendering,
		 method=excluded.method,
		 score=excluded.score,
		 confidence=excluded.confidence,
		 signals=excluded.signals,
		 metrics=excluded.metrics,
		 checked_at=excluded.checked_at`,
		urlStr,
		needs,
		res.Method,
		res.Score,
		res.Confidence,
		string(signals),
		string(metrics),
		time.Now().UTC().Format(time.RFC3339),
	)
	return err
}
