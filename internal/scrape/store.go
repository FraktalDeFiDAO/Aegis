package scrape

import (
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type scrapeStore struct {
	db  *sql.DB
	log *slog.Logger
}

func newScrapeStore(path string, log *slog.Logger) (*scrapeStore, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("open scrape db: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	store := &scrapeStore{db: db, log: log}
	if err := store.init(); err != nil {
		_ = db.Close()
		return nil, err
	}

	return store, nil
}

func (s *scrapeStore) init() error {
	if _, err := s.db.Exec(`PRAGMA journal_mode = WAL;`); err != nil {
		return fmt.Errorf("init scrape db: %w", err)
	}
	if _, err := s.db.Exec(`PRAGMA busy_timeout = 5000;`); err != nil {
		return fmt.Errorf("init scrape db: %w", err)
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
	}

	for _, stmt := range statements {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("init scrape db: %w", err)
		}
	}
	return nil
}

func (s *scrapeStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *scrapeStore) RecordPage(url string, depth int, htmlPath string) error {
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

func (s *scrapeStore) RecordLink(fromURL string, toURL string) error {
	if s == nil || s.db == nil {
		return nil
	}
	_, err := s.db.Exec(
		`INSERT OR IGNORE INTO links (from_url, to_url) VALUES (?, ?)`,
		fromURL, toURL,
	)
	return err
}

func (s *scrapeStore) RecordAsset(url string, kind string, fromPage string, localPath string) error {
	if s == nil || s.db == nil {
		return nil
	}
	_, err := s.db.Exec(
		`INSERT INTO assets (url, kind, from_page, local_path)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(url, kind, from_page) DO UPDATE SET
		 local_path = CASE WHEN excluded.local_path != '' THEN excluded.local_path ELSE assets.local_path END`,
		url, kind, fromPage, localPath,
	)
	return err
}

func (s *scrapeStore) RecordError(urlStr string, stage string, err error) error {
	if s == nil || s.db == nil || err == nil {
		return nil
	}
	_, dbErr := s.db.Exec(
		`INSERT INTO errors (url, stage, error, created_at) VALUES (?, ?, ?, ?)`,
		urlStr, stage, err.Error(), time.Now().UTC().Format(time.RFC3339),
	)
	return dbErr
}
