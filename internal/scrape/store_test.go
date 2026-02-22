package scrape

import (
	"path/filepath"
	"testing"
)

func TestScrapeStoreRecords(t *testing.T) {
	dir := t.TempDir()
	store, err := newScrapeStore(filepath.Join(dir, "crawl.db"), nil)
	if err != nil {
		t.Fatalf("newScrapeStore: %v", err)
	}
	defer store.Close()

	pageURL := "https://example.com"
	assetURL := "https://example.com/app.js"

	if err := store.RecordPage(pageURL, 1, "/tmp/page.html"); err != nil {
		t.Fatalf("RecordPage: %v", err)
	}
	if err := store.RecordLink(pageURL, "https://example.com/about"); err != nil {
		t.Fatalf("RecordLink: %v", err)
	}
	if err := store.RecordAsset(assetURL, "source", pageURL, ""); err != nil {
		t.Fatalf("RecordAsset empty: %v", err)
	}
	if err := store.RecordAsset(assetURL, "source", pageURL, "/tmp/app.js"); err != nil {
		t.Fatalf("RecordAsset update: %v", err)
	}
	if err := store.RecordError(pageURL, "scrape", errTest("boom")); err != nil {
		t.Fatalf("RecordError: %v", err)
	}

	var pageCount int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM pages`).Scan(&pageCount); err != nil {
		t.Fatalf("count pages: %v", err)
	}
	if pageCount != 1 {
		t.Fatalf("expected 1 page, got %d", pageCount)
	}

	var linkCount int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM links`).Scan(&linkCount); err != nil {
		t.Fatalf("count links: %v", err)
	}
	if linkCount != 1 {
		t.Fatalf("expected 1 link, got %d", linkCount)
	}

	var assetPath string
	if err := store.db.QueryRow(
		`SELECT local_path FROM assets WHERE url=? AND kind=? AND from_page=?`,
		assetURL, "source", pageURL,
	).Scan(&assetPath); err != nil {
		t.Fatalf("select asset path: %v", err)
	}
	if assetPath != "/tmp/app.js" {
		t.Fatalf("expected asset path update, got %q", assetPath)
	}

	var errCount int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM errors`).Scan(&errCount); err != nil {
		t.Fatalf("count errors: %v", err)
	}
	if errCount != 1 {
		t.Fatalf("expected 1 error, got %d", errCount)
	}
}

type errTest string

func (e errTest) Error() string { return string(e) }
