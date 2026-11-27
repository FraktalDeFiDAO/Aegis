package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestCopyDownloadVerifiesBytesAndNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "download.bin")
	destination := filepath.Join(dir, "artifact.bin")
	content := []byte("\x00browser download\xff\n")
	if err := os.WriteFile(source, content, 0600); err != nil {
		t.Fatal(err)
	}
	sha, size, err := copyDownload(source, destination, int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	if sha != fmt.Sprintf("%x", sha256.Sum256(content)) || size != int64(len(content)) {
		t.Fatal("incorrect download receipt")
	}
	if _, _, err := copyDownload(source, destination, int64(len(content))); err == nil {
		t.Fatal("overwrote an existing destination")
	}
	got, _ := os.ReadFile(destination)
	if string(got) != string(content) {
		t.Fatal("destination was changed")
	}
	bad := filepath.Join(dir, "wrong-size.bin")
	if _, _, err := copyDownload(source, bad, 999); err == nil {
		t.Fatal("accepted incorrect browser size")
	}
	if _, err := os.Stat(bad); !os.IsNotExist(err) {
		t.Fatal("left an invalid destination")
	}
}

func TestCopyDownloadPreservesDestinationSymlink(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	target := filepath.Join(dir, "target")
	dest := filepath.Join(dir, "link")
	_ = os.WriteFile(source, []byte("download"), 0600)
	_ = os.WriteFile(target, []byte("keep"), 0600)
	if err := os.Symlink(target, dest); err != nil {
		t.Fatal(err)
	}
	if _, _, err := copyDownload(source, dest, 8); err == nil {
		t.Fatal("replaced a symlink")
	}
	got, _ := os.ReadFile(target)
	if string(got) != "keep" {
		t.Fatal("changed the symlink target")
	}
}
