package recon

import (
	"net"
	"testing"
)

func TestWeb3AnalyzeContent(t *testing.T) {
	m := NewWeb3Manager()
	content := "Send funds to 0x71C7656EC7ab88b098defB751B7401B5f6d8976F or vitalik.eth"

	artifacts := m.AnalyzeContent(content)

	if len(artifacts.Addresses) != 1 {
		t.Errorf("Expected 1 address, got %d", len(artifacts.Addresses))
	}
	if artifacts.Addresses[0] != "0x71C7656EC7ab88b098defB751B7401B5f6d8976F" {
		t.Errorf("Wrong address found: %s", artifacts.Addresses[0])
	}
	if len(artifacts.ENSNames) != 1 {
		t.Errorf("Expected 1 ENS name, got %d", len(artifacts.ENSNames))
	}
	if artifacts.ENSNames[0] != "vitalik.eth" {
		t.Errorf("Wrong ENS name found: %s", artifacts.ENSNames[0])
	}
}

func TestWeb3DetectNetwork(t *testing.T) {
	m := NewWeb3Manager()

	if m.DetectNetwork("link to etherscan.io/tx/...") != "Ethereum Mainnet" {
		t.Error("Failed to detect Ethereum")
	}
	if m.DetectNetwork("link to bscscan.com/tx/...") != "Binance Smart Chain" {
		t.Error("Failed to detect BSC")
	}
	if m.DetectNetwork("link to polygonscan.com/tx/...") != "Polygon" {
		t.Error("Failed to detect Polygon")
	}
	if m.DetectNetwork("no matching network") != "Unknown" {
		t.Error("Expected Unknown for unmatched network")
	}
}

func TestWeb2DiscoverSubdomains(t *testing.T) {
	m := NewWeb2Manager()
	subs, err := m.DiscoverSubdomains("example.com")
	if err != nil {
		t.Fatalf("DiscoverSubdomains failed: %v", err)
	}
	if len(subs) != 3 {
		t.Fatalf("Expected 3 subdomains, got %d", len(subs))
	}
	if subs[0] != "www.example.com" || subs[1] != "api.example.com" || subs[2] != "dev.example.com" {
		t.Errorf("Unexpected subdomains: %v", subs)
	}
}

func TestWeb2PortScan(t *testing.T) {
	m := NewWeb2Manager()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to open test listener: %v", err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port
	open := m.PortScan("127.0.0.1", port)
	if len(open) != 1 || open[0] != port {
		t.Errorf("Expected port %d to be detected as open, got %v", port, open)
	}
}
