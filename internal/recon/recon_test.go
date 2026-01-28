package recon

import "testing"

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
}
