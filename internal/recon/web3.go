package recon

import (
	"regexp"
	"strings"

	"github.com/coppertone/bug-hunter/app/aegis/internal/logger"
)

// Compiled regular expressions for Web3 reconnaissance
var (
	// ethAddrRegex matches Ethereum addresses (0x followed by 40 hex chars)
	ethAddrRegex = regexp.MustCompile(`\b0x[a-fA-F0-9]{40}\b`)
	
	// ensRegex matches ENS names (something.eth)
	ensRegex = regexp.MustCompile(`\b[a-zA-Z0-9-]+\.eth\b`)
)

// Web3Manager handles blockchain-related reconnaissance, including address
// detection and ENS name resolution.
type Web3Manager struct {
	log *logger.Logger
}

// NewWeb3Manager initializes a new Web3 reconnaissance manager.
func NewWeb3Manager() *Web3Manager {
	return &Web3Manager{log: logger.New()}
}

// Web3Artifacts holds discovered blockchain entities.
type Web3Artifacts struct {
	Addresses []string // Hex-encoded Ethereum/EVM addresses
	ENSNames  []string // Ethereum Name Service domains (.eth)
}

// AnalyzeContent scans the provided text for Ethereum addresses and ENS names
// using optimized regular expressions.
func (m *Web3Manager) AnalyzeContent(content string) Web3Artifacts {
	return Web3Artifacts{
		Addresses: ethAddrRegex.FindAllString(content, -1),
		ENSNames:  ensRegex.FindAllString(content, -1),
	}
}

// DetectNetwork attempts to identify the blockchain network from the content
func (m *Web3Manager) DetectNetwork(content string) string {
	if strings.Contains(content, "etherscan.io") {
		return "Ethereum Mainnet"
	}
	if strings.Contains(content, "bscscan.com") {
		return "Binance Smart Chain"
	}
	if strings.Contains(content, "polygonscan.com") {
		return "Polygon"
	}
	return "Unknown"
}
