// Package recon provides utilities for reconnaissance across Web2 and Web3
// ecosystems.
package recon

import (
	"fmt"
	"net"

	"github.com/coppertone/bug-hunter/app/aegis/internal/logger"
)

// Web2Manager handles traditional DNS and network-based reconnaissance.
type Web2Manager struct {
	log *logger.Logger
}

// NewWeb2Manager initializes a new Web2 reconnaissance manager.
func NewWeb2Manager() *Web2Manager {
	return &Web2Manager{log: logger.New()}
}

// DiscoverSubdomains performs subdomain enumeration for a given root domain.
// Currently returns a placeholder set of common subdomains.
func (m *Web2Manager) DiscoverSubdomains(domain string) ([]string, error) {
	m.log.Info("Discovering subdomains", "domain", domain)
	// In a real implementation, this would use tools like subfinder or crt.sh
	return []string{"www." + domain, "api." + domain, "dev." + domain}, nil
}

// PortScan checks for common open ports (simplified)
func (m *Web2Manager) PortScan(host string) []int {
	commonPorts := []int{80, 443, 8080, 8443}
	openPorts := []int{}

	for _, port := range commonPorts {
		address := fmt.Sprintf("%s:%d", host, port)
		conn, err := net.DialTimeout("tcp", address, 1)
		if err == nil {
			openPorts = append(openPorts, port)
			conn.Close()
		}
	}
	return openPorts
}
