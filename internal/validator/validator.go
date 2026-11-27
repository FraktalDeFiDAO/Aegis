// Package validator provides utilities for sanitizing and validating
// inputs to ensure secure operation of the platform.
package validator

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// ValidateURL checks if a raw string is a well-formed URL and uses
// allowed protocols (http or https).
//
// Parameters:
//   - rawURL: The string to validate.
//
// Returns an error if the URL is invalid or uses an insecure scheme.
func ValidateURL(rawURL string) error {
	u, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("unsupported protocol: %s", u.Scheme)
	}

	if u.Host == "" && u.Hostname() == "" {
		return fmt.Errorf("missing host in URL")
	}

	return nil
}

// ValidateTargetURL validates a crawl target URL and blocks localhost/private IPs.
func ValidateTargetURL(rawURL string) error {
	if err := ValidateURL(rawURL); err != nil {
		return err
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}

	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("missing host")
	}

	return ValidateTargetHost(host)
}

// ValidateTargetHost validates a hostname or IP and blocks private/local targets.
// Hostnames are resolved to ensure public-looking names that point to private IPs
// are rejected before network access occurs.
func ValidateTargetHost(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("missing host")
	}

	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return fmt.Errorf("blocked target host")
	}

	if ip := net.ParseIP(host); ip != nil {
		if blockedIP(ip) {
			return fmt.Errorf("blocked target host")
		}
		return nil
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("resolve host: %w", err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("resolve host: no addresses found")
	}
	for _, ip := range ips {
		if blockedIP(ip) {
			return fmt.Errorf("blocked target host")
		}
	}

	return nil
}

// RedirectPolicy revalidates every redirect target to preserve the same host
// safety guarantees as the original request.
func RedirectPolicy(allowPrivate bool) func(req *http.Request, via []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return fmt.Errorf("too many redirects")
		}
		if allowPrivate {
			return ValidateURL(req.URL.String())
		}
		return ValidateTargetURL(req.URL.String())
	}
}

func blockedIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}

// SanitizeFilename cleans a string of potentially dangerous characters
// to prevent path traversal or shell injection during file operations.
func SanitizeFilename(name string) string {
	badChars := []string{"..", "/", "\\", "$", "&", "|"}
	clean := name
	for _, char := range badChars {
		clean = strings.ReplaceAll(clean, char, "_")
	}
	return clean
}
