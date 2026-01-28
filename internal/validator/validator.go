// Package validator provides utilities for sanitizing and validating
// inputs to ensure secure operation of the platform.
package validator

import (
	"fmt"
	"net"
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

	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return fmt.Errorf("blocked target host")
	}

	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("blocked target host")
		}
	}

	return nil
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
