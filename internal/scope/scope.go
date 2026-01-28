// Package scope parses and evaluates in-scope assets from JSON/YAML configs.
package scope

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Item struct {
	Value     string
	Domain    string
	Type      string // exact, wildcard, ip, cidr
	InScope   bool
	AssetType string
	Notes     string
}

type Scope struct {
	ProgramName string
	Platform    string
	InScope     []Item
	OutOfScope  []Item
}

// ParseFile loads a scope config (JSON or YAML) and returns a normalized scope.
func ParseFile(path string) (*Scope, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	ext := strings.ToLower(filepath.Ext(path))
	var payload map[string]interface{}

	switch ext {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(raw, &payload); err != nil {
			return nil, err
		}
	case ".json":
		if err := json.Unmarshal(raw, &payload); err != nil {
			return nil, err
		}
	default:
		// Try JSON first, fallback to YAML.
		if err := json.Unmarshal(raw, &payload); err != nil {
			if err := yaml.Unmarshal(raw, &payload); err != nil {
				return nil, err
			}
		}
	}

	return parsePayload(payload)
}

func parsePayload(payload map[string]interface{}) (*Scope, error) {
	if _, ok := payload["targets"]; ok {
		return parseHackerOne(payload)
	}
	if _, ok := payload["target_groups"]; ok {
		return parseBugcrowd(payload)
	}
	if _, ok := payload["in_scope"]; ok {
		return parseCustom(payload)
	}
	return nil, errors.New("unsupported scope format")
}

func parseCustom(payload map[string]interface{}) (*Scope, error) {
	scope := &Scope{
		ProgramName: getString(payload, "program_name", "Custom"),
		Platform:    getString(payload, "platform", "custom"),
	}

	scope.InScope = parseItems(payload["in_scope"], true)
	scope.OutOfScope = parseItems(payload["out_of_scope"], false)
	return scope, nil
}

func parseItems(raw interface{}, inScope bool) []Item {
	items := []Item{}
	list, ok := raw.([]interface{})
	if !ok {
		return items
	}

	for _, entry := range list {
		switch v := entry.(type) {
		case string:
			items = append(items, normalizeItem(v, inScope, "", ""))
		case map[string]interface{}:
			value := getString(v, "domain", "")
			if value == "" {
				value = getString(v, "asset_identifier", "")
			}
			if value == "" {
				value = getString(v, "asset", "")
			}
			if value == "" {
				value = getString(v, "name", "")
			}
			if value == "" {
				value = getString(v, "target", "")
			}
			assetType := strings.ToLower(getString(v, "asset_type", getString(v, "category", "")))
			notes := getString(v, "notes", getString(v, "instruction", getString(v, "description", "")))
			if value != "" {
				items = append(items, normalizeItem(value, inScope, assetType, notes))
			}
		}
	}

	return items
}

func parseHackerOne(payload map[string]interface{}) (*Scope, error) {
	scope := &Scope{
		ProgramName: getString(payload, "name", "HackerOne Program"),
		Platform:    "hackerone",
	}

	targets, _ := payload["targets"].(map[string]interface{})
	scope.InScope = parseItems(targets["in_scope"], true)
	scope.OutOfScope = parseItems(targets["out_of_scope"], false)
	return scope, nil
}

func parseBugcrowd(payload map[string]interface{}) (*Scope, error) {
	scope := &Scope{
		ProgramName: getString(payload, "name", "Bugcrowd Program"),
		Platform:    "bugcrowd",
	}

	groups, ok := payload["target_groups"].([]interface{})
	if !ok {
		return scope, nil
	}

	for _, entry := range groups {
		group, ok := entry.(map[string]interface{})
		if !ok {
			continue
		}
		inScope := getBool(group, "in_scope", true)
		items := parseItems(group["targets"], inScope)
		if inScope {
			scope.InScope = append(scope.InScope, items...)
		} else {
			scope.OutOfScope = append(scope.OutOfScope, items...)
		}
	}

	return scope, nil
}

func getString(m map[string]interface{}, key string, fallback string) string {
	if value, ok := m[key]; ok {
		if str, ok := value.(string); ok && str != "" {
			return str
		}
	}
	return fallback
}

func getBool(m map[string]interface{}, key string, fallback bool) bool {
	if value, ok := m[key]; ok {
		if b, ok := value.(bool); ok {
			return b
		}
	}
	return fallback
}

func normalizeItem(value string, inScope bool, assetType string, notes string) Item {
	value = strings.TrimSpace(value)
	domain := normalizeDomain(value)

	return Item{
		Value:     value,
		Domain:    domain,
		Type:      detectType(domain),
		InScope:   inScope,
		AssetType: assetType,
		Notes:     notes,
	}
}

func normalizeDomain(value string) string {
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		if parsed, err := parseHost(value); err == nil {
			return parsed
		}
	}
	value = strings.TrimSpace(value)
	if idx := strings.Index(value, "/"); idx >= 0 {
		value = value[:idx]
	}
	return value
}

func parseHost(rawURL string) (string, error) {
	parsed, err := parseURL(rawURL)
	if err != nil {
		return "", err
	}
	if parsed == "" {
		return "", fmt.Errorf("missing host")
	}
	return parsed, nil
}

func detectType(domain string) string {
	if strings.HasPrefix(domain, "*.") {
		return "wildcard"
	}
	if _, _, err := net.ParseCIDR(domain); err == nil {
		return "cidr"
	}
	if net.ParseIP(domain) != nil {
		return "ip"
	}
	return "exact"
}

func parseURL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	return parsed.Hostname(), nil
}

// Targets returns normalized start URLs for in-scope items.
func (s *Scope) Targets() []string {
	var targets []string
	for _, item := range s.InScope {
		value := item.Value
		if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
			targets = append(targets, value)
			continue
		}

		if item.Type == "cidr" {
			continue
		}
		if item.Type == "ip" {
			targets = append(targets, "http://"+item.Domain)
			continue
		}

		base := strings.TrimPrefix(value, "*.")
		base = strings.TrimPrefix(base, ".")
		if base == "" {
			continue
		}
		targets = append(targets, "https://"+base)
	}
	return uniqueStrings(targets)
}

// IsInScope reports whether the provided URL or domain is in scope.
func (s *Scope) IsInScope(raw string) bool {
	host := normalizeDomain(raw)
	if host == "" {
		return false
	}

	for _, item := range s.OutOfScope {
		if matches(host, item.Domain, item.Type) {
			return false
		}
	}
	for _, item := range s.InScope {
		if matches(host, item.Domain, item.Type) {
			return true
		}
	}
	return false
}

func matches(host, pattern, patternType string) bool {
	host = strings.ToLower(host)
	pattern = strings.ToLower(pattern)

	switch patternType {
	case "wildcard":
		base := strings.TrimPrefix(pattern, "*.")
		return host == base || strings.HasSuffix(host, "."+base)
	case "cidr":
		ip := net.ParseIP(host)
		if ip == nil {
			return false
		}
		_, network, err := net.ParseCIDR(pattern)
		if err != nil {
			return false
		}
		return network.Contains(ip)
	case "ip":
		return host == pattern
	default:
		return host == pattern
	}
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
