// Package intel provides modules for gathering and managing threat intelligence
// from various external feeds.
package intel

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/coppertone/bug-hunter/app/aegis/internal/logger"
)

// ThreatFeed represents a data source for threat intelligence.
type ThreatFeed struct {
	Name string // Descriptive name of the feed
	URL  string // Endpoint URL to fetch the data
}

// IntelManager coordinates the lifecycle of threat intelligence data,
// including fetching, caching, and querying.
type IntelManager struct {
	feeds      []ThreatFeed
	cache      sync.Map
	log        *logger.Logger
	httpClient *http.Client
}

// NewIntelManager initializes an IntelManager with default threat feeds.
func NewIntelManager() *IntelManager {
	return &IntelManager{
		log: logger.New(),
		feeds: []ThreatFeed{
			{Name: "URLHaus", URL: "https://urlhaus.abuse.ch/api/v1/urls/recent/"},
		},
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{},
			},
		},
	}
}

// FetchUpdates synchronizes the local cache with the latest data from
// all registered threat feeds.
func (m *IntelManager) FetchUpdates() error {
	for _, feed := range m.feeds {
		m.log.Info("Fetching threat intel", "feed", feed.Name)
		resp, err := m.httpClient.Get(feed.URL)
		if err != nil {
			m.log.Error("Failed to fetch feed", "feed", feed.Name, "error", err)
			continue
		}

		// Decode and close response body immediately to prevent resource leaks
		var data interface{}
		decodeErr := json.NewDecoder(resp.Body).Decode(&data)
		resp.Body.Close()
		if decodeErr != nil {
			m.log.Error("Failed to decode feed", "feed", feed.Name, "error", decodeErr)
			continue
		}
		m.cache.Store(feed.Name, data)
	}
	return nil
}

// IsMalicious checks if a URL is known in the threat cache
func (m *IntelManager) IsMalicious(targetURL string) bool {
	if targetURL == "" {
		return false
	}

	found := false
	m.cache.Range(func(_, value interface{}) bool {
		if containsTarget(value, targetURL) {
			found = true
			return false
		}
		return true
	})
	return found
}

func containsTarget(value interface{}, target string) bool {
	return containsTargetDepth(value, target, 0)
}

// containsTargetDepth recursively searches nested structures for target string,
// limited to max 10 levels deep to prevent stack overflow on malicious input.
func containsTargetDepth(value interface{}, target string, depth int) bool {
	if depth > 10 {
		return false
	}
	switch v := value.(type) {
	case string:
		return v == target
	case []interface{}:
		for _, item := range v {
			if containsTargetDepth(item, target, depth+1) {
				return true
			}
		}
	case map[string]interface{}:
		for _, item := range v {
			if containsTargetDepth(item, target, depth+1) {
				return true
			}
		}
	case []string:
		for _, item := range v {
			if item == target {
				return true
			}
		}
	case map[string]string:
		for _, item := range v {
			if item == target {
				return true
			}
		}
	}
	return false
}
