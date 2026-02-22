// Package platform provides framework and platform detection capabilities.
// It identifies frontend frameworks (React, Vue, Svelte, Angular), backend technologies,
// and extracts version information for vulnerability correlation.
package platform

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Framework represents a detected web framework
 type Framework int

const (
	Unknown Framework = iota
	React
	Vue
	Svelte
	Angular
	Preact
	Solid
	Alpine
	jQuery
	Ember
	Backbone
	// Backend frameworks
	Express
	Django
	Rails
	Laravel
	Spring
	ASP
	// CMS platforms
	WordPress
	Drupal
	Joomla
	// E-commerce
	Shopify
	Magento
	WooCommerce
)

func (f Framework) String() string {
	switch f {
	case React:
		return "React"
	case Vue:
		return "Vue.js"
	case Svelte:
		return "Svelte"
	case Angular:
		return "Angular"
	case Preact:
		return "Preact"
	case Solid:
		return "SolidJS"
	case Alpine:
		return "Alpine.js"
	case jQuery:
		return "jQuery"
	case Ember:
		return "Ember.js"
	case Backbone:
		return "Backbone.js"
	case Express:
		return "Express.js"
	case Django:
		return "Django"
	case Rails:
		return "Ruby on Rails"
	case Laravel:
		return "Laravel"
	case Spring:
		return "Spring"
	case ASP:
		return "ASP.NET"
	case WordPress:
		return "WordPress"
	case Drupal:
		return "Drupal"
	case Joomla:
		return "Joomla"
	case Shopify:
		return "Shopify"
	case Magento:
		return "Magento"
	case WooCommerce:
		return "WooCommerce"
	default:
		return "Unknown"
	}
}

// PlatformType categorizes the platform type
 type PlatformType int

const (
	UnknownPlatform PlatformType = iota
	StaticSite     // Static HTML/CSS
	SPA            // Single Page Application
	SSR            // Server-Side Rendered
	Hybrid         // Mix of technologies
)

func (p PlatformType) String() string {
	switch p {
	case StaticSite:
		return "Static"
	case SPA:
		return "SPA"
	case SSR:
		return "SSR"
	case Hybrid:
		return "Hybrid"
	default:
		return "Unknown"
	}
}

// Detection holds the results of platform detection
 type Detection struct {
	Frameworks      []FrameworkInfo    `json:"frameworks"`
	PlatformType    PlatformType       `json:"platform_type"`
	ServerTech      []string           `json:"server_technologies,omitempty"`
	JavaScriptLibs  []LibraryInfo      `json:"javascript_libraries,omitempty"`
	CMS             *CMSInfo           `json:"cms,omitempty"`
	APIEndpoints    []string           `json:"api_endpoints,omitempty"`
	IsDevMode       bool               `json:"is_dev_mode"`
	HasSourceMap    bool               `json:"has_source_map"`
	SourceMapURL    string             `json:"source_map_url,omitempty"`
	CDNAssets       []string           `json:"cdn_assets,omitempty"`
	EOLInfo         []EOLInfo          `json:"eol_info,omitempty"`
}

// FrameworkInfo holds detailed framework information
 type FrameworkInfo struct {
	Name       string `json:"name"`
	Version    string `json:"version,omitempty"`
	Confidence int    `json:"confidence"` // 0-100
	IsEOL      bool   `json:"is_eol,omitempty"`
	EOLVersion string `json:"eol_version,omitempty"`
}

// LibraryInfo holds JavaScript library information
 type LibraryInfo struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// CMSInfo holds CMS-specific information
 type CMSInfo struct {
	Name      string            `json:"name"`
	Version   string            `json:"version,omitempty"`
	Theme     string            `json:"theme,omitempty"`
	Plugins   []string          `json:"plugins,omitempty"`
	Vulnerabilities []string    `json:"known_vulnerabilities,omitempty"`
}

// Detector performs platform detection
 type Detector struct {
	httpClient *http.Client
}

// NewDetector creates a new platform detector
 func NewDetector(timeout time.Duration) *Detector {
	return &Detector{
		httpClient: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return nil // Follow redirects
			},
		},
	}
}

// Detect performs full platform detection on a URL
 func (d *Detector) Detect(url string) (*Detection, error) {
	detection := &Detection{
		Frameworks:     []FrameworkInfo{},
		ServerTech:     []string{},
		JavaScriptLibs: []LibraryInfo{},
		APIEndpoints:   []string{},
		CDNAssets:      []string{},
	}

	// Fetch main page
	resp, err := d.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch URL: %w", err)
	}
	defer resp.Body.Close()

	// Read body
	body := make([]byte, 0)
	buf := make([]byte, 1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			body = append(body, buf[:n]...)
		}
		if err != nil {
			break
		}
	}
	content := string(body)

	// Detect from HTTP headers
	d.detectFromHeaders(resp.Header, detection)

	// Detect from HTML content
	d.detectFromHTML(content, detection)

	// Detect JavaScript frameworks
	d.detectJSFrameworks(content, detection)

	// Detect CMS
	d.detectCMS(content, resp.Header, detection)

	// Detect API endpoints
	d.detectAPIEndpoints(content, detection)

	// Detect CDN assets
	d.detectCDNs(content, detection)

	// Determine platform type
	d.determinePlatformType(detection)

	// Check EOL status for detected frameworks
	eolChecker := NewEOLChecker()
	detection.EOLInfo = eolChecker.CheckDetection(detection)

	return detection, nil
}

// detectFromHeaders extracts information from HTTP headers
 func (d *Detector) detectFromHeaders(headers http.Header, detection *Detection) {
	// Server header
	if server := headers.Get("Server"); server != "" {
		detection.ServerTech = append(detection.ServerTech, server)
	}

	// X-Powered-By
	if poweredBy := headers.Get("X-Powered-By"); poweredBy != "" {
		detection.ServerTech = append(detection.ServerTech, poweredBy)
	}

	// Detect backend from headers
	for _, tech := range detection.ServerTech {
		tech = strings.ToLower(tech)
		switch {
		case strings.Contains(tech, "express"):
			detection.addFramework(Express, "", 70)
		case strings.Contains(tech, "django"):
			detection.addFramework(Django, "", 70)
		case strings.Contains(tech, "ruby"):
			detection.addFramework(Rails, "", 60)
		case strings.Contains(tech, "php"):
			detection.addFramework(Laravel, "", 50)
		case strings.Contains(tech, "asp"):
			detection.addFramework(ASP, "", 70)
		}
	}
 }

// detectFromHTML extracts information from HTML content
 func (d *Detector) detectFromHTML(content string, detection *Detection) {
	// Check for React markers
	if matches := regexp.MustCompile(`data-reactid|data-reactroot|__REACT__|reactRoot`).FindString(content); matches != "" {
		version := d.extractReactVersion(content)
		detection.addFramework(React, version, 90)
		detection.HasSourceMap = strings.Contains(content, ".js.map")
	}

	// Check for Vue markers
	if matches := regexp.MustCompile(`data-v-[a-f0-9]+|vue\.js|Vue\.|__VUE__|vue-router|v-if=|v-for=`).FindString(content); matches != "" {
		version := d.extractVueVersion(content)
		detection.addFramework(Vue, version, 90)
	}

	// Check for Angular markers
	if matches := regexp.MustCompile(`ng-app|ng-controller|ng-model|ng-repeat|angular\.js|ng-version`).FindString(content); matches != "" {
		version := d.extractAngularVersion(content)
		detection.addFramework(Angular, version, 90)
	}

	// Check for Svelte markers
	if matches := regexp.MustCompile(`svelte-[a-z0-9]+|create_ssr_component|svelte/internal`).FindString(content); matches != "" {
		version := d.extractSvelteVersion(content)
		detection.addFramework(Svelte, version, 85)
	}

	// Check for jQuery
	if matches := regexp.MustCompile(`jquery[.-]([0-9.]+)`).FindStringSubmatch(content); len(matches) > 0 {
		detection.addFramework(jQuery, matches[1], 95)
		detection.JavaScriptLibs = append(detection.JavaScriptLibs, LibraryInfo{Name: "jQuery", Version: matches[1]})
	}

	// Check for dev mode indicators
	if regexp.MustCompile(`(?i)react.*dev|vue.*dev|ng.*dev|__DEV__`).MatchString(content) {
		detection.IsDevMode = true
	}
 }

// detectJSFrameworks performs deeper JavaScript framework detection
 func (d *Detector) detectJSFrameworks(content string, detection *Detection) {
	// Extract all script sources
	scriptRegex := regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)
	matches := scriptRegex.FindAllStringSubmatch(content, -1)
	
	for _, match := range matches {
		if len(match) > 1 {
			src := strings.ToLower(match[1])
			
			// Check for various frameworks
			switch {
			case strings.Contains(src, "react"):
				if !detection.hasFramework(React) {
					detection.addFramework(React, "", 70)
				}
			case strings.Contains(src, "vue"):
				if !detection.hasFramework(Vue) {
					detection.addFramework(Vue, "", 70)
				}
			case strings.Contains(src, "angular"):
				if !detection.hasFramework(Angular) {
					detection.addFramework(Angular, "", 70)
				}
			case strings.Contains(src, "svelte"):
				if !detection.hasFramework(Svelte) {
					detection.addFramework(Svelte, "", 70)
				}
			case strings.Contains(src, "preact"):
				detection.addFramework(Preact, "", 80)
			case strings.Contains(src, "solid"):
				detection.addFramework(Solid, "", 80)
			case strings.Contains(src, "alpine"):
				detection.addFramework(Alpine, "", 80)
			}
			
			// Check for CDN
			if strings.Contains(src, "cdn") || strings.Contains(src, "unpkg") || strings.Contains(src, "jsdelivr") {
				detection.CDNAssets = append(detection.CDNAssets, match[1])
			}
		}
	}
 }

// detectCMS detects Content Management Systems
 func (d *Detector) detectCMS(content string, headers http.Header, detection *Detection) {
	// WordPress detection
	if regexp.MustCompile(`wp-content|wp-includes|wordpress|wp-json`).MatchString(content) {
		cms := &CMSInfo{Name: "WordPress"}
		
		// Try to extract version
		if matches := regexp.MustCompile(`wp-includes/js/wp-emoji-release\.min\.js\?ver=([0-9.]+)`).FindStringSubmatch(content); len(matches) > 1 {
			cms.Version = matches[1]
		}
		
		// Check for plugins
		pluginRegex := regexp.MustCompile(`wp-content/plugins/([^/]+)`)
		pluginMatches := pluginRegex.FindAllStringSubmatch(content, -1)
		for _, pm := range pluginMatches {
			if len(pm) > 1 && !contains(cms.Plugins, pm[1]) {
				cms.Plugins = append(cms.Plugins, pm[1])
			}
		}
		
		detection.CMS = cms
		detection.addFramework(WordPress, cms.Version, 95)
		
		// Check for WooCommerce
		if strings.Contains(content, "woocommerce") || strings.Contains(content, "wc-") {
			detection.addFramework(WooCommerce, "", 85)
		}
	}

	// Drupal detection
	if regexp.MustCompile(`drupal|sites/default|sites/all`).MatchString(content) {
		cms := &CMSInfo{Name: "Drupal"}
		detection.CMS = cms
		detection.addFramework(Drupal, "", 85)
	}

	// Shopify detection
	if strings.Contains(content, "myshopify.com") || strings.Contains(content, "shopify") {
		detection.addFramework(Shopify, "", 90)
	}
 }

// detectAPIEndpoints extracts potential API endpoints from content
 func (d *Detector) detectAPIEndpoints(content string, detection *Detection) {
	// Common API patterns
	apiPatterns := []*regexp.Regexp{
		regexp.MustCompile(`["']/(?:api|graphql|rest|v\d+)/[^"']+["']`),
		regexp.MustCompile(`fetch\(["']/(?:[^"']+)["']`),
		regexp.MustCompile(`axios\.(?:get|post|put|delete)\(["']/(?:[^"']+)["']`),
		regexp.MustCompile(`url:\s*["']/(?:[^"']+)["']`),
	}
	
	seen := make(map[string]bool)
	for _, pattern := range apiPatterns {
		matches := pattern.FindAllString(content, -1)
		for _, match := range matches {
			endpoint := strings.Trim(match, `"'`)
			if !seen[endpoint] {
				seen[endpoint] = true
				detection.APIEndpoints = append(detection.APIEndpoints, endpoint)
			}
		}
	}
 }

// detectCDNs extracts CDN asset information
 func (d *Detector) detectCDNs(content string, detection *Detection) {
	cdnPatterns := []string{
		`cdnjs\.cloudflare\.com`,
		`unpkg\.com`,
		`cdn\.jsdelivr\.net`,
		`ajax\.googleapis\.com`,
		`maxcdn\.bootstrapcdn\.com`,
		`cdn\.bootstrapcdn\.com`,
		`code\.jquery\.com`,
		`stackpath\.bootstrapcdn\.com`,
	}
	
	for _, pattern := range cdnPatterns {
		if regexp.MustCompile(pattern).MatchString(content) {
			// Already added in detectJSFrameworks
			break
		}
	}
 }

// determinePlatformType determines if site is SPA, SSR, or static
 func (d *Detector) determinePlatformType(detection *Detection) {
	hasSPAFramework := false
	for _, fw := range detection.Frameworks {
		switch fw.Name {
		case "React", "Vue.js", "Svelte", "Angular", "Preact", "SolidJS":
			hasSPAFramework = true
		}
	}
	
	if hasSPAFramework {
		// Check for SSR indicators
		if len(detection.ServerTech) > 0 {
			detection.PlatformType = Hybrid
		} else {
			detection.PlatformType = SPA
		}
	} else if len(detection.ServerTech) > 0 {
		detection.PlatformType = SSR
	} else {
		detection.PlatformType = StaticSite
	}
 }

// Helper methods
 func (d *Detection) addFramework(fw Framework, version string, confidence int) {
	// Check if already exists
	for i, existing := range d.Frameworks {
		if existing.Name == fw.String() {
			// Update if higher confidence
			if confidence > existing.Confidence {
				d.Frameworks[i].Confidence = confidence
				if version != "" {
					d.Frameworks[i].Version = version
				}
			}
			return
		}
	}
	
	d.Frameworks = append(d.Frameworks, FrameworkInfo{
		Name:       fw.String(),
		Version:    version,
		Confidence: confidence,
	})
 }

 func (d *Detection) hasFramework(fw Framework) bool {
	for _, existing := range d.Frameworks {
		if existing.Name == fw.String() {
			return true
		}
	}
	return false
 }

 func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
 }

// Version extraction helpers
 func (d *Detector) extractReactVersion(content string) string {
	// Try various patterns
	patterns := []string{
		`react@([0-9.]+)`,
		`react\.js@([0-9.]+)`,
		`React version["']?\s*[:=]\s*["']?([0-9.]+)`,
	}
	
	for _, pattern := range patterns {
		if matches := regexp.MustCompile(pattern).FindStringSubmatch(content); len(matches) > 1 {
			return matches[1]
		}
	}
	return ""
 }

 func (d *Detector) extractVueVersion(content string) string {
	patterns := []string{
		`vue@([0-9.]+)`,
		`Vue\.version\s*=\s*["']([0-9.]+)`,
		`vue\.js@([0-9.]+)`,
	}
	
	for _, pattern := range patterns {
		if matches := regexp.MustCompile(pattern).FindStringSubmatch(content); len(matches) > 1 {
			return matches[1]
		}
	}
	return ""
 }

 func (d *Detector) extractAngularVersion(content string) string {
	patterns := []string{
		`angular@([0-9.]+)`,
		`angular\.js@([0-9.]+)`,
		`ng-version=["']([0-9.]+)`,
	}
	
	for _, pattern := range patterns {
		if matches := regexp.MustCompile(pattern).FindStringSubmatch(content); len(matches) > 1 {
			return matches[1]
		}
	}
	return ""
 }

 func (d *Detector) extractSvelteVersion(content string) string {
	if matches := regexp.MustCompile(`svelte@([0-9.]+)`).FindStringSubmatch(content); len(matches) > 1 {
		return matches[1]
	}
	return ""
 }

// ToJSON returns detection as JSON
 func (d *Detection) ToJSON() ([]byte, error) {
	return json.MarshalIndent(d, "", "  ")
 }

// IsSPA returns true if the platform is a Single Page Application
 func (d *Detection) IsSPA() bool {
	return d.PlatformType == SPA || d.PlatformType == Hybrid
 }

// IsStatic returns true if the platform is a static site
 func (d *Detection) IsStatic() bool {
	return d.PlatformType == StaticSite
 }