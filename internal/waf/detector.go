// Package waf provides WAF detection and bypass capabilities
package waf

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// WAFType represents a known WAF vendor
type WAFType string

const (
	WAFUnknown     WAFType = "unknown"
	WAFCloudflare  WAFType = "cloudflare"
	WAFAkamai      WAFType = "akamai"
	WAFImperva     WAFType = "imperva"
	WAFModSecurity WAFType = "modsecurity"
	WAFAFW         WAFType = "aws-waf"
	WAFSuccuri     WAFType = "sucuri"
	WAFBarracuda   WAFType = "barracuda"
	WAFCitrix      WAFType = "citrix-adc"
	WAFNginx       WAFType = "nginx-naxsi"
	WAFStackPath   WAFType = "stackpath"
	WAFIncapsula   WAFType = "incapsula"
	WAFBIG_IP_ASM  WAFType = "f5-big-ip-asm"
	WAFFortiWeb    WAFType = "fortiweb"
	WAFPaloAlto    WAFType = "palo-alto"
	WAFRadware     WAFType = "radware"
	WAFReblaze     WAFType = "reblaze"
	WAFSafedog     WAFType = "safedog"
	WAFKona        WAFType = "akamai-kona"
	WAFWordfence   WAFType = "wordfence"
)

// DetectionResult holds WAF fingerprinting results
type DetectionResult struct {
	WAFType       WAFType           `json:"waf_type"`
	Confidence    int               `json:"confidence"` // 0-100
	Evidence      []string          `json:"evidence"`
	Headers       map[string]string `json:"headers,omitempty"`
	Cookies       []string          `json:"cookies,omitempty"`
	BlockingBehavior string         `json:"blocking_behavior,omitempty"`
}

// Detector provides WAF fingerprinting capabilities
type Detector struct {
	httpClient *http.Client
	timeout    time.Duration
	userAgent  string
}

// DetectorOption configures the WAF detector
type DetectorOption func(*Detector)

// WithTimeout sets the HTTP timeout
func WithTimeout(timeout time.Duration) DetectorOption {
	return func(d *Detector) {
		d.timeout = timeout
	}
}

// WithUserAgent sets a custom user agent
func WithUserAgent(ua string) DetectorOption {
	return func(d *Detector) {
		d.userAgent = ua
	}
}

// NewDetector creates a new WAF detector
func NewDetector(opts ...DetectorOption) *Detector {
	d := &Detector{
		timeout:   30 * time.Second,
		userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	}

	for _, opt := range opts {
		opt(d)
	}

	d.httpClient = &http.Client{
		Timeout: d.timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return d
}

// WAF fingerprint signatures
type wafSignature struct {
	WAFType        WAFType
	HeaderPatterns map[string]*regexp.Regexp
	CookiePatterns []*regexp.Regexp
	BodyPatterns   []*regexp.Regexp
	StatusCodes    []int
}

var wafSignatures = []wafSignature{
	{
		WAFType: WAFCloudflare,
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server":     regexp.MustCompile(`(?i)cloudflare`),
			"CF-RAY":     regexp.MustCompile(`.+`),
			"CF-Cache-Status": regexp.MustCompile(`.+`),
			"cf-request-id":   regexp.MustCompile(`.+`),
		},
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)__cf_bm`),
			regexp.MustCompile(`(?i)cf_clearance`),
			regexp.MustCompile(`(?i)__cfduid`),
			regexp.MustCompile(`(?i)__cfruid`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)cloudflare`),
			regexp.MustCompile(`(?i)ray\s*id`),
			regexp.MustCompile(`(?i)attention\s+required`),
			regexp.MustCompile(`(?i)checking your browser`),
		},
	},
	{
		WAFType: WAFAkamai,
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server":        regexp.MustCompile(`(?i)akamai`),
			"X-Akamai-Transformed": regexp.MustCompile(`.+`),
			"Akamai-GRN":    regexp.MustCompile(`.+`),
			"X-Akamai-Session-Info": regexp.MustCompile(`.+`),
		},
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)akamai_`),
			regexp.MustCompile(`(?i)akavpau_`),
			regexp.MustCompile(`(?i)_abck`),
			regexp.MustCompile(`(?i)bm_sz`),
			regexp.MustCompile(`(?i)ak_bmsc`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)akamai`),
			regexp.MustCompile(`(?i)reference\s*#[0-9]+\.[0-9a-f]+`),
		},
	},
	{
		WAFType: WAFKona,
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)akamai.*ghost`),
			"X-Kona-Error": regexp.MustCompile(`.+`),
		},
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)kona`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)kona site defender`),
		},
	},
	{
		WAFType: WAFImperva,
		HeaderPatterns: map[string]*regexp.Regexp{
			"X-Iinfo":     regexp.MustCompile(`.+`),
			"X-CDN":       regexp.MustCompile(`(?i)imperva`),
		},
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)incap_ses_`),
			regexp.MustCompile(`(?i)visid_incap_`),
			regexp.MustCompile(`(?i)nlbi_`),
			regexp.MustCompile(`(?i)reese84`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)incapsula`),
			regexp.MustCompile(`(?i)imperva`),
			regexp.MustCompile(`(?i)incident\s*id`),
			regexp.MustCompile(`(?i)_incapsula_resource`),
		},
	},
	{
		WAFType: WAFIncapsula,
		HeaderPatterns: map[string]*regexp.Regexp{
			"X-CDN": regexp.MustCompile(`(?i)incapsula`),
		},
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)incap_ses`),
			regexp.MustCompile(`(?i)visid_incap`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)incapsula incident`),
		},
	},
	{
		WAFType: WAFModSecurity,
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)mod_security|NOYB`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)mod_security`),
			regexp.MustCompile(`(?i)modsecurity`),
			regexp.MustCompile(`(?i)this error was generated by mod_security`),
			regexp.MustCompile(`(?i)not acceptable`),
			regexp.MustCompile(`(?i)method not implemented`),
		},
		StatusCodes: []int{406, 501},
	},
	{
		WAFType: WAFAFW,
		HeaderPatterns: map[string]*regexp.Regexp{
			"X-AMZ-CF-ID":    regexp.MustCompile(`.+`),
			"X-AMZ-ID-2":     regexp.MustCompile(`.+`),
			"X-AMZN-RequestId": regexp.MustCompile(`.+`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)aws.*waf`),
			regexp.MustCompile(`(?i)request blocked`),
			regexp.MustCompile(`(?i)awselb`),
		},
	},
	{
		WAFType: WAFSuccuri,
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server":         regexp.MustCompile(`(?i)sucuri`),
			"X-Sucuri-ID":    regexp.MustCompile(`.+`),
			"X-Sucuri-Block": regexp.MustCompile(`.+`),
			"X-Sucuri-Cache": regexp.MustCompile(`.+`),
		},
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)sucuri_`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)sucuri`),
			regexp.MustCompile(`(?i)cloudproxy`),
			regexp.MustCompile(`(?i)access denied.*sucuri`),
		},
	},
	{
		WAFType: WAFBarracuda,
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)barracuda`),
		},
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)barra_counter_session`),
			regexp.MustCompile(`(?i)BNI__BARRACUDA_LB_COOKIE`),
			regexp.MustCompile(`(?i)BNI_persistence`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)barracuda`),
		},
	},
	{
		WAFType: WAFCitrix,
		HeaderPatterns: map[string]*regexp.Regexp{
			"Via":     regexp.MustCompile(`(?i)citrix|netscaler|ns-`),
			"X-NS-ID": regexp.MustCompile(`.+`),
		},
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)citrix_ns_id`),
			regexp.MustCompile(`(?i)NSC_`),
			regexp.MustCompile(`(?i)ns_af`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)citrix`),
			regexp.MustCompile(`(?i)netscaler`),
			regexp.MustCompile(`(?i)ns_af=`),
		},
	},
	{
		WAFType: WAFNginx,
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)naxsi|nginx.*waf`),
			"X-NAXSI-SIG": regexp.MustCompile(`.+`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)naxsi`),
			regexp.MustCompile(`(?i)blocked by naxsi`),
		},
	},
	{
		WAFType: WAFStackPath,
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server":             regexp.MustCompile(`(?i)stackpath|maxcdn|netdna`),
			"X-SP-Edge-Host":     regexp.MustCompile(`.+`),
			"X-SP-URL":           regexp.MustCompile(`.+`),
			"X-SP-WAF-Reason":    regexp.MustCompile(`.+`),
		},
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)stackpath`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)stackpath`),
			regexp.MustCompile(`(?i)maxcdn`),
		},
	},
	{
		WAFType: WAFBIG_IP_ASM,
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server":     regexp.MustCompile(`(?i)bigip|big-ip|f5`),
			"X-Cnection": regexp.MustCompile(`(?i)close`),
		},
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)BIGipServer`),
			regexp.MustCompile(`(?i)TS[0-9a-f]{6,}`),
			regexp.MustCompile(`(?i)F5_`),
			regexp.MustCompile(`(?i)f5avraaaaaaa`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)the requested url was rejected`),
			regexp.MustCompile(`(?i)support id`),
			regexp.MustCompile(`(?i)big-ip|f5 networks`),
		},
	},
	{
		WAFType: WAFFortiWeb,
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)fortiweb`),
		},
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)FORTIWAFSID`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)fortiweb`),
			regexp.MustCompile(`(?i)fortigate`),
		},
	},
	{
		WAFType: WAFRadware,
		HeaderPatterns: map[string]*regexp.Regexp{
			"X-SL-CompState": regexp.MustCompile(`.+`),
		},
		CookiePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)rd[0-9]+`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)radware`),
			regexp.MustCompile(`(?i)appwall`),
			regexp.MustCompile(`(?i)unauthorized activity`),
		},
	},
	{
		WAFType: WAFWordfence,
		HeaderPatterns: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`(?i)wordfence`),
		},
		BodyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)wordfence`),
			regexp.MustCompile(`(?i)this response was generated by wordfence`),
			regexp.MustCompile(`(?i)block reason:`),
			regexp.MustCompile(`(?i)your access to this site has been limited`),
		},
	},
}

// Detect performs WAF fingerprinting on a target URL
func (d *Detector) Detect(targetURL string) (*DetectionResult, error) {
	return d.DetectWithContext(context.Background(), targetURL)
}

// DetectWithContext performs WAF fingerprinting with context
func (d *Detector) DetectWithContext(ctx context.Context, targetURL string) (*DetectionResult, error) {
	result := &DetectionResult{
		WAFType:    WAFUnknown,
		Confidence: 0,
		Evidence:   []string{},
		Headers:    make(map[string]string),
	}

	// Send normal request
	normalResp, normalBody, err := d.sendRequest(ctx, targetURL, false)
	if err != nil {
		return result, err
	}

	// Analyze normal response
	d.analyzeResponse(normalResp, normalBody, result)

	// Send malicious request to trigger WAF
	maliciousResp, maliciousBody, err := d.sendRequest(ctx, targetURL, true)
	if err == nil {
		d.analyzeResponse(maliciousResp, maliciousBody, result)

		// Check for blocking behavior
		if maliciousResp.StatusCode == 403 || maliciousResp.StatusCode == 406 || maliciousResp.StatusCode == 501 {
			result.Evidence = append(result.Evidence, "Blocking status code on malicious request")
			result.Confidence += 20
			result.BlockingBehavior = "blocks_malicious_requests"
		}
	}

	// Normalize confidence
	if result.Confidence > 100 {
		result.Confidence = 100
	}

	return result, nil
}

func (d *Detector) sendRequest(ctx context.Context, targetURL string, malicious bool) (*http.Response, string, error) {
	url := targetURL
	if malicious {
		// Add XSS test payload to trigger WAF
		if strings.Contains(url, "?") {
			url += "&test=<script>alert(1)</script>"
		} else {
			url += "?test=<script>alert(1)</script>"
		}
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, "", err
	}

	req.Header.Set("User-Agent", d.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // Limit to 1MB
	if err != nil {
		return resp, "", err
	}

	return resp, string(body), nil
}

func (d *Detector) analyzeResponse(resp *http.Response, body string, result *DetectionResult) {
	// Store relevant headers
	for name, values := range resp.Header {
		if len(values) > 0 {
			result.Headers[name] = values[0]
		}
	}

	// Extract cookies
	for _, cookie := range resp.Cookies() {
		result.Cookies = append(result.Cookies, cookie.Name)
	}

	// Match against WAF signatures
	for _, sig := range wafSignatures {
		matchScore := 0
		var evidence []string

		// Check headers
		for headerName, pattern := range sig.HeaderPatterns {
			if headerValue := resp.Header.Get(headerName); headerValue != "" {
				if pattern.MatchString(headerValue) {
					matchScore += 30
					evidence = append(evidence, "Header match: "+headerName)
				}
			}
		}

		// Check cookies
		for _, cookie := range resp.Cookies() {
			for _, pattern := range sig.CookiePatterns {
				if pattern.MatchString(cookie.Name) {
					matchScore += 25
					evidence = append(evidence, "Cookie match: "+cookie.Name)
				}
			}
		}

		// Check body patterns
		for _, pattern := range sig.BodyPatterns {
			if pattern.MatchString(body) {
				matchScore += 20
				match := pattern.FindString(body)
				if len(match) > 50 {
					match = match[:50] + "..."
				}
				evidence = append(evidence, "Body pattern: "+match)
			}
		}

		// Check status codes
		for _, code := range sig.StatusCodes {
			if resp.StatusCode == code {
				matchScore += 15
				evidence = append(evidence, "Status code match: "+resp.Status)
			}
		}

		// Update result if this WAF has higher confidence
		if matchScore > result.Confidence {
			result.WAFType = sig.WAFType
			result.Confidence = matchScore
			result.Evidence = evidence
		}
	}
}

// GetBypassStrategies returns recommended bypass strategies for a WAF type
func GetBypassStrategies(wafType WAFType) []string {
	strategies := map[WAFType][]string{
		WAFCloudflare: {
			"Use Unicode encoding for payloads",
			"Try null byte injection",
			"Use case variation in tags",
			"Attempt chunked transfer encoding",
			"Try JavaScript protocol variations",
		},
		WAFAkamai: {
			"Double URL encoding",
			"Mixed case keywords",
			"Comment insertion in payloads",
			"Parameter pollution",
			"Use backtick instead of parentheses",
		},
		WAFKona: {
			"Double URL encoding",
			"HTTP parameter pollution",
			"Case variation",
			"Comment insertion",
		},
		WAFImperva: {
			"Whitespace variations",
			"HTML entity encoding",
			"Mixed encoding schemes",
			"Protocol handler variations",
			"Unicode normalization bypass",
		},
		WAFIncapsula: {
			"Unicode encoding",
			"Case variation",
			"Null byte insertion",
			"Comment-based bypass",
		},
		WAFModSecurity: {
			"Comment insertion",
			"Case variation",
			"Null byte injection",
			"Whitespace variations",
			"Parameterized payloads",
		},
		WAFAFW: {
			"Double URL encoding",
			"HTTP parameter pollution",
			"Content-Type confusion",
			"Multipart form data bypass",
		},
		WAFSuccuri: {
			"Unicode encoding",
			"Case mixing",
			"Whitespace injection",
			"Protocol variations",
		},
		WAFBarracuda: {
			"URL encoding",
			"Case variations",
			"Null byte injection",
			"Chunked encoding",
		},
		WAFCitrix: {
			"Double encoding",
			"Case variations",
			"Whitespace bypass",
			"Comment insertion",
		},
		WAFNginx: {
			"URL encoding",
			"Unicode normalization",
			"Whitespace variations",
			"Case mixing",
		},
		WAFStackPath: {
			"URL encoding",
			"Case variations",
			"Comment bypass",
			"Chunked transfer",
		},
		WAFBIG_IP_ASM: {
			"Double URL encoding",
			"Case variations",
			"Parameter pollution",
			"Content-Type bypass",
		},
		WAFFortiWeb: {
			"URL encoding",
			"Unicode bypass",
			"Case mixing",
			"Null bytes",
		},
		WAFRadware: {
			"Double encoding",
			"Case variation",
			"Comment insertion",
			"Whitespace bypass",
		},
		WAFWordfence: {
			"URL encoding",
			"Case variations",
			"Whitespace injection",
			"Parameter splitting",
		},
		WAFUnknown: {
			"Try all encoding types",
			"Test case variations",
			"Attempt null byte injection",
			"Use comment insertion",
			"Try parameter pollution",
		},
	}

	if s, ok := strategies[wafType]; ok {
		return s
	}
	return strategies[WAFUnknown]
}

// IsBlocking returns true if the WAF appears to be blocking requests
func (d *Detector) IsBlocking(targetURL string) bool {
	result, err := d.Detect(targetURL)
	if err != nil {
		return false
	}
	return result.BlockingBehavior != ""
}

// String returns a human-readable name for the WAF type
func (w WAFType) String() string {
	names := map[WAFType]string{
		WAFUnknown:     "Unknown WAF",
		WAFCloudflare:  "Cloudflare",
		WAFAkamai:      "Akamai",
		WAFImperva:     "Imperva/Incapsula",
		WAFModSecurity: "ModSecurity",
		WAFAFW:         "AWS WAF",
		WAFSuccuri:     "Sucuri",
		WAFBarracuda:   "Barracuda",
		WAFCitrix:      "Citrix ADC/NetScaler",
		WAFNginx:       "Nginx Naxsi",
		WAFStackPath:   "StackPath",
		WAFIncapsula:   "Incapsula",
		WAFBIG_IP_ASM:  "F5 BIG-IP ASM",
		WAFFortiWeb:    "FortiWeb",
		WAFPaloAlto:    "Palo Alto",
		WAFRadware:     "Radware AppWall",
		WAFReblaze:     "Reblaze",
		WAFSafedog:     "Safedog",
		WAFKona:        "Akamai Kona",
		WAFWordfence:   "Wordfence",
	}
	if name, ok := names[w]; ok {
		return name
	}
	return string(w)
}
