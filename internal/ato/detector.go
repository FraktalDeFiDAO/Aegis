// Package ato provides Account Takeover vulnerability detection
package ato

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// ATOType represents a type of account takeover vulnerability
type ATOType string

const (
	ATOSessionFixation     ATOType = "session_fixation"
	ATOWeakSessionToken    ATOType = "weak_session_token"
	ATOMissingHttpOnly     ATOType = "missing_httponly"
	ATOMissingSecure       ATOType = "missing_secure"
	ATOMissingSameSite     ATOType = "missing_samesite"
	ATOCSRFTokenIssue      ATOType = "csrf_token_issue"
	ATOPasswordResetFlaw   ATOType = "password_reset_flaw"
	ATOOAuthMisconfigured  ATOType = "oauth_misconfigured"
	ATOJWTWeakness         ATOType = "jwt_weakness"
	ATOBruteForceVuln      ATOType = "brute_force_vulnerable"
	ATOAccountEnumeration  ATOType = "account_enumeration"
	ATOInsecureRememberMe  ATOType = "insecure_remember_me"
	ATOTokenInURL          ATOType = "token_in_url"
	ATOConcurrentSessions  ATOType = "concurrent_sessions"
	ATOInsecureLogout      ATOType = "insecure_logout"
)

// Severity levels
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// ATOFinding represents an ATO vulnerability finding
type ATOFinding struct {
	Type        ATOType  `json:"type"`
	Severity    Severity `json:"severity"`
	CVSS        float64  `json:"cvss"`
	CWE         string   `json:"cwe"`
	URL         string   `json:"url"`
	Evidence    string   `json:"evidence"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation"`
	References  []string `json:"references,omitempty"`
}

// Detector provides ATO vulnerability detection
type Detector struct {
	httpClient *http.Client
	timeout    time.Duration
	userAgent  string
}

// DetectorOption configures the ATO detector
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

// NewDetector creates a new ATO detector
func NewDetector(opts ...DetectorOption) *Detector {
	d := &Detector{
		timeout:   30 * time.Second,
		userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
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

// DetectAll performs comprehensive ATO vulnerability detection
func (d *Detector) DetectAll(targetURL string) []ATOFinding {
	return d.DetectAllWithContext(context.Background(), targetURL)
}

// DetectAllWithContext performs ATO detection with context
func (d *Detector) DetectAllWithContext(ctx context.Context, targetURL string) []ATOFinding {
	var findings []ATOFinding

	// Get initial response for analysis
	resp, body, err := d.sendRequest(ctx, targetURL)
	if err != nil {
		return findings
	}

	// Check session cookies
	findings = append(findings, d.checkSessionCookies(resp, targetURL)...)

	// Check for JWT issues
	findings = append(findings, d.checkJWTIssues(resp, body, targetURL)...)

	// Check CSRF protection
	findings = append(findings, d.checkCSRFProtection(body, targetURL)...)

	// Check OAuth configurations
	findings = append(findings, d.checkOAuthConfig(body, targetURL)...)

	// Check password reset patterns
	findings = append(findings, d.checkPasswordReset(body, targetURL)...)

	// Check for tokens in URLs
	findings = append(findings, d.checkTokenInURL(resp, targetURL)...)

	// Check authentication headers
	findings = append(findings, d.checkAuthHeaders(resp, targetURL)...)

	return findings
}

func (d *Detector) sendRequest(ctx context.Context, targetURL string) (*http.Response, string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, "", err
	}

	req.Header.Set("User-Agent", d.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return resp, "", err
	}

	return resp, string(body), nil
}

// checkSessionCookies analyzes session cookie security
func (d *Detector) checkSessionCookies(resp *http.Response, targetURL string) []ATOFinding {
	var findings []ATOFinding

	sessionCookiePatterns := []string{
		"session", "sess", "sid", "jsessionid", "phpsessid", "aspsession",
		"auth", "token", "jwt", "access_token", "refresh_token", "remember",
	}

	for _, cookie := range resp.Cookies() {
		cookieName := strings.ToLower(cookie.Name)
		isSessionCookie := false

		for _, pattern := range sessionCookiePatterns {
			if strings.Contains(cookieName, pattern) {
				isSessionCookie = true
				break
			}
		}

		if !isSessionCookie {
			continue
		}

		// Check HttpOnly flag
		if !cookie.HttpOnly {
			findings = append(findings, ATOFinding{
				Type:        ATOMissingHttpOnly,
				Severity:    SeverityHigh,
				CVSS:        6.1,
				CWE:         "CWE-1004",
				URL:         targetURL,
				Evidence:    fmt.Sprintf("Cookie '%s' is missing HttpOnly flag", cookie.Name),
				Description: "Session cookie is accessible via JavaScript, enabling XSS-based session theft",
				Remediation: "Set HttpOnly flag on all session cookies",
				References:  []string{"https://owasp.org/www-community/HttpOnly"},
			})
		}

		// Check Secure flag (if HTTPS)
		if strings.HasPrefix(targetURL, "https://") && !cookie.Secure {
			findings = append(findings, ATOFinding{
				Type:        ATOMissingSecure,
				Severity:    SeverityMedium,
				CVSS:        5.3,
				CWE:         "CWE-614",
				URL:         targetURL,
				Evidence:    fmt.Sprintf("Cookie '%s' is missing Secure flag", cookie.Name),
				Description: "Session cookie can be transmitted over unencrypted connections",
				Remediation: "Set Secure flag on all session cookies when using HTTPS",
				References:  []string{"https://owasp.org/www-community/controls/SecureCookieAttribute"},
			})
		}

		// Check SameSite attribute
		if cookie.SameSite == http.SameSiteDefaultMode || cookie.SameSite == 0 {
			findings = append(findings, ATOFinding{
				Type:        ATOMissingSameSite,
				Severity:    SeverityMedium,
				CVSS:        4.3,
				CWE:         "CWE-1275",
				URL:         targetURL,
				Evidence:    fmt.Sprintf("Cookie '%s' is missing SameSite attribute", cookie.Name),
				Description: "Session cookie may be sent with cross-site requests, enabling CSRF attacks",
				Remediation: "Set SameSite=Strict or SameSite=Lax on session cookies",
				References:  []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"},
			})
		}

		// Check for weak session token
		if len(cookie.Value) < 16 {
			findings = append(findings, ATOFinding{
				Type:        ATOWeakSessionToken,
				Severity:    SeverityHigh,
				CVSS:        7.5,
				CWE:         "CWE-330",
				URL:         targetURL,
				Evidence:    fmt.Sprintf("Cookie '%s' has short value (length: %d)", cookie.Name, len(cookie.Value)),
				Description: "Session token appears too short, may be predictable",
				Remediation: "Use cryptographically secure random tokens of at least 128 bits",
				References:  []string{"https://owasp.org/www-community/vulnerabilities/Insufficient_Session-ID_Length"},
			})
		}

		// Check for predictable patterns in session token
		if d.isTokenPredictable(cookie.Value) {
			findings = append(findings, ATOFinding{
				Type:        ATOWeakSessionToken,
				Severity:    SeverityCritical,
				CVSS:        9.1,
				CWE:         "CWE-330",
				URL:         targetURL,
				Evidence:    fmt.Sprintf("Cookie '%s' appears to have predictable pattern", cookie.Name),
				Description: "Session token appears to follow a predictable pattern",
				Remediation: "Use cryptographically secure random number generator for session tokens",
				References:  []string{"https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"},
			})
		}
	}

	return findings
}

// isTokenPredictable checks if a token appears to have predictable patterns
func (d *Detector) isTokenPredictable(token string) bool {
	// Check for sequential numbers
	seqPattern := regexp.MustCompile(`^\d+$`)
	if seqPattern.MatchString(token) {
		return true
	}

	// Check for timestamp-based tokens
	timestampPattern := regexp.MustCompile(`^[0-9]{10,13}$`)
	if timestampPattern.MatchString(token) {
		return true
	}

	// Check for base64 encoded sequential data
	if decoded, err := base64.StdEncoding.DecodeString(token); err == nil {
		if seqPattern.MatchString(string(decoded)) {
			return true
		}
	}

	// Check for very low entropy (e.g., "aaaaaa" or "123456")
	if len(token) > 4 {
		uniqueChars := make(map[rune]bool)
		for _, c := range token {
			uniqueChars[c] = true
		}
		// If less than 3 unique characters in a token of 6+, it's predictable
		if len(uniqueChars) <= 2 {
			return true
		}
	}

	return false
}

// checkJWTIssues analyzes JWT tokens for vulnerabilities
func (d *Detector) checkJWTIssues(resp *http.Response, body, targetURL string) []ATOFinding {
	var findings []ATOFinding

	// Look for JWTs in cookies
	for _, cookie := range resp.Cookies() {
		if d.isJWT(cookie.Value) {
			findings = append(findings, d.analyzeJWT(cookie.Value, targetURL, "cookie:"+cookie.Name)...)
		}
	}

	// Look for JWTs in response headers
	for name, values := range resp.Header {
		for _, value := range values {
			if d.isJWT(value) {
				findings = append(findings, d.analyzeJWT(value, targetURL, "header:"+name)...)
			}
		}
	}

	// Look for JWTs in response body
	jwtPattern := regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
	matches := jwtPattern.FindAllString(body, -1)
	for _, match := range matches {
		findings = append(findings, d.analyzeJWT(match, targetURL, "body")...)
	}

	return findings
}

// isJWT checks if a string appears to be a JWT
func (d *Detector) isJWT(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	return strings.HasPrefix(parts[0], "eyJ")
}

// analyzeJWT checks a JWT for security issues
func (d *Detector) analyzeJWT(token, targetURL, location string) []ATOFinding {
	var findings []ATOFinding

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return findings
	}

	// Decode header
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return findings
	}

	var headerData map[string]interface{}
	if err := json.Unmarshal(header, &headerData); err != nil {
		return findings
	}

	// Check for "alg": "none"
	if alg, ok := headerData["alg"].(string); ok {
		if strings.ToLower(alg) == "none" {
			findings = append(findings, ATOFinding{
				Type:        ATOJWTWeakness,
				Severity:    SeverityCritical,
				CVSS:        9.8,
				CWE:         "CWE-327",
				URL:         targetURL,
				Evidence:    fmt.Sprintf("JWT at %s uses 'none' algorithm", location),
				Description: "JWT uses 'none' algorithm, allowing signature bypass",
				Remediation: "Reject JWTs with 'none' algorithm; use HS256 or RS256",
				References:  []string{"https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"},
			})
		}

		// Check for weak algorithms
		weakAlgs := []string{"hs256", "hs384", "hs512"}
		for _, weak := range weakAlgs {
			if strings.ToLower(alg) == weak {
				findings = append(findings, ATOFinding{
					Type:        ATOJWTWeakness,
					Severity:    SeverityMedium,
					CVSS:        5.9,
					CWE:         "CWE-327",
					URL:         targetURL,
					Evidence:    fmt.Sprintf("JWT at %s uses symmetric algorithm: %s", location, alg),
					Description: "JWT uses symmetric algorithm which may be vulnerable to brute force if secret is weak",
					Remediation: "Consider using asymmetric algorithms (RS256, ES256) for better security",
					References:  []string{"https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"},
				})
				break
			}
		}
	}

	// Decode payload to check for sensitive data and expiry
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return findings
	}

	var payloadData map[string]interface{}
	if err := json.Unmarshal(payload, &payloadData); err != nil {
		return findings
	}

	// Check for missing expiry
	if _, hasExp := payloadData["exp"]; !hasExp {
		findings = append(findings, ATOFinding{
			Type:        ATOJWTWeakness,
			Severity:    SeverityMedium,
			CVSS:        5.4,
			CWE:         "CWE-613",
			URL:         targetURL,
			Evidence:    fmt.Sprintf("JWT at %s has no expiration claim", location),
			Description: "JWT has no expiration, tokens remain valid indefinitely",
			Remediation: "Include 'exp' claim with reasonable expiration time",
			References:  []string{"https://tools.ietf.org/html/rfc7519#section-4.1.4"},
		})
	}

	// Check for sensitive data in payload
	sensitiveKeys := []string{"password", "secret", "private", "ssn", "credit_card", "cvv"}
	for key := range payloadData {
		for _, sensitive := range sensitiveKeys {
			if strings.Contains(strings.ToLower(key), sensitive) {
				findings = append(findings, ATOFinding{
					Type:        ATOJWTWeakness,
					Severity:    SeverityHigh,
					CVSS:        7.5,
					CWE:         "CWE-311",
					URL:         targetURL,
					Evidence:    fmt.Sprintf("JWT contains potentially sensitive field: %s", key),
					Description: "JWT payload contains sensitive data that should not be exposed",
					Remediation: "Remove sensitive data from JWT payload; use encrypted JWTs (JWE) if needed",
					References:  []string{"https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"},
				})
			}
		}
	}

	return findings
}

// checkCSRFProtection analyzes CSRF protection mechanisms
func (d *Detector) checkCSRFProtection(body, targetURL string) []ATOFinding {
	var findings []ATOFinding

	// Look for forms
	formPattern := regexp.MustCompile(`(?i)<form[^>]*>`)
	postFormPattern := regexp.MustCompile(`(?i)<form[^>]*method\s*=\s*["']?post`)
	csrfInputPattern := regexp.MustCompile(`(?i)<input[^>]*name\s*=\s*["']?(_?csrf|_?token|authenticity_token|__RequestVerificationToken|antiforgery)`)

	// Find all forms
	forms := formPattern.FindAllStringIndex(body, -1)
	postForms := postFormPattern.FindAllString(body, -1)

	if len(postForms) > 0 {
		// Check if CSRF tokens exist
		csrfInputs := csrfInputPattern.FindAllString(body, -1)

		if len(csrfInputs) == 0 {
			findings = append(findings, ATOFinding{
				Type:        ATOCSRFTokenIssue,
				Severity:    SeverityMedium,
				CVSS:        6.5,
				CWE:         "CWE-352",
				URL:         targetURL,
				Evidence:    fmt.Sprintf("Found %d POST forms but no CSRF tokens detected", len(postForms)),
				Description: "Forms appear to lack CSRF protection tokens",
				Remediation: "Implement CSRF tokens in all state-changing forms",
				References:  []string{"https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"},
			})
		} else if len(csrfInputs) < len(forms) {
			findings = append(findings, ATOFinding{
				Type:        ATOCSRFTokenIssue,
				Severity:    SeverityLow,
				CVSS:        4.3,
				CWE:         "CWE-352",
				URL:         targetURL,
				Evidence:    fmt.Sprintf("Found %d forms but only %d CSRF tokens", len(forms), len(csrfInputs)),
				Description: "Some forms may lack CSRF protection",
				Remediation: "Ensure all state-changing forms include CSRF tokens",
				References:  []string{"https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"},
			})
		}
	}

	return findings
}

// checkOAuthConfig checks for OAuth misconfigurations
func (d *Detector) checkOAuthConfig(body, targetURL string) []ATOFinding {
	var findings []ATOFinding

	// Look for OAuth redirect URLs
	oauthRedirectPattern := regexp.MustCompile(`(?i)(redirect_uri|callback)\s*[=:]\s*["']?([^"'\s&]+)`)
	matches := oauthRedirectPattern.FindAllStringSubmatch(body, -1)

	for _, match := range matches {
		if len(match) > 2 {
			redirectURL := match[2]

			// Check for open redirect in redirect_uri
			if strings.Contains(redirectURL, "//") || strings.HasPrefix(redirectURL, "/") {
				// Potentially safe relative URL
				continue
			}

			// Check if redirect_uri validation appears weak
			if strings.Contains(redirectURL, "*") || strings.Contains(redirectURL, "localhost") {
				findings = append(findings, ATOFinding{
					Type:        ATOOAuthMisconfigured,
					Severity:    SeverityHigh,
					CVSS:        7.4,
					CWE:         "CWE-601",
					URL:         targetURL,
					Evidence:    fmt.Sprintf("OAuth redirect_uri may be misconfigured: %s", redirectURL),
					Description: "OAuth redirect_uri may allow open redirect attacks",
					Remediation: "Strictly validate redirect_uri against whitelist of allowed URLs",
					References:  []string{"https://portswigger.net/web-security/oauth"},
				})
			}
		}
	}

	// Check for missing state parameter
	oauthURLPattern := regexp.MustCompile(`(?i)oauth|authorize\?`)
	if oauthURLPattern.MatchString(body) {
		statePattern := regexp.MustCompile(`(?i)state\s*=`)
		if !statePattern.MatchString(body) {
			findings = append(findings, ATOFinding{
				Type:        ATOOAuthMisconfigured,
				Severity:    SeverityMedium,
				CVSS:        6.1,
				CWE:         "CWE-352",
				URL:         targetURL,
				Evidence:    "OAuth flow detected without state parameter",
				Description: "OAuth implementation may be missing state parameter for CSRF protection",
				Remediation: "Include cryptographically random state parameter in OAuth requests",
				References:  []string{"https://datatracker.ietf.org/doc/html/rfc6749#section-10.12"},
			})
		}
	}

	return findings
}

// checkPasswordReset checks for password reset vulnerabilities
func (d *Detector) checkPasswordReset(body, targetURL string) []ATOFinding {
	var findings []ATOFinding

	// Check for password reset tokens in URLs
	resetPatterns := []string{
		`(?i)reset[_-]?token\s*[=:]\s*["']?([a-zA-Z0-9]{8,})`,
		`(?i)forgot[_-]?password.*token\s*[=:]\s*["']?([a-zA-Z0-9]{8,})`,
		`(?i)recovery[_-]?token\s*[=:]\s*["']?([a-zA-Z0-9]{8,})`,
	}

	for _, pattern := range resetPatterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(body, -1)

		for _, match := range matches {
			if len(match) > 1 {
				token := match[1]

				// Check token length
				if len(token) < 32 {
					findings = append(findings, ATOFinding{
						Type:        ATOPasswordResetFlaw,
						Severity:    SeverityHigh,
						CVSS:        7.5,
						CWE:         "CWE-640",
						URL:         targetURL,
						Evidence:    fmt.Sprintf("Short password reset token detected (length: %d)", len(token)),
						Description: "Password reset token appears too short, may be predictable",
						Remediation: "Use cryptographically secure tokens of at least 256 bits",
						References:  []string{"https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html"},
					})
				}

				// Check for predictable patterns
				if d.isTokenPredictable(token) {
					findings = append(findings, ATOFinding{
						Type:        ATOPasswordResetFlaw,
						Severity:    SeverityCritical,
						CVSS:        9.1,
						CWE:         "CWE-640",
						URL:         targetURL,
						Evidence:    "Password reset token appears predictable",
						Description: "Password reset token may follow predictable pattern",
						Remediation: "Use cryptographically secure random number generator",
						References:  []string{"https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html"},
					})
				}
			}
		}
	}

	return findings
}

// checkTokenInURL checks for tokens exposed in URLs
func (d *Detector) checkTokenInURL(resp *http.Response, targetURL string) []ATOFinding {
	var findings []ATOFinding

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return findings
	}

	// Check for sensitive tokens in URL parameters
	sensitiveParams := []string{
		"token", "access_token", "auth_token", "api_key", "apikey",
		"session", "sessionid", "sid", "jwt", "bearer",
		"password", "secret", "key", "credential",
	}

	query := parsedURL.Query()
	for _, param := range sensitiveParams {
		if query.Get(param) != "" {
			findings = append(findings, ATOFinding{
				Type:        ATOTokenInURL,
				Severity:    SeverityMedium,
				CVSS:        5.3,
				CWE:         "CWE-598",
				URL:         targetURL,
				Evidence:    fmt.Sprintf("Sensitive parameter '%s' found in URL", param),
				Description: "Sensitive tokens in URLs may leak via referrer headers, logs, and browser history",
				Remediation: "Use POST requests or HTTP headers for sensitive tokens",
				References:  []string{"https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url"},
			})
		}
	}

	// Check Location header for sensitive data in redirects
	location := resp.Header.Get("Location")
	if location != "" {
		for _, param := range sensitiveParams {
			if strings.Contains(strings.ToLower(location), param+"=") {
				findings = append(findings, ATOFinding{
					Type:        ATOTokenInURL,
					Severity:    SeverityMedium,
					CVSS:        5.3,
					CWE:         "CWE-598",
					URL:         targetURL,
					Evidence:    fmt.Sprintf("Sensitive parameter '%s' found in redirect URL", param),
					Description: "Redirect URL contains sensitive token",
					Remediation: "Avoid placing sensitive data in redirect URLs",
					References:  []string{"https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url"},
				})
			}
		}
	}

	return findings
}

// checkAuthHeaders checks for authentication header issues
func (d *Detector) checkAuthHeaders(resp *http.Response, targetURL string) []ATOFinding {
	var findings []ATOFinding

	// Check for exposed internal authentication headers
	sensitiveHeaders := []string{
		"X-Auth-Token", "X-Api-Key", "Authorization", "X-Access-Token",
		"X-Session-Token", "X-User-Token", "X-JWT-Token",
	}

	for _, header := range sensitiveHeaders {
		if value := resp.Header.Get(header); value != "" {
			// Check if it's exposed in response
			if strings.HasPrefix(strings.ToLower(header), "x-") {
				findings = append(findings, ATOFinding{
					Type:        ATOTokenInURL,
					Severity:    SeverityLow,
					CVSS:        3.7,
					CWE:         "CWE-200",
					URL:         targetURL,
					Evidence:    fmt.Sprintf("Authentication header '%s' exposed in response", header),
					Description: "Authentication tokens in response headers may leak to JavaScript or logs",
					Remediation: "Consider using HttpOnly cookies for session management",
					References:  []string{"https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"},
				})
			}
		}
	}

	// Check for missing security headers that could enable ATO
	securityHeaders := map[string]ATOFinding{
		"X-Frame-Options": {
			Type:        ATOCSRFTokenIssue,
			Severity:    SeverityLow,
			CVSS:        4.3,
			CWE:         "CWE-1021",
			Description: "Missing X-Frame-Options header may enable clickjacking attacks",
			Remediation: "Set X-Frame-Options: DENY or SAMEORIGIN",
		},
		"Content-Security-Policy": {
			Type:        ATOCSRFTokenIssue,
			Severity:    SeverityLow,
			CVSS:        4.3,
			CWE:         "CWE-693",
			Description: "Missing Content-Security-Policy header reduces XSS protection",
			Remediation: "Implement Content-Security-Policy header",
		},
	}

	for header, finding := range securityHeaders {
		if resp.Header.Get(header) == "" {
			finding.URL = targetURL
			finding.Evidence = fmt.Sprintf("Missing %s header", header)
			findings = append(findings, finding)
		}
	}

	return findings
}

// CheckBruteForce tests for brute force protection
func (d *Detector) CheckBruteForce(ctx context.Context, loginURL string, attempts int) *ATOFinding {
	// Send multiple rapid requests to check for rate limiting
	for i := 0; i < attempts; i++ {
		req, err := http.NewRequestWithContext(ctx, "POST", loginURL, strings.NewReader("username=test&password=test"))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", d.userAgent)

		resp, err := d.httpClient.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		// Check for rate limiting response
		if resp.StatusCode == 429 || resp.StatusCode == 503 {
			return nil // Rate limiting is in place
		}
	}

	return &ATOFinding{
		Type:        ATOBruteForceVuln,
		Severity:    SeverityMedium,
		CVSS:        5.3,
		CWE:         "CWE-307",
		URL:         loginURL,
		Evidence:    fmt.Sprintf("No rate limiting detected after %d requests", attempts),
		Description: "Login endpoint may be vulnerable to brute force attacks",
		Remediation: "Implement rate limiting, account lockout, and CAPTCHA",
		References:  []string{"https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"},
	}
}

// String returns a string representation of the ATO type
func (t ATOType) String() string {
	return string(t)
}
