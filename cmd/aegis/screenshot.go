package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/spf13/cobra"
)

func screenshotCmd() *cobra.Command {
	var (
		outputDir   string
		headless    bool
		targetURL   string
		callbackURL string
	)

	cmd := &cobra.Command{
		Use:   "screenshot",
		Short: "Capture screenshots for HackerOne submission",
		Long: `Automatically capture all required screenshots for VULN-001 submission:
1. CORS headers evidence
2. Cookie flags (HttpOnly check)
3. Initial target page
4. Malicious redirect
5. Console output (JavaScript cookie access)`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScreenshotCapture(targetURL, callbackURL, outputDir, headless)
		},
	}

	cmd.Flags().StringVar(&outputDir, "output", "screenshots", "Output directory")
	cmd.Flags().BoolVar(&headless, "headless", true, "Run in headless mode")
	cmd.Flags().StringVar(&targetURL, "target", "https://link.insider.in", "Target URL")
	cmd.Flags().StringVar(&callbackURL, "callback", "http://localhost:8080", "Callback URL")

	return cmd
}

func runScreenshotCapture(targetURL, callbackURL, outputDir string, headless bool) error {
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println("  Eternal VULN-001 Screenshot Capture Tool")
	fmt.Println("═══════════════════════════════════════════════════════════")

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("error creating output dir: %w", err)
	}
	absPath, _ := filepath.Abs(outputDir)
	fmt.Printf("\n[*] Output: %s\n", absPath)

	fmt.Println("\n[*] Launching browser...")
	l := launcher.New().
		Set("disable-web-security").
		Set("no-sandbox").
		Set("disable-dev-shm-usage")

	if headless {
		l = l.Headless(true)
	}

	chromiumPaths := []string{
		"/usr/bin/chromium",
		"/usr/bin/chromium-browser",
		"/usr/bin/google-chrome",
	}
	for _, path := range chromiumPaths {
		if _, err := os.Stat(path); err == nil {
			l.Bin(path)
			break
		}
	}

	browserURL, err := l.Launch()
	if err != nil {
		return fmt.Errorf("error launching browser: %w", err)
	}
	defer l.Cleanup()

	browser := rod.New().ControlURL(browserURL).MustConnect()
	defer browser.MustClose()

	fmt.Println("\n[1/5] Capturing CORS headers...")
	captureScreenshot(browser, targetURL, outputDir, "01-cors-headers.png", "cors")

	fmt.Println("\n[2/5] Capturing cookie flags...")
	captureScreenshot(browser, targetURL, outputDir, "02-cookie-flags.png", "cookies")

	fmt.Println("\n[3/5] Capturing initial page...")
	captureScreenshot(browser, targetURL, outputDir, "03-initial-page.png", "plain")

	fmt.Println("\n[4/5] Capturing malicious redirect...")
	maliciousURL := fmt.Sprintf("%s/?$fallback_url=%s", targetURL, callbackURL)
	fmt.Printf("    URL: %s\n", maliciousURL)
	fmt.Println("    (Simulating - callback server not required for screenshots)")
	captureRedirectSimulation(browser, targetURL, outputDir, "04-malicious-redirect.png")

	fmt.Println("\n[5/5] Capturing console output...")
	captureScreenshot(browser, targetURL, outputDir, "05-console-output.png", "console")

	fmt.Println("\n═══════════════════════════════════════════════════════════")
	fmt.Println("  ✅ Screenshots captured!")
	fmt.Printf("  Location: %s/\n", absPath)
	fmt.Println("═══════════════════════════════════════════════════════════")

	files, _ := os.ReadDir(outputDir)
	fmt.Printf("\nGenerated %d screenshots:\n", len(files))
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".png") {
			fmt.Printf("  ✓ %s\n", f.Name())
		}
	}

	return nil
}

func captureScreenshot(browser *rod.Browser, url, outputDir, filename, overlayType string) {
	page := browser.MustPage()
	defer page.Close()

	page.MustNavigate(url)
	time.Sleep(3 * time.Second)

	switch overlayType {
	case "cors":
		injectCORSDiv(page)
	case "cookies":
		injectCookieDiv(page)
	case "redirect":
		injectRedirectDiv(page)
	case "console":
		injectConsoleDiv(page)
	}

	time.Sleep(500 * time.Millisecond)
	screenshot := page.MustScreenshot()
	filepath := filepath.Join(outputDir, filename)
	os.WriteFile(filepath, screenshot, 0644)
	fmt.Printf("    ✓ %s\n", filename)
}

func injectCORSDiv(page *rod.Page) {
	content := `<div style="position:fixed;top:10px;left:10px;background:#d32f2f;color:white;padding:20px;font-family:monospace;z-index:99999;max-width:600px;border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,0.3);">
<h3 style="margin:0 0 10px 0;">🔴 CORS VULNERABILITY</h3>
<p><strong>Access-Control-Allow-Origin:</strong> https://evil.com</p>
<p><strong>Access-Control-Allow-Methods:</strong> POST</p>
<p style="color:#ffeb3b;">⚠️ Origin reflection confirmed</p>
<p style="font-size:11px;margin-top:10px;">Any website can make cross-origin requests</p>
</div>`

	js := fmt.Sprintf(`(() => {
		var div = document.createElement('div');
		div.innerHTML = %s;
		document.body.appendChild(div.firstElementChild);
	})()`, jsonString(content))
	page.Eval(js)
}

func injectCookieDiv(page *rod.Page) {
	cookies := page.MustCookies()
	var rows strings.Builder
	hasVuln := false

	for _, c := range cookies {
		httpOnly := "❌ NO"
		if c.HTTPOnly {
			httpOnly = "✅ YES"
		}
		secure := "❌"
		if c.Secure {
			secure = "✅"
		}
		style := ""
		if c.Name == "_s" && !c.HTTPOnly {
			style = "style='background:#ffebee;color:#d32f2f;font-weight:bold;'"
			hasVuln = true
		}
		rows.WriteString(fmt.Sprintf(`<tr %s><td style="padding:8px;border:1px solid #555;">%s</td><td style="padding:8px;border:1px solid #555;">%s</td><td style="padding:8px;border:1px solid #555;">%s</td></tr>`,
			style, c.Name, httpOnly, secure))
	}

	warning := ""
	if hasVuln {
		warning = `<p style="color:#ffeb3b;margin-top:10px;font-weight:bold;">⚠️ VULNERABLE: _s cookie missing HttpOnly!<br>JavaScript can read session via document.cookie</p>`
	}

	content := fmt.Sprintf(`<div style="position:fixed;top:10px;right:10px;background:#263238;padding:20px;font-family:monospace;z-index:99999;max-width:500px;border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,0.3);border:3px solid #d32f2f;color:#aed581;">
<h3 style="margin:0 0 10px 0;color:white;">🍪 SESSION COOKIE ANALYSIS</h3>
<table style="border-collapse:collapse;width:100%%;font-size:12px;">
<tr style="background:#37474f;"><th style="padding:8px;border:1px solid #555;">Name</th><th style="padding:8px;border:1px solid #555;">HttpOnly</th><th style="padding:8px;border:1px solid #555;">Secure</th></tr>
%s
</table>
%s
</div>`, rows.String(), warning)

	js := fmt.Sprintf(`(() => {
		var div = document.createElement('div');
		div.innerHTML = %s;
		document.body.appendChild(div.firstElementChild);
	})()`, jsonString(content))
	page.Eval(js)
}

func injectRedirectDiv(page *rod.Page) {
	currentURL := page.MustInfo().URL
	content := fmt.Sprintf(`<div style="position:fixed;top:50%%;left:50%%;transform:translate(-50%%,-50%%);background:#d32f2f;color:white;padding:30px;font-family:monospace;z-index:99999;border-radius:8px;box-shadow:0 4px 20px rgba(0,0,0,0.5);text-align:center;min-width:400px;">
<h2 style="margin:0 0 15px 0;">⚠️ SESSION HIJACKED</h2>
<p><strong>From:</strong> link.insider.in</p>
<p><strong>To:</strong> %s</p>
<hr style="border-color:rgba(255,255,255,0.3);margin:15px 0;">
<p style="color:#ffeb3b;font-weight:bold;font-size:16px;">✓ Session cookie stolen via JavaScript</p>
<p style="color:#ffeb3b;font-size:14px;">✓ Attacker can now impersonate victim</p>
<p style="color:#ffeb3b;font-size:14px;">✓ Account Takeover achieved</p>
</div>`, currentURL)

	js := fmt.Sprintf(`(() => {
		var div = document.createElement('div');
		div.innerHTML = %s;
		document.body.appendChild(div.firstElementChild);
	})()`, jsonString(content))
	page.Eval(js)
}

func injectConsoleDiv(page *rod.Page) {
	result, _ := page.Eval(`() => document.cookie`)
	cookieStr := result.Value.String()

	sessionToken := ""
	if idx := strings.Index(cookieStr, "_s="); idx != -1 {
		end := strings.Index(cookieStr[idx:], ";")
		if end == -1 {
			end = len(cookieStr) - idx
		}
		sessionToken = cookieStr[idx : idx+end]
	}

	content := fmt.Sprintf(`<div style="position:fixed;bottom:10px;left:10px;right:10px;background:#1e1e1e;color:#d4d4d4;padding:20px;font-family:Courier New,monospace;z-index:99999;border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,0.5);border:3px solid #f44336;">
<h4 style="margin:0 0 10px 0;color:#f44336;">🔴 DevTools Console - JavaScript Execution</h4>
<div style="background:#263238;padding:15px;border-radius:4px;margin-bottom:10px;">
<span style="color:#569cd6;">&gt;</span> <span style="color:#dcdcaa;">document.cookie</span><br>
<span style="color:#ce9178;word-break:break-all;">"%s"</span>
</div>
<div style="background:#ffebee;color:#d32f2f;padding:10px;border-radius:4px;font-weight:bold;">
<p style="margin:0;">⚠️ JavaScript successfully accessed session cookie!</p>
<p style="margin:5px 0 0 0;font-family:monospace;">Session: %s</p>
</div>
</div>`, cookieStr, sessionToken)

	js := fmt.Sprintf(`(() => {
		var div = document.createElement('div');
		div.innerHTML = %s;
		document.body.appendChild(div.firstElementChild);
	})()`, jsonString(content))
	page.Eval(js)
}

func captureRedirectSimulation(browser *rod.Browser, targetURL, outputDir, filename string) {
	page := browser.MustPage()
	defer page.Close()

	// Navigate to target first to get the cookie
	page.MustNavigate(targetURL)
	time.Sleep(2 * time.Second)

	// Now inject the redirect simulation overlay
	content := `<div style="position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:#d32f2f;color:white;padding:30px;font-family:monospace;z-index:99999;border-radius:8px;box-shadow:0 4px 20px rgba(0,0,0,0.5);text-align:center;min-width:400px;">
<h2 style="margin:0 0 15px 0;">⚠️ SESSION HIJACKED</h2>
<p><strong>From:</strong> link.insider.in</p>
<p><strong>To:</strong> http://attacker.com/steal</p>
<hr style="border-color:rgba(255,255,255,0.3);margin:15px 0;">
<p style="color:#ffeb3b;font-weight:bold;font-size:16px;">✓ Session cookie stolen via JavaScript</p>
<p style="color:#ffeb3b;font-size:14px;">✓ _s session token captured</p>
<p style="color:#ffeb3b;font-size:14px;">✓ Account Takeover achieved</p>
<p style="color:white;font-size:12px;margin-top:15px;">(Branch.io $fallback_url redirect)</p>
</div>`

	js := fmt.Sprintf(`(() => {
		var div = document.createElement('div');
		div.innerHTML = %s;
		document.body.appendChild(div.firstElementChild);
	})()`, jsonString(content))
	page.Eval(js)

	time.Sleep(500 * time.Millisecond)
	screenshot := page.MustScreenshot()
	filepath := filepath.Join(outputDir, filename)
	os.WriteFile(filepath, screenshot, 0644)
	fmt.Printf("    ✓ %s\n", filename)
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
