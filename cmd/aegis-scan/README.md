# Aegis Complete Security Scanner

The Aegis Complete Security Scanner runs all scanning modules against a target:

## Modules Included

1. **Platform Detection** - Framework identification with EOL checking
2. **Deep Crawling** - Discovers all frontend pages including SPAs
3. **XSS Scanning** - Reflected, Stored, and DOM-based XSS detection
4. **Asset Discovery** - All JS, CSS, images, fonts, media files
5. **API Extraction** - REST, GraphQL, WebSocket, gRPC endpoints
6. **Exploitable Software** - Redis, MongoDB, Elasticsearch, Jenkins
7. **OWASP Top 25** - Security vulnerability scanning

## Quick Start

### Using the Wrapper Script

```bash
# Basic scan
./scripts/run-aegis-scan.sh https://example.com

# Scan with custom ports
./scripts/run-aegis-scan.sh https://example.com -p 80,443,8080,3000

# Deep scan with more pages
./scripts/run-aegis-scan.sh https://example.com --max-pages 100 --max-depth 5

# High-performance scan
./scripts/run-aegis-scan.sh https://example.com -w 20 --timeout 60

# Custom output directory
./scripts/run-aegis-scan.sh https://example.com -o /tmp/aegis-results

# Disable specific modules
./scripts/run-aegis-scan.sh https://example.com --no-exploitable --no-crawl
```

### Direct Usage

```bash
cd app/aegis

go run cmd/aegis-scan/main.go -target https://example.com
```

### Build Binary

```bash
cd app/aegis
go build -o aegis-scan cmd/aegis-scan/main.go

# Run
./aegis-scan -target https://example.com
```

## Command Line Options

```
Usage: aegis-scan -target <url> [options]

Required:
  -target string          Target URL (required)

Options:
  -host string            Target host for port scanning (default: derived from URL)
  -ports string           Ports to scan (comma-separated, default: 80,443,6379,27017,9200,8080)
  -max-pages int          Maximum pages to crawl (default: 50)
  -max-depth int          Maximum crawl depth (default: 3)
  -workers int            Number of concurrent workers (default: 10)
  -timeout int            Timeout in seconds (default: 30)
  -output string          Output directory (default: ./scan-results)

Module Toggles (enabled by default):
  -xss bool               Enable XSS scanning (default: true)
  -assets bool            Enable asset discovery (default: true)
  -apis bool              Enable API extraction (default: true)
  -exploitable bool       Enable exploitable software scanning (default: true)
  -owasp bool             Enable OWASP scanning (default: true)
  -platform bool          Enable platform detection (default: true)
  -deep-crawl bool        Enable deep crawling (default: true)
  -verbose                Verbose output
```

## Output

The scanner generates three report formats:

1. **JSON** (`scan-results/aegis-scan-<host>-<timestamp>.json`)
   - Complete machine-readable results
   
2. **HTML** (`scan-results/aegis-scan-<host>-<timestamp>.html`)
   - Visual report with statistics
   
3. **Markdown** (`scan-results/aegis-scan-<host>-<timestamp>.md`)
   - Human-readable summary

## Example Output

```
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║     ÆGIS - COMPLETE SECURITY SCANNER                      ║
║     XSS • Assets • APIs • Exploitable • OWASP • EOL       ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝

[*] Target: https://example.com
[*] Host: example.com
[*] Ports: [80 443 6379 27017 9200 8080]
[*] Output: ./scan-results

[1/8] Platform Detection & Content Acquisition...
    [+] Detected 3 frameworks
    [!] Found 1 EOL frameworks

[2/8] Deep Crawling...
    [+] Discovered 47 pages

[3/8] XSS Scanning...
    [+] Found 3 XSS vulnerabilities

[4/8] Asset Discovery...
    [+] Found 156 assets
        - javascript: 42
        - css: 8
        - image: 89
        - font: 12
        - json: 5

[5/8] API Endpoint Extraction...
    [+] Found 23 API endpoints
        - REST: 18
        - GraphQL: 2
        - WebSocket: 3

[6/8] Exploitable Software Scanning...
    [+] Found 1 exploitable services

[7/8] OWASP Top 25 Scanning...
    [+] Found 12 OWASP violations

[8/8] Generating Summary...

============================================================
SCAN SUMMARY
============================================================
XSS Vulnerabilities:       3
Assets Discovered:         156
API Endpoints:             23
Pages Crawled:             47
Exploitable Services:      1
OWASP Violations:          12
------------------------------------------------------------
SEVERITY BREAKDOWN
  Critical: 2
  High: 5
  Medium: 8
  Low: 3
============================================================

[+] JSON Report: ./scan-results/aegis-scan-example-com-20260201-143052.json
[+] HTML Report: ./scan-results/aegis-scan-example-com-20260201-143052.html
[+] Markdown Report: ./scan-results/aegis-scan-example-com-20260201-143052.md
```

## Requirements

- Go 1.21+
- Chrome/Chromium (for browser-based scanning)
- Network access to target

## Troubleshooting

### Browser Issues
If you see browser initialization errors, ensure Chrome/Chromium is installed:
```bash
# Ubuntu/Debian
sudo apt-get install chromium-browser

# macOS
brew install chromium
```

### Permission Errors
Ensure the output directory is writable:
```bash
mkdir -p ./scan-results
chmod 755 ./scan-results
```

### Timeout Issues
Increase timeout for slower targets:
```bash
./scripts/run-aegis-scan.sh https://slow-target.com -t 60
```

## License

Same as Aegis project.
