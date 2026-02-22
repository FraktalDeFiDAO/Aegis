# Project Aegis

Project Aegis is an authenticated web crawler and security scanner designed to identify potential vulnerabilities and exposed secrets in web applications.

## Features

- **Authentication Capture**: Captures and persists authenticated browser sessions
- **Web Crawling**: Discovers and mirrors web application content up to a configurable depth
- **Security Scanning**: Analyzes mirrored content for potential security issues and exposed secrets

## Commands


### Auth
Captures and persists the authenticated browser session:

```bash
aegis auth --session /path/to/session/file
```

### Crawl
Runs the discovery spider against the target application:

```bash
aegis crawl --config /path/to/config.yaml --dump /path/to/crawl/dir --session /path/to/session/file
```

If `--dump` is omitted, output defaults to `./crawl`.
Use `--include-external` to allow cross-domain crawl even when the config file disables it.
The crawl output folder includes `crawl.db` with pages, links, assets, and error metadata.

### Crawl database
`crawl.db` stores:
- `pages`: URL, depth, HTML path, fetch timestamp
- `links`: from → to edges
- `assets`: asset URL, kind, source page, local path
- `errors`: crawl/download errors with stage + timestamp
- `render_checks`: render verification metrics (method, score, signals, metrics)

### Scan
Analyzes the mirrored dump for secrets and dangerous artifacts:

```bash
aegis scan --input /path/to/crawl/dir
```

### Rendercheck
Decide whether a page needs JS rendering (heuristic-only or Rod-verified):

```bash
aegis rendercheck --url https://example.com
aegis rendercheck --url https://example.com --verify always
```

### Exploit
Run targeted ATO (Account Takeover) simulations and multi-instance exploit chains:

```bash
aegis exploit --config ./configs/ato_scenario.yaml
```

See the [ATO Guide](ATO_GUIDE.md) for detailed configuration instructions.

## Configuration

The crawler uses a YAML configuration file with the following options:

```yaml
target: https://example.local      # Target URL to crawl
maxDepth: 3                        # Maximum depth to crawl
includeExternal: false             # Allow crawling external domains
renderVerify: "auto"               # Render verification: auto, never, always
renderBorderLow: 3                 # Rendercheck borderline low score
renderBorderHigh: 8                # Rendercheck borderline high score
renderTextDeltaMin: 350            # Visible text delta threshold
renderMaxBytes: 2097152            # Max bytes for rendercheck/static HTML fetch
userAgent: "Project-Aegis/1.0"     # User agent string to use
maxPages: 0                        # Optional cap on pages (0 = unlimited)
enableDownload: true               # Download assets discovered during crawl
downloadPath: "downloads"          # Defaults to <dump>/downloads
allowPrivateHosts: false           # Block localhost/private IPs unless explicitly allowed
pageTimeoutSeconds: 30             # Per-page timeout
```

For scope scraping, you can provide a YAML config via `--scrape-config`:

```yaml
maxDepth: 2
workerCount: 2
headless: true
scroll: false
includeExternal: false
allowPrivateHosts: false
userAgent: "AegisScrape/1.0"
headers:
  X-Hackerone: "your_username"
maxPages: 0                          # 0 = unlimited
maxLinksPerPage: 0                   # 0 = unlimited
requestDelayMillis: 0                # Delay between HTTP requests
enableScreenshot: false
screenshotPath: ""                  # Optional, defaults to <outputDir>/screenshots when enabled
pageTimeoutSeconds: 30
downloadTimeoutSeconds: 30
maxDownloadBytes: 20971520
```

Scope scraping writes outputs into the chosen `outputDir`:

- `manifest.json` (or `manifest.yaml`) with pages, downloads, and errors
- `crawl.db` (SQLite) with pages, links, assets, and errors
- `pages/` for saved HTML
- Host-based folders for downloaded assets (e.g., `example.com/...`)
- `screenshots/` when enabled

## Security Considerations

### Current State (Local Development)
This tool is currently designed for local, single-developer environments. The following security considerations apply:

- Session data is stored in plain text format
- No encryption of sensitive authentication tokens
- Default file paths are used for session and dump storage

### Planned Improvements (Remote Deployment)
Before deploying to remote servers, the following security enhancements will be implemented:

- **Session Encryption**: Encrypt session data to protect sensitive authentication tokens
- **Input Validation**: Add robust input validation to prevent path traversal and injection attacks
- **Secure Defaults**: Implement secure default paths and permissions
- **Privilege Reduction**: Minimize container privileges required for operation


## Architecture

- **Main Command**: Orchestrates the auth, crawl, and scan workflows using Cobra
- **Session Manager**: Handles capturing and restoring browser sessions (cookies, localStorage, sessionStorage)
- **Crawler**: Discovers and mirrors web application content
- **Scanner**: Analyzes content for potential security issues

## Building

To build the project:

```bash
# Using the provided script to run in a consistent Go environment
./scripts/go-run.sh go build -o aegis ./cmd/aegis
```

## Running with Podman Compose

The project includes a Podman Compose configuration for containerized execution:

```bash
podman-compose -f compose/podman-compose.yml up --build
```

## Development

For development, use the provided sandbox environment:

```bash
# Build the sandbox container
podman build -f sandbox/Containerfile -t aegis-sandbox .

# Run in the sandbox environment
podman run --privileged --rm -it \
  -v "$PWD":/workspace:z \
  -v /var/lib/containers:/var/lib/containers:z \
  aegis-sandbox
```

## Security Scan Capabilities

The scanner currently detects:

- API keys and secrets
- Passwords and credentials
- JWT tokens
- AWS/GCP/other cloud provider keys
- Private keys
- Dangerous JavaScript patterns (eval, innerHTML, unsafe redirects)
- Inline scripts

## Future Enhancements

- Enhanced authentication automation
- More sophisticated crawling algorithms
- Additional security checks
- Performance optimizations
- Better reporting formats
