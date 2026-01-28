# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Aegis is a Go-based CLI tool for authenticated web crawling and security scanning. It uses Rod (Chromium automation) for browser control and discovers vulnerabilities in web applications.

## Build Commands

```bash
# Build the binary (requires Go 1.25)
go build -o aegis ./cmd/aegis/

# Or use the containerized Go environment (recommended)
./infra/scripts/go-run.sh go build -o aegis ./cmd/aegis/

# Container-based deployment
podman-compose -f deploy/compose/podman-compose.yml up --build
```

## Testing

```bash
# Run all tests
go test ./...

# Or via container
./infra/scripts/go-run.sh go test ./...

# Run specific package tests
go test ./internal/crawler/
go test ./internal/scanner/
go test ./internal/session/
```

## CLI Commands

```bash
# Capture authenticated session (opens browser for manual login)
aegis auth --session /path/to/session --target-url https://target.com

# Crawl with session and save to dump directory
aegis crawl --config /path/to/config.yaml --dump /path/to/dump --session /path/to/session

# Scan dump for vulnerabilities
aegis scan --input /path/to/dump [--format json|html|console] [--output /path/to/file]
```

## Architecture

```
cmd/aegis/main.go     # CLI entry point (Cobra commands: auth, crawl, scan)
internal/
├── session/          # Browser session persistence (cookies, localStorage, sessionStorage)
├── crawler/          # Rod-based recursive web crawler with depth limits
└── scanner/          # Regex pattern matching for secrets and dangerous code patterns
```

**Data Flow:** auth → session file → crawl → dump directory → scan → findings report

**Key Dependencies:**
- `go-rod/rod` - Chromium automation
- `spf13/cobra` - CLI framework
- `yaml.v3` - Configuration parsing

## Configuration

Config files use YAML format (`configs/config.yaml`):
```yaml
target: https://example.local
maxDepth: 3
userAgent: "Project-Aegis/1.0"
```

## Scanner Detection Patterns

The scanner looks for:
- **Secrets:** AWS keys (AKIA*), JWTs (eyJ*), GitHub tokens, private keys, API keys
- **Dangerous patterns:** eval(), innerHTML, unsafe redirects, XSS vectors, SQL injection patterns, CORS misconfigurations

Findings have severity levels: HIGH, MEDIUM, LOW
