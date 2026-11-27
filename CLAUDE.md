# CLAUDE.md

This file provides guidance to coding agents working in this repository.

## Project Overview

Aegis is a Go-native CLI for authenticated web crawling and security triage. It uses
Rod/Chromium for browser automation, captures encrypted browser sessions, crawls a
single authorized target, dumps rendered content/assets, and scans for secrets,
DOM XSS, OWASP-style patterns, WAF indicators, exposed APIs, and session/ATO issues.

Aegis is not currently a Burp Suite/Caido replacement, not a multi-target scanner,
not an active exploitation framework, and not a Web3/Android/Desktop analyzer.
Keep docs and code aligned with the focused Go-native scanner scope unless the user
explicitly requests a new strategic pivot.

## Build Commands

```bash
# Build via container (recommended; host may not have Go)
./scripts/go-run.sh go build -o aegis ./cmd/aegis/

# Direct container equivalent
podman run --rm --userns keep-id -v "$(pwd):/workspace" -w /workspace \
  -e GOCACHE=/workspace/.cache/go-build \
  -e GOMODCACHE=/workspace/.cache/gomod \
  docker.io/library/golang:1.25-bookworm \
  go build -o aegis ./cmd/aegis/
```

## Testing

```bash
./scripts/go-run.sh go test ./...
./scripts/go-run.sh go test -count=1 -race ./...
```

Quality gate:

```bash
gofmt -l cmd internal
go vet ./...
go build ./...
go test -count=1 ./...
```

Run through Podman or `scripts/go-run.sh`.

## CLI Workflow

```bash
# Capture authenticated session
aegis auth --session ./session.enc --target-url https://target.example

# Crawl with session and save to dump directory
aegis crawl --config configs/config.yaml --dump ./dump --session ./session.enc

# Scan dump for vulnerabilities
aegis scan --input ./dump --format json --output findings.json
```

## Architecture

```text
cmd/aegis/main.go     Cobra CLI entrypoint
internal/session/     AES-256-GCM session persistence
internal/crawler/     Rod-based crawler + crawl DB
internal/scanner/     secret/dangerous-pattern scanner
internal/owasp25/     OWASP-pattern detector
internal/xss/         DOM XSS detection
internal/waf/         WAF detection and bypass payloads
internal/api/         /health and /crawl REST API
```

Data flow: `auth -> session.enc -> crawl -> dump -> scan -> findings`.

## API Environment

- `AEGIS_API_TOKEN` — required bearer/API-key token unless unauthenticated dev mode is explicit
- `AEGIS_API_ALLOW_UNAUTH=true` — dev only; disables auth
- `AEGIS_API_RATE_PER_MIN` — default 60
- `AEGIS_API_RATE_BURST` — default 10
- `AEGIS_API_MAX_BUCKETS` — default 10000
- `AEGIS_API_DUMP_MAX_DIRS` — default 16

## Documentation Source of Truth

- `docs/PRD.md` — product intent and scope
- `docs/SPEC.md` — technical spec, backlog, and quality gates
- `docs/plans/2026-06-02-go-native-hardening-remediation.md` — active hardening plan
- `docs/TESTING.md` — testing strategy
- `docs/api-reference/index.md` — current API endpoints

## Development Rules

- Keep all functionality Go-native.
- Prefer mature Go libraries for well-solved problems; custom code is acceptable when smaller and easier to audit.
- Every detector must have positive, negative, and edge-case tests.
- Every new HTTP client must have a timeout and verified TLS by default.
- Update SPEC and PRD in the same change when behavior, scope, or status changes.
