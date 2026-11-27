# Architecture Overview

## Scope

Aegis is a Go-native authenticated web crawler and vulnerability triage scanner.
It is intentionally scoped to web application crawling, content acquisition, static
analysis, WAF/XSS support, ATO scenarios, and a small REST API. It does not contain
Web3, Android, desktop binary, or multi-analyzer coordinator services.

## Component map

```text
cmd/aegis/
  main.go                 Cobra CLI entrypoint
  auth/crawl/scan/api     primary workflow commands
  exploit                 ATO scenario runner command
  screenshot/rendercheck  visual/render verification commands

internal/
  api/                    REST API: /health and /crawl, auth, rate limit, dump quota
  apiextract/             REST/GraphQL/WebSocket endpoint extraction from content
  assets/                 asset extraction and storage helpers
  browser/                Rod/Chromium launcher wrapper
  content/                static/rendered content acquisition
  crawler/                recursive browser crawler and crawl database
  exploitable/            detection-only service probes
  intel/                  URLHaus feed ingestion and URL threat cache
  owasp25/                regex-based OWASP category scanner
  platform/               framework/version detection
  recon/                  shallow web2/web3 recon helpers; web2 subdomain enum is backlog
  response/               webhook/response helpers
  runner/                 multi-instance ATO runner
  scanner/                secret and dangerous-pattern scanner
  scope/                  scope config and matcher
  scrape/                 scope-aware scraper
  session/                AES-256-GCM browser session persistence
  validator/              URL/host/path validation and sanitization
  waf/                    WAF fingerprinting and bypass payloads
  workflow/               YAML workflow execution
  xss/                    DOM XSS and enhanced XSS scanning
```

## Data flow

```text
auth
  -> session.enc (AES-256-GCM, 0600)
  -> crawl with session + config
  -> crawl.db + pages/assets/screenshots
  -> scan
  -> findings report
```

REST API flow:

```text
POST /crawl
  -> authenticate bearer/API key
  -> rate-limit by client key
  -> create bounded api_dump/<timestamp>
  -> run crawler asynchronously
  -> return 202 Accepted
```

## Go-native build-vs-buy rule

Aegis uses Go libraries when they are mature and scoped:

- `go-rod/rod` for browser automation
- `spf13/cobra` for CLI
- `yaml.v3` for config/workflows
- `mattn/go-sqlite3` for crawl databases
- Go stdlib crypto/net/http/regexp/context/sync for security and orchestration

Custom code is used where the domain logic is Aegis-specific: detector corpora,
WAF payload generation, crawler queueing, scope policy, session lifecycle, and
false-positive gates.

## Safety model

- API auth is fail-closed unless `AEGIS_API_ALLOW_UNAUTH=true`
- Rate limiter has TTL + max-bucket eviction
- API dump directories are quota-capped
- Session files are encrypted and owner-only
- Private/loopback target scanning requires explicit config
- Every outbound HTTP client must have a timeout

## Current architecture gaps

See `docs/SPEC.md` §3 for the authoritative backlog. Important known gaps:
real subdomain enumeration, expanded port scan, CVE correlation, SARIF output,
security headers, atomic session writes, and Nuclei compatibility.
