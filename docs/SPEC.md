# SPEC: Aegis Technical Specification

> **Status:** v3.5 audit-aligned (2026-06-02). Single-target web security
> scanner, all-Go. Living document. Every status label is verified against
> the codebase as of the v3 audit.

## 0. Document Conventions

- **All functionality written in Go** (`go 1.25`). The implementation
  language is Go; no Rust, no FFI, no language bridges.
- **Native or prebuilt — both valid, decision recorded inline.** Every
  component in §2 is tagged `[LIB: <name>]` (uses a Go library from
  stdlib or community) or `[CUSTOM]` (hand-rolled, either because no
  good library exists or because pulling one in would be heavier than
  the custom code).
- **Build-vs-buy decision rule** (applied in this order):
  1. If a problem is well-understood and a mature Go library exists that
     solves it without dragging in transitive weight → use the library.
  2. If no good library exists, or the off-the-shelf option pulls in
     >5 transitive deps for what is essentially 200 lines of code →
     write it custom.
  3. If a library exists but the custom implementation is observably
     less buggy (e.g. security-critical code where we want full audit
     trail) → write it custom.
- Every public symbol listed in this SPEC must have a corresponding
  test in `internal/<package>/<file>_test.go`. SPEC items without tests
  are "documented but unverified" and must be flagged in the audit.
- Quality gates in §10 are **non-negotiable**. They run in CI and
  locally via `scripts/go-run.sh` on the Podman overlay-driver host.

## 1. Architecture

- **Language:** Go 1.25+
- **Module path:** `github.com/coppertone/bug-hunter/app/aegis`
- **Browser Core:** `go-rod/rod` (DevTools Protocol) for headless automation
- **Concurrency:** Worker pool with bounded goroutines; `context.Context`
  propagated to every long-running op
- **Storage:**
  - AES-256-GCM encrypted local storage for session data (key from `--key`
    or fresh keygen)
  - SQLite (`mattn/go-sqlite3`) with WAL mode for crawl databases
  - Local filesystem for mirrors, screenshots, HTML dumps
- **HTTP Clients:** Every outbound `http.Client` MUST have a `Timeout`.
  Every TLS config defaults to verified; unverified mode is opt-in via
  `WithInsecureTLS(true)` or a `*WithInsecureTLS` constructor variant.
- **Build / Test Environment:** Podman (overlay driver, Btrfs root).
  Host has no Go install; all tooling runs via `scripts/go-run.sh`.
- **CI/CD:** Woodpecker CI on Podman. Full pipeline in `.woodpecker.yaml`.

## 2. Component Breakdown

Every component has a status: **[DONE]** (implemented, has tests, passes
gates), **[PARTIAL]** (implemented with documented gaps), **[STUB]**
(interface present, behavior placeholder).

### 2.1 Web Orchestration (`internal/crawler`, `internal/scrape`, `internal/browser`)

- **[DONE, LIB: rod] Recursive link discovery with depth limits** (`crawler`)
  — uses rod for browser control; custom queue, depth tracking, link
  extraction heuristics
- **[DONE, CUSTOM] Deep crawler with sub-domain and asset enumeration**
  (`crawler/deep.go`) — custom HTTP client + scope validator integration
- **[DONE, CUSTOM] Scope-based scraping with per-scope config** (`scrape`)
  — custom YAML-driven config; custom host-foldered asset storage
- **[DONE, LIB: rod] Browser launcher and lifecycle management** (`browser`)
  — wraps `rod/launcher` with retry/fallback to system chromium
- **[DONE, LIB: rod] Screenshot capture** (`cmd/aegis/screenshot.go`) —
  uses `rod.Page.Screenshot` + custom CSS overlay injection
- **[DONE, LIB: crypto/aes + cipher.GCM] Session persistence** —
  (`session/manager.go`) — stdlib crypto only; custom key/session
  lifecycle; owner-only `0o600` perms; constant-time comparisons
- **[PARTIAL, CUSTOM] API endpoint discovery** (`apiextract`) — regex-based
  REST/GraphQL extraction; lacks WebSocket payload inspection and live
  response verification (see §3 backlog)

### 2.2 Security Analysis (`internal/scanner`, `internal/xss`, `internal/owasp25`, `internal/waf`)

- **[DONE, LIB: regexp] Secret pattern matching** (`scanner`) — stdlib
  `regexp` + custom pattern corpus (AWS, JWT, GitHub, private keys, …)
- **[DONE, LIB: regexp] 20 OWASP Top 25 categories** (`owasp25`) —
  custom category definitions on top of stdlib `regexp`
- **[DONE, CUSTOM] DOM XSS static analyzer** (`xss/domxss`) — custom
  sink/source tracking
- **[DONE, CUSTOM] DOM XSS enhanced scanner with WAF bypass**
  (`xss/enhanced_scanner`) — custom payload generation + per-WAF encoding
- **[DONE, CUSTOM] WAF fingerprinting for 19 vendors** (`waf/detector`)
  — custom header/cookie/body signature DB; TLS configurable
- **[DONE, CUSTOM] WAF bypass payload generation, 5 encoding levels**
  (`waf/encoder`, `waf/payloads`) — custom payload corpus + encoding chain
- **[PARTIAL, CUSTOM] Exploitable service detection** (`exploitable`) —
  custom protocol probes for Jenkins, Elasticsearch, MongoDB, Redis.
  **Detection-only by design** (does NOT exploit). TLS verification
  configurable per-scanner.

### 2.3 Intelligence & Recon (`internal/intel`, `internal/recon`)

- **[DONE, LIB: net/http] Intel feed framework** (`intel`) — stdlib
  `http.Client` + custom URLHaus feed parser
- **[DONE, LIB: sync.Map] URL threat-cache lookup** — stdlib concurrent map
- **[PARTIAL, LIB: net] Web2 recon** (`recon/web2.go`) — port scan uses
  stdlib `net.DialTimeout` (4-port default, configurable); subdomain
  enumeration is a STUB returning 3 hardcoded entries (see §3 B-6)
- **[PARTIAL, CUSTOM] Web3 recon** (`recon/web3.go`) — custom EVM/ENS regex;
  shallow vs dedicated web3 recon tools (see §3 B-6)

### 2.4 Reliability & Safety (`internal/validator`, `internal/response`, `internal/scope`)

- **[DONE, LIB: net/url + regexp] URL validation** (`validator`) —
  stdlib URL parsing + custom policy layer
- **[DONE, LIB: net] Target host validation** — blocks private/loopback/
  link-local IPs via `net.IP.IsPrivate` etc.
- **[DONE, LIB: net/http] Redirect policy** — revalidates every hop
- **[DONE, CUSTOM] Path sanitization** (`SanitizeFilename`) — character
  blacklist + traversal detection
- **[DONE, LIB: regexp] Scope configuration** — stdlib regex + custom matcher
- **[PARTIAL, LIB: net/http] Webhook response handler** — basic, receiver
  contract not yet stabilized (see §3)

### 2.5 Orchestration & API (`internal/api`, `internal/runner`, `internal/workflow`, `cmd/aegis`)

- **[DONE, LIB: spf13/cobra + pflag] Cobra CLI with 11 subcommands**:
  `auth`, `crawl`, `scan`, `api`, `bench` (stub), `intel`, `recon`,
  `scrape-scope`, `exploit`, `screenshot`, `rendercheck`
- **[DONE, LIB: net/http + crypto/subtle] REST API** (`api`):
  - Bearer token or `X-API-Key` auth
  - Fail-closed: refuses to start without `AEGIS_API_TOKEN` unless
    `AEGIS_API_ALLOW_UNAUTH=true`
  - Per-client token-bucket rate limiting with TTL + LRU eviction
  - `api_dump/` directory quota (max 16 by default, oldest pruned)
  - Sanitized error responses (no internal error string leak)
- **[DONE, LIB: go-rod/rod + yaml.v3] Multi-instance ATO runner** (`runner`)
- **[DONE, LIB: yaml.v3] Workflow YAML engine** (`workflow`) — stdlib YAML
  + custom step executor
- **[STUB] `benchCmd`** — replaced with explicit error pointing to
  `go test -bench` (v3.5 cleanup; v1 placeholder removed)

### 2.6 Platform Detection & Content Acquisition (`internal/platform`, `internal/content`)

- **[DONE, LIB: regexp] Framework detection** — stdlib regex + custom
  signature library
- **[DONE, LIB: rod + net/http] Platform-aware content acquisition** —
  rod for rendered, stdlib HTTP for static
- **[PARTIAL, LIB: regexp] Version extraction** — regex present, **no CVE
  correlation** (see §3 B-8)

## 3. Backlog (Documented Gaps, not bugs)

| ID    | Sev    | Title                                                       |
|-------|--------|-------------------------------------------------------------|
| B-1   | LOW    | Replace `https://link.insider.in` dev default in `--target`  |
| B-2   | LOW    | Unify `scrape.sanitizeSegment` and `validator.SanitizeFilename` |
| B-3   | MED    | Add circuit-breaker to `scanner.Scanner` worker pool        |
| B-4   | MED    | Add security headers (CSP, X-Frame-Options) to API responses |
| B-5   | MED    | Atomic session writes (temp file + rename)                  |
| B-6   | INFO   | Replace recon/web2 subdomain stub with real wordlist + DNS  |
| B-7   | INFO   | Replace `intel` raw-JSON cache with normalized IOC schema   |
| B-8   | INFO   | Wire CVE database (offline NVD mirror + sqlite)             |
| B-9   | INFO   | Nuclei template compatibility layer over `owasp25`          |
| B-10  | INFO   | SARIF output format for SIEM ingestion                      |

All B-items are scoped in the v3.5 plan at
`docs/plans/2026-06-02-go-native-hardening-remediation.md`, Batch 7.

## 4. Capability Statement (Honest Accounting)

### Capable
- Single authenticated target scan: capture session → crawl with depth →
  dump HTML/JS → run static analysis → get finding list
- OWASP Top 25 regex detection across 20 categories
- DOM XSS detection (static + rendered)
- WAF fingerprint + bypass payload library
- API endpoint discovery (REST/GraphQL/WebSocket) from rendered HTML
- ATO simulation via multi-instance runner
- Internal asset inventory (JS endpoints, cookies, libraries)

### Not Capable (would require §3 B-items or are out of scope)
- Subdomain enumeration beyond 3 hardcoded entries (B-6)
- Service-version → CVE correlation (B-8)
- Real port scan beyond 4 default ports
- Nuclei-style template-driven detection (B-9)
- Fuzz harness (out of scope per PRD §3.2)
- Active exploitation (out of scope per PRD §3.1)
- Multi-target continuous scanning (out of scope)
- Smart contract / EVM analysis (out of scope)

## 5. Data Flow

```
auth → session.enc (AES-256-GCM, 0o600) → crawl → dump.db + pages/* + assets/*
                                                  ↓
                                              scan → findings.{json,html,md}
                                                  ↓
                                       (optional) exploit → pocs/

# API path (v2+):
POST /crawl → prepareCrawlDumpDir() (quota-aware) → go func() → c.Run()
                                                            ↓
                                                    /crawl returns 202
```

## 6. Configuration

YAML configs in `configs/*.yaml`. API env vars in §6.1.

```yaml
target: https://example.local
maxDepth: 3
userAgent: "Project-Aegis/1.0"
allowPrivateHosts: false          # safe default; explicit opt-in needed
                                  # to scan internal targets
```

### 6.1 API Server Environment Variables

All have safe defaults. The server **refuses to start** without
`AEGIS_API_TOKEN` unless `AEGIS_API_ALLOW_UNAUTH=true`.

| Var | Default | Purpose |
|-----|---------|---------|
| `AEGIS_API_TOKEN` | (required) | Bearer token for auth |
| `AEGIS_API_ALLOW_UNAUTH` | `false` | Disable auth (dev only) |
| `AEGIS_API_RATE_PER_MIN` | 60 | Per-client req/min |
| `AEGIS_API_RATE_BURST` | 10 | Token bucket size |
| `AEGIS_API_BUCKET_TTL_SEC` | 600 | Rate-limit bucket eviction TTL |
| `AEGIS_API_MAX_BUCKETS` | 10000 | Cap on rate-limit map size |
| `AEGIS_API_SWEEP_EVERY_SEC` | 60 | Stale-bucket sweep frequency |
| `AEGIS_API_DUMP_MAX_DIRS` | 16 | `api_dump/` directory quota |
| `AEGIS_API_DUMP_ROOT` | `api_dump` | Override dump location |

## 7. Testing Strategy

### 7.1 Unit Tests
- All public symbols in §2 must have tests
- 80% branch coverage target on `internal/**` (CI gate fails PR)
- Mocks/fakes for network and filesystem dependencies
- Located alongside code: `internal/<pkg>/<file>_test.go`

### 7.2 Integration & E2E Tests
- Mock server → crawl → scan → finding detection
- API endpoint validation via `net/http/httptest`
- Cross-package: `internal/integration_test.go`

### 7.3 Security Tests
- `gosec` runs in CI (`.woodpecker.yaml`)
- `golangci-lint` runs in CI
- New HTTP client → must come with `httptest.NewServer` test verifying
  Timeout / redirect / TLS posture

### 7.4 False-Positive & Inconsistency Gates (PRD §7)

These are the **contracts** that every detector and orchestrator must
satisfy. A detector is **not considered implemented** until its contract
test exists and passes.

#### 7.4.1 Per-Detector Contract
Every detector in `internal/owasp25`, `internal/xss`, `internal/scanner`,
`internal/waf/payloads` MUST have:

| Test type | Requirement |
|-----------|-------------|
| Positive | At least one known-vulnerable input → 1+ findings |
| Negative | At least one safe input (UUIDs, base64, version strings, static text) → 0 findings |
| Edge case | Empty string, 1MB random, unicode/emoji, binary noise, truncated input → no panic, no false positive |

Negative tests must use **realistic** safe data, not placeholder x's.

#### 7.4.2 Crawl Determinism
Same `Config` + same mock server → same set of pages crawled. Random
worker scheduling must NOT change the final page set. Test: run the
same crawl N times, assert page-set equality modulo timestamps.

#### 7.4.3 Session Determinism
A captured session, restored to a new browser instance via a fresh
SessionManager (same key), lands on the same authenticated state.
Round-trip test in `session_test.go` covers this.

#### 7.4.4 API Behavior Contract
7 assertions, codified in `api/api_spec_test.go`:
1. `GET /health` → 200 always
2. `GET /crawl` (any method) without auth → 401
3. `POST /crawl` with valid bearer → 202
4. Burst exceed → 429 (covered by 3 rate-limit tests)
5. `api_dump/` bounded by env var (covered by 2 quota tests)
6. `POST /crawl` with malformed JSON → 400
7. `POST /crawl` with invalid config (e.g. target=localhost, allow_private=false) → 400

#### 7.4.5 No-Regression Rule
v1 finding closure rate: 12/38 (31.6%) at v2 → 16/38 (42.1%) target by v4.
v2 fixes (9) and v3 fixes (4) MUST stay verified. A v4 audit must not
regress any prior fix.

## 8. Operational Runbook

`DISASTER_RECOVERY.md` at repo root covers 8 scenarios (API start, browser
launch, SQLite lock, build cache, rate-limit lockout, session corruption,
release rollback, scan artifact cleanup). Current as of 2026-06-02.

## 9. CI/CD (`.woodpecker.yaml`)

5 stages: prepare (goimports, vendor) → lint (golangci-lint) → security-scan
(gosec) → test (go test -race -coverprofile + 80% gate) → build (podman).

`deploy-staging` runs only on push to `develop`. Container registry uses
localhost:5000 (local Podman registry).

## 10. Quality Gates (non-negotiable, run on every commit)

```bash
# Run via scripts/go-run.sh (host has no Go install)
podman run --rm --userns keep-id -v "$(pwd):/workspace" -w /workspace \
  -e GOCACHE=/workspace/.cache/go-build -e GOMODCACHE=/workspace/.cache/gomod \
  docker.io/library/golang:1.25-bookworm bash -c "
    gofmt -l cmd internal
    go vet ./...
    go build ./...
    go test -count=1 -race ./...
  "
```

All four must pass:

1. **gofmt** — zero files out of compliance
2. **go vet** — zero warnings
3. **go build** — clean compilation
4. **go test -race** — all tests pass with race detector

Plus CI-level gates:

5. **golangci-lint** — zero issues
6. **gosec** — no HIGH+ findings
7. **Coverage** — `internal/**` ≥ 80% branch coverage

A release is blocked if any gate fails.

## 11. Change Management

- Every change reflected in SPEC + PRD within the same PR.
- Every new exported symbol has godoc + test.
- Every new external HTTP client defaults to Timeout + verified TLS.
- Backlog items in §3 require a SPEC status update (DONE/PARTIAL/STUB)
  when completed.

## 12. Subagent-Cautionary Note

Per the v2/v3 audit subagent-timeout pattern (skill pitfall #5), deep
audits of 25,000+ LOC projects may exceed subagent tool budgets. v3 used
direct parent-context file reads. Same applies to any implementation
work in §3: any subagent task touching ≥10 files should run in parent
context or under a bounded-execution plan.
