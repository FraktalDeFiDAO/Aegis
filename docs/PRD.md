# PRD: Aegis — Authenticated Web Security Scanner

> **Status:** v3.5 audit-aligned (2026-06-02). Companion to SPEC.md.
> All implementation in Go. No external language bridges.

## 1. Vision

Aegis is a **focused, single-target, authenticated web security scanner**
written in Go. It captures a browser session, crawls the target with depth
limits, dumps the rendered HTML and JavaScript, then runs static and
dynamic analysis to find vulnerabilities. It is designed to run locally
or inside a Podman-in-Podman sandbox, with reproducible builds and a
clear upgrade path.

Aegis is **not** a Burp Suite replacement, a Nuclei competitor, or a
fuzzer. It is a **single-target triage assistant** that produces a
finding list a human can act on. See SPEC §4 for honest accounting of
capable vs not-capable.

## 2. Target Audience

- **Security researchers** running bounty work or red-team engagements
- **AppSec engineers** running internal scans against a known application
- **DevSecOps** adding a CI step that scans a staging deployment

Not the audience:

- Multi-target continuous scanning (use Nuclei + asset inventory)
- Active exploitation / payload delivery (use Metasploit / custom)
- Smart contract / EVM analysis (out of scope)
- Web3 dApp deep analysis (covered lightly by `recon/web3.go`)

## 3. Scope

### 3.1 In Scope (v3.5)

| Capability | Status | Notes |
|-----------|--------|-------|
| Authenticated browser session capture (AES-256-GCM, owner-only) | DONE | |
| Recursive web crawl with depth limits | DONE | |
| Scope-based scraping with per-project config | DONE | |
| Screenshot capture per page | DONE | `--no-sandbox` for rootless Podman |
| DOM XSS detection (static + rendered) | DONE | 5 encoding levels |
| OWASP Top 25 regex-based detection (20 cats) | DONE | per-detector contract enforced |
| WAF fingerprinting + bypass payload library | DONE | 19 vendors |
| API endpoint extraction (REST/GraphQL/WebSocket) | DONE | |
| ATO simulation via multi-instance runner | DONE | YAML scenarios |
| Exploitable-service detection (Jenkins/ES/Mongo/Redis) | DONE | detection-only |
| REST API with bearer auth + rate limit + dump quota | DONE | post-v3 |
| Incident response webhook handler | DONE | basic |
| Threat intel ingestion (URLHaus source) | DONE | one feed |
| Render-verify heuristic (static vs rendered fetch) | DONE | |

### 3.2 Out of Scope

- Multi-target continuous scanning
- Smart contract / EVM bytecode analysis
- Mobile (APK/IPA) static analysis
- Desktop binary analysis
- Active exploitation / payload delivery
- Built-in CVE database (no offline NVD mirror; SPEC §3 B-8)
- Nuclei-style template engine (SPEC §3 B-9)
- Fuzzing
- Webhook receivers from third-party scanners (Aegis produces, not consumes)

## 4. Key Features (v3.5)

### 4.1 Authenticated Crawl
- `aegis auth --session <path> --target-url <url>` opens headless browser,
  user logs in manually, session is encrypted + persisted with owner-only
  permissions.
- `aegis crawl --config <yaml> --dump <dir> --session <path>` reuses the
  session, crawls to depth N, dumps HTML/JS/screenshots, stores pages/links/
  assets/errors in SQLite.
- Render verification heuristic auto-decides per-page whether the static
  HTML is sufficient or a full Rod render is required.

### 4.2 Static + Dynamic Analysis
- `aegis scan --input <dump-dir>` runs all enabled detectors over the
  dumped content. Output: `findings.{json,html,md}`.
- Detectors: secrets (AWS/JWT/GitHub/...), OWASP Top 25 (20 cats),
  DOM XSS (sinks + sources), WAF-specific bypass patterns, ATO patterns
  (CSRF, missing HttpOnly, ...).
- All detectors default to fail-closed TLS, bounded timeouts, and
  per-client rate limiting (where they hit network).

### 4.3 Multi-Instance ATO
- `aegis exploit --config <yaml>` launches N browser instances with
  role-based naming (victim, attacker, admin).
- Tasks are YAML-defined sequences of `navigate`, `eval`, `cookie-set`,
  `assert`, etc. Variables extracted from one instance and used in
  another (`{{stolen_token}}`).
- `runFromConfig()` orchestrates the full scenario.

### 4.4 REST API
- `aegis api --addr <host:port>` starts the scan API.
- Auth: bearer token via `Authorization: Bearer <token>` or `X-API-Key` header.
- Refuses to start without `AEGIS_API_TOKEN` unless `AEGIS_API_ALLOW_UNAUTH=true`.
- Rate-limited per client IP via token bucket with TTL + LRU eviction.
- `api_dump/` is quota-capped (default 16 directories, oldest pruned).
- Sanitized error responses (no internal error string leak).

### 4.5 Browser Connector
- Optional live-browser control uses a localhost-only bridge and extension.
- Both controller and extension authenticate a token-bearing hello before any
  connection registration or command dispatch. Unauthenticated clients cannot
  replace an authenticated session.
- Tokens are generated per bridge start, delivered through registered native
  messaging or an owner-only discovery file, and rotated on restart.
- Sensitive commands use one-time popup approval or exact trusted scopes.
  Controllers cannot self-approve, change policy, or execute arbitrary
  JavaScript. Direct, workflow, scheduled, and capture paths share this module.
- Cookie/storage values require explicit inclusion, retained task data is
  bounded/redacted and locally deletable, and `/info` requires authentication.
- Linux/macOS/Windows registration and checksummed release packaging are
  implemented; clean native and store installation remain release gates.

### 4.6 Intelligence (limited)
- Single URLHaus feed ingestion; threat-cache lookup for scanned URLs.
- Not a SIEM replacement; local lookup during scan.

## 5. Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Test coverage** | ≥ 80% branch on `internal/**` | `go test -coverprofile`; CI gate fails build |
| **Quality gate pass rate** | 100% on main | `gofmt -l`, `go vet`, `go test -race` |
| **False-positive rate** | < 5% on detector patterns | Per-detector contract in SPEC §7.4.1 |
| **Crawl determinism** | Same config → same pages | Snapshot test on mock server (SPEC §7.4.2) |
| **Session security** | 100% of session files are 0o600 | `os.Stat` in CI smoke test |
| **API uptime under attack** | Rate limit prevents OOM at 1M unique spoofable IPs | `TestRateLimitBucketEvictionAtMaxBuckets` passes |
| **API disk bound** | `api_dump/` never exceeds `AEGIS_API_DUMP_MAX_DIRS` | `TestPrepareCrawlDumpDirPrunesOldest` passes |
| **No regressions** | v2 fixes (9) and v3 fixes (4) stay verified | Per-audit grep verification (SPEC §7.4.5) |

## 6. Quality Gates (per release)

1. `gofmt -l cmd internal` returns empty
2. `go vet ./...` returns no warnings
3. `go build ./...` succeeds
4. `go test -count=1 -race ./...` passes all 203+ tests
5. CI: `golangci-lint` clean
6. CI: `gosec` no HIGH+ findings
7. CI: `go test -coverprofile=coverage.out` ≥ 80% on `internal/**`

Any failure = blocked release.

## 7. False-Positive / Inconsistency Gates

These are the **contracts** every detector and orchestrator must satisfy.
Full text in SPEC §7.4; summary:

| # | Gate | What it requires |
|---|------|------------------|
| 7.1 | Per-Detector Contract | Positive + Negative + Edge case test for every detector |
| 7.2 | Crawl Determinism | Same config → same page set, regardless of worker schedule |
| 7.3 | Session Determinism | Round-trip save/load via different managers, same key |
| 7.4 | API Behavior | 7 assertions in `api/api_spec_test.go` |
| 7.5 | No-Regression | v2 and v3 fixes verified per audit, must not regress |

### 7.1 Per-Detector Contract (most important)

Every regex detector in `internal/owasp25`, `internal/xss`, `internal/scanner`,
and `internal/waf/payloads` MUST have a test file with:

- **Positive tests** (≥1): known-vulnerable input produces 1+ findings
- **Negative tests** (≥1): realistic safe input produces 0 findings
  - Use real-world-shaped data, not `xxxxxxxxx` placeholders
  - Examples: UUIDs that look like AWS keys, base64 strings that aren't
    JWTs, version strings that aren't path traversal, static `<pre>` text
    that mentions `innerHTML` as a word
- **Edge case tests** (≥1): empty string, 1MB random, unicode/emoji,
  binary noise, 1-byte truncated — must not panic, must not false-positive

A detector is **not considered implemented** until all three test types pass.
A detector that fails its negative test is over-broad; the regex must be
tightened until the negative test passes.

### 7.4 API Behavior Contract (post-v3, codified)

See SPEC §7.4.4 for the 7 assertions. Already enforced via
`api/api_spec_test.go` and the 10 v2/v3 rate-limit and dump tests.

## 8. Timeline (after v3.5)

| Phase | Target | Description |
|-------|--------|-------------|
| **v3.5** | Now | SPEC + PRD + solility-remediation plan written |
| **v4** | +2 weeks | All 20 OWASP detectors have negative tests; crawl-determinism snapshot; session-roundtrip test |
| **v4.5** | +4 weeks | B-6 (real subdomain enum) + B-3 (circuit breaker) |
| **v5** | +8 weeks | B-8 (CVE database) + B-9 (Nuclei compat layer) |
| **v6** | +12 weeks | B-4 (security headers) + B-5 (atomic writes) + B-10 (SARIF) |

Each release increases v1 finding closure rate by 5-10%.

## 9. Change Log

| Date | Version | Change |
|------|---------|--------|
| 2026-04-20 | v0.0.1 | Initial release. 25,658 LOC. 38 findings. |
| 2026-05-02 | v1 | Full 16-dimension audit. |
| 2026-06-02 | v2 | 9 new findings fixed. 12 of 38 v1 closed. 198 tests. |
| 2026-06-02 | v3 | 4 new findings fixed. No v2 regressions. 203 tests. |
| 2026-06-02 | v3.5 | SPEC + PRD + plan rewritten. Adds build-vs-buy rule, per-detector contract, capability statement, and explicit backlog. |
| 2026-11-26 | connector | Browser bridge now requires authenticated hello for controller and extension, with private discovery credentials and rotation. |
