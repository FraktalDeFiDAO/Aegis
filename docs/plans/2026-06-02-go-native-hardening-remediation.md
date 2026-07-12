# Aegis Go-Native Hardening & FP-Gate Remediation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.
> **Status:** Ready to execute. Each task is bite-sized (2-5 min), TDD-shaped, and ends with a quality gate.

**Goal:** Make every functional component in Aegis match the SPEC.md
status labels, and add the false-positive / inconsistency gates from
PRD §7 to every detector. All in Go.

**Architecture:** Build the missing test contracts first, then fix the
gaps they expose. No big-bang rewrites; each task is one failing test
+ one minimal fix + one green build.

**Tech Stack:** Go 1.25, stdlib (testing, net/http, regexp, crypto), go-rod,
cobra, yaml.v3, sqlite3, golangci-lint, gosec. All tooling runs in
Podman via `scripts/go-run.sh`.

**Quality gates** (from SPEC §10 — must pass after every task):

```bash
podman run --rm --userns keep-id -v "$(pwd):/workspace" -w /workspace \
  -e GOCACHE=/workspace/.cache/go-build -e GOMODCACHE=/workspace/.cache/gomod \
  docker.io/library/golang:1.25-bookworm bash -c "
    gofmt -l cmd internal
    go vet ./...
    go build ./...
    go test -count=1 -race ./...
  "
```

---

## How to Read This Plan

- **Batches** group related tasks; each batch ends with a verification gate
- **Tasks within a batch** are sequential (depend on previous)
- **Batches** are committed in order; do NOT skip ahead
- **Quality gate per task:** the test you wrote in step 1 must pass by step 4
- **Quality gate per batch:** the four commands above must all pass
- **Bounded execution budget:** 15 iterations; check in every 3 with progress

---

## Batch 1: Detector False-Positive Gates (PRD §7.1, SPEC §7.4.1)

**Objective:** Every detector in `internal/owasp25`, `internal/xss`, and
`internal/scanner` must have positive + negative + edge-case tests. This
batch adds 60+ test cases and fixes any detectors that fail their
negative-test contract.

### Task 1.1: Audit current detector test coverage

**Files:** (read-only)
- `internal/owasp25/scanner_test.go`
- `internal/owasp25/scanner.go`
- `internal/xss/scanner_test.go`
- `internal/scanner/scanner_test.go`

**Step 1:** Read each detector's pattern list and current tests.

**Step 2:** For each detector, write a checklist entry:
- [ ] Has positive test (vulnerable input → 1+ findings)
- [ ] Has negative test (safe input → 0 findings)
- [ ] Has edge case test (empty / huge / unicode input → no panic, no false positive)

**Step 3:** Save the checklist to `.hermes/detector-coverage.md` (create the
file). This becomes the task source for 1.2 onwards.

**Quality gate:** Document exists; every detector has an entry (TBD or done).

### Task 1.2: Add negative tests for `owasp25` IDOR + Path Traversal

**Files:**
- Modify: `internal/owasp25/scanner_test.go`

**Step 1:** Write failing test that proves false positive on safe URLs:
```go
func TestOWASP_IDOR_NegativeNoIDInURL(t *testing.T) {
    s := NewScanner()
    findings := s.ScanString(`fetch("/api/users")`, "test.js")
    for _, f := range findings {
        if f.Category == "IDOR Pattern" {
            t.Errorf("IDOR false positive on safe URL: %s", f.Evidence)
        }
    }
}

func TestOWASP_PathTraversal_NegativeLiteralDots(t *testing.T) {
    s := NewScanner()
    findings := s.ScanString(`const x = "v1.0.0-beta.1"`, "test.js")
    for _, f := range findings {
        if f.Category == "Path Traversal" {
            t.Errorf("Path Traversal false positive on version string: %s", f.Evidence)
        }
    }
}
```

**Step 2:** Run — expect FAIL (detector has no negative coverage; pattern is over-broad).

**Step 3:** Tighten the regex in `owasp25/categories.go` to require ID context
(e.g. `/users/${id}` not just `/api/users`).

**Step 4:** Run — expect PASS.

**Step 5:** Commit: `test(owasp25): add IDOR + path-traversal negative tests; tighten regex`

### Task 1.3: Add negative tests for `owasp25` SQLi + Command Injection

**Files:**
- Modify: `internal/owasp25/scanner_test.go`

**Step 1:** Write failing test:
```go
func TestOWASP_SQLi_NegativeNoTaintedVar(t *testing.T) {
    s := NewScanner()
    findings := s.ScanString(`db.query("SELECT id FROM users WHERE active = 1")`, "test.js")
    for _, f := range findings {
        if f.Category == "SQL Injection" {
            t.Errorf("SQLi false positive on static query: %s", f.Evidence)
        }
    }
}

func TestOWASP_CmdInjection_NegativeNoShell(t *testing.T) {
    s := NewScanner()
    findings := s.ScanString(`exec("/usr/bin/node app.js")`, "test.js")
    for _, f := range findings {
        if f.Category == "Command Injection" {
            t.Errorf("CmdInjection false positive on binary path: %s", f.Evidence)
        }
    }
}
```

**Step 2-5:** Same as 1.2.

### Task 1.4: Add negative tests for `scanner` AWS key + JWT + GitHub token

**Files:**
- Modify: `internal/scanner/scanner_test.go`

**Step 1:** Write failing tests:
```go
func TestScanner_AWSKey_NegativeUUID(t *testing.T) {
    s := NewScanner(t.TempDir())
    findings := s.ScanString(`const id = "550e8400-e29b-41d4-a716-446655440000";`)
    for _, f := range findings {
        if strings.Contains(f.Type, "AWS") {
            t.Errorf("AWS false positive on UUID: %s", f.Value)
        }
    }
}

func TestScanner_JWT_NegativeRandomBase64(t *testing.T) {
    s := NewScanner(t.TempDir())
    // Three random base64 segments that don't decode to a JSON header
    findings := s.ScanString(`const x = "aaaaa.bbbbb.ccccc";`)
    for _, f := range findings {
        if strings.Contains(f.Type, "JWT") {
            t.Errorf("JWT false positive on non-JWT: %s", f.Value)
        }
    }
}

func TestScanner_GitHubToken_NegativeGitSHA(t *testing.T) {
    s := NewScanner(t.TempDir())
    findings := s.ScanString(`const sha = "ghp_abcdef1234567890abcdef1234567890ABCDEF_NOT_REAL";`)
    for _, f := range findings {
        if strings.Contains(f.Type, "GitHub") && !strings.HasPrefix(f.Value, "ghp_") {
            t.Errorf("GitHub false positive on non-token: %s", f.Value)
        }
    }
}
```

**Step 2-5:** Same as 1.2.

### Task 1.5: Add negative tests for `xss` DOM XSS sink detection

**Files:**
- Modify: `internal/xss/scanner_test.go`
- Modify: `internal/xss/domxss_test.go`

**Step 1:** Write failing tests:
```go
func TestXSS_InnerHTML_NegativeStaticText(t *testing.T) {
    s := NewScanner()
    html := `<pre>var x = "safe text with innerHTML as a word";</pre>`
    findings := s.ScanHTML(html)
    for _, f := range findings {
        if f.Type == "DOM XSS" {
            t.Errorf("DOM XSS false positive on text in <pre>: %s", f.Evidence)
        }
    }
}

func TestXSS_Eval_NegativeStringLiteral(t *testing.T) {
    s := NewScanner()
    js := `const fn = "JSON.parse"; var x = JSON.parse(input);`
    findings := s.ScanJS(js)
    for _, f := range findings {
        if f.Type == "Eval Usage" {
            t.Errorf("Eval false positive on string literal: %s", f.Evidence)
        }
    }
}
```

**Step 2-5:** Same as 1.2.

### Task 1.6: Add edge-case tests for all 20 OWASP detectors

**Files:**
- Modify: `internal/owasp25/scanner_test.go`

**Step 1:** Add a table-driven test with 5 input variants per detector:
- empty string
- 1MB of random text
- unicode / emoji
- binary noise (control chars)
- truncated input (1 byte)

**Step 2-5:** Same as 1.2.

### Task 1.7: Batch 1 quality gate

Run the 4 commands from SPEC §10. All must pass. Commit:
`chore(audit): batch 1 detector FP gates complete`

---

## Batch 2: Crawl Determinism Contract (PRD §7.2, SPEC §7.4.2)

**Objective:** Same `Config` + same mock server → same set of pages
crawled. Random scheduling order must not change the final state.

### Task 2.1: Write crawl-determinism snapshot test

**Files:**
- Create: `internal/crawler/determinism_test.go`

**Step 1:** Write failing test that:
1. Spins up a `httptest.NewServer` with 5 known routes
2. Runs `c.Run()` against it with a fixed seed
3. Asserts the resulting `crawl.db` has the same set of URLs as a
   hard-coded expected list

```go
func TestCrawlDeterminism_SameConfigSamePages(t *testing.T) {
    srv := newMockSite(t, 5) // /, /a, /b, /a/1, /a/2
    defer srv.Close()
    
    cfg := Config{
        Target: srv.URL,
        MaxDepth: 3,
        Seed: 42, // NEW: deterministic seed field
    }
    
    var got1, got2 []string
    for i := 0; i < 2; i++ {
        c := NewCrawler(cfg, "")
        c.Run(t.TempDir())
        got1 = append(got1, readURLs(t, c.db))
    }
    if !reflect.DeepEqual(got1[0], got1[1]) {
        t.Errorf("non-deterministic crawl: run1=%v run2=%v", got1[0], got1[1])
    }
}
```

**Step 2:** Run — expect FAIL (no Seed field; no db read API).

**Step 3:** Add `Seed int64` to `Config`; use it for queue ordering;
expose `(*Crawler).Pages()` for tests.

**Step 4:** Run — expect PASS.

**Step 5:** Commit.

### Task 2.2: Add fuzz test for crawler URL extraction

**Files:**
- Modify: `internal/crawler/crawler_test.go`

**Step 1:** Write fuzz test:
```go
func FuzzExtractLinks(f *testing.F) {
    f.Add(`<a href="https://x.com">x</a>`)
    f.Add(`<a href="javascript:alert(1)">x</a>`)
    f.Add(`<a href="">x</a>`)
    f.Add(`<a>x</a>`)
    
    f.Fuzz(func(t *testing.T, html string) {
        links := extractLinks(html)
        for _, l := range links {
            // Invariants every extraction must satisfy
            if strings.HasPrefix(l, "javascript:") {
                t.Errorf("extractLinks leaked javascript: URL: %s", l)
            }
            if strings.HasPrefix(l, "data:") && len(l) > 64 {
                t.Errorf("extractLinks leaked large data: URL: %s", l)
            }
            u, err := url.Parse(l)
            if err != nil {
                t.Errorf("extractLinks produced unparseable URL: %s", l)
                continue
            }
            if u.Scheme != "" && u.Scheme != "http" && u.Scheme != "https" {
                t.Errorf("extractLinks produced non-http(s) URL: %s", l)
            }
        }
    })
}
```

**Step 2:** Run for 30s with `go test -fuzz=ExtractLinks -fuzztime=30s`.

**Step 3:** Fix any invariant violations found.

**Step 4:** Re-run, confirm clean.

**Step 5:** Commit.

### Task 2.3: Batch 2 quality gate

Same 4 commands; all must pass. Commit.

---

## Batch 3: Session Round-Trip Contract (PRD §7.3, SPEC §7.4.3)

### Task 3.1: Write session round-trip integration test

**Files:**
- Modify: `internal/session/session_test.go`

**Step 1:** Write failing test that:
1. Creates a SessionManager with a known key
2. Saves a known set of cookies
3. Reads it back via a fresh manager (same key)
4. Asserts the cookies round-trip exactly

```go
func TestSession_RoundTripAcrossManagers(t *testing.T) {
    key := bytes.Repeat([]byte{0x42}, 32)
    path := filepath.Join(t.TempDir(), "session.enc")
    
    want := []Cookie{
        {Name: "auth", Value: "secret", Domain: ".example.com", HTTPOnly: true},
        {Name: "csrf", Value: "abc123", Domain: ".example.com", Secure: true},
    }
    
    m1 := NewSessionManager(path, key)
    if err := m1.SaveCookies(want); err != nil { t.Fatal(err) }
    
    m2 := NewSessionManager(path, key)
    got, err := m2.LoadCookies()
    if err != nil { t.Fatal(err) }
    
    if !reflect.DeepEqual(got, want) {
        t.Errorf("round-trip mismatch: got %+v want %+v", got, want)
    }
}
```

**Step 2-5:** TDD as before. Commit.

### Task 3.2: Write session tamper-detection test

**Files:**
- Modify: `internal/session/session_test.go`

**Step 1:** Write failing test that flips a byte in the encrypted file
and expects `decrypt` to fail with a clear error.

**Step 2-5:** TDD as before. Commit.

### Task 3.3: Batch 3 quality gate

Same 4 commands. Commit.

---

## Batch 4: API Behavior Contract (PRD §7.4, SPEC §7.4.4)

The v2/v3 work already added 5 API tests. This batch fills the remaining
gaps and codifies them as the "API contract" tests.

### Task 4.1: Add `api_spec_test.go` covering the 7-assertion contract

**Files:**
- Create: `internal/api/api_spec_test.go`

**Step 1:** Write the 7 contract assertions from SPEC §7.4.4:
1. `GET /health` → 200 always
2. `GET /crawl` without auth → 401
3. `POST /crawl` with valid bearer → 202
4. Burst exceed → 429 (already covered in v2/v3)
5. `api_dump/` bounded (already covered)
6. `POST /crawl` with malformed JSON → 400
7. `POST /crawl` with invalid config (e.g. target=localhost with allow_private=false) → 400

**Step 2-5:** TDD as before. Commit.

### Task 4.2: Add concurrent-request race test

**Files:**
- Modify: `internal/api/api_test.go`

**Step 1:** Write failing test that fires 100 concurrent requests from
distinct RemoteAddr values and asserts no panic, no rate-limit false
negatives, map size bounded.

**Step 2-5:** TDD. Commit.

### Task 4.3: Batch 4 quality gate

Commit.

---

## Batch 5: Recon Stubs → Real Implementations (PRD §3, SPEC §3 B-6)

The biggest capability gap. Replace the 3-entry hardcoded subdomain
stub and the 4-port port scan with real implementations.

### Task 5.1: Add wordlist-based subdomain enumeration

**Files:**
- Modify: `internal/recon/web2.go`
- Create: `internal/recon/wordlists/subdomains-top1k.txt` (~1000 entries)

**Step 1:** Write failing test that asserts `DiscoverSubdomains("example.com")`
returns at least 50 entries and that the result varies by wordlist.

**Step 2:** Embed the wordlist via `//go:embed`. Loop and `net.LookupHost`
each candidate. Return resolved subdomains only.

**Step 3-5:** TDD. Commit.

### Task 5.2: Expand port scan to N-port common + Nmap-format top-1000

**Files:**
- Modify: `internal/recon/web2.go`
- Create: `internal/recon/wordlists/ports-top100.txt`

**Step 1:** Write failing test that asserts `PortScan("scanme.nmap.org", ...)` with
no args returns 5+ common ports AND that the default list includes 443/80/22/21/25.

**Step 2:** Expand the default port list to 100+ (from wordlist). Keep 1s timeout
per port (configurable). Add parallelism via worker pool (10 workers max) to
avoid the sequential 100s scan time.

**Step 3-5:** TDD. Commit.

### Task 5.3: Add banner grab for detected open ports

**Files:**
- Modify: `internal/recon/web2.go`

**Step 1:** Write failing test that asserts `BannerGrab("scanme.nmap.org", 22)`
returns a non-empty string within 5s for a real SSH service.

**Step 2:** Read 512 bytes with 5s timeout; return raw bytes trimmed.

**Step 3-5:** TDD. Commit.

### Task 5.4: Batch 5 quality gate

This batch uses external network. Mark tests with `t.Skip` if no network
so they don't break in offline CI. Commit.

---

## Batch 6: OWASP Detector Quality (deepen what's there)

### Task 6.1: Add CVE-version correlation to `platform/detector.go`

**Files:**
- Modify: `internal/platform/detector.go`
- Create: `internal/platform/cve.go`
- Create: `internal/platform/cve_test.go`

**Step 1:** Write failing test that asserts `DetectVersion("nginx 1.14.0")`
returns a finding with severity "HIGH" and CVE reference (using a small
embedded CVE table for nginx < 1.18.0).

**Step 2:** Add a small static `cveTable map[string][]CVE` to `cve.go`:
- nginx 1.x with known CVEs
- jQuery < 3.5.0
- Apache < 2.4.46
- WordPress < 5.5
- React < 16.13.0 (XSS via dangerouslySetInnerHTML doc)

**Step 3-5:** TDD. Commit.

### Task 6.2: Add per-detector `Confidence` field to `Finding`

**Files:**
- Modify: `internal/owasp25/categories.go`
- Modify: `internal/owasp25/scanner.go`
- Modify: `internal/xss/scanner.go`
- Modify: `internal/scanner/scanner.go`

**Step 1:** Write failing test that asserts `Finding.Confidence` is in [0,1]
and that the same input always produces the same confidence.

**Step 2:** Add `Confidence float64` field. Populate based on regex
specificity (e.g. AWS key = 0.95, "looks like a URL" = 0.30).

**Step 3-5:** TDD. Commit.

### Task 6.3: Batch 6 quality gate

Commit.

---

## Batch 7: Spec/Backlog closure (B-1 through B-10 from SPEC §3)

The "polish" pass. Each backlog item gets one bite-sized task.

### Task 7.1: B-1 — Remove hardcoded `link.insider.in` default
Replace with empty + required-flag in `cmd/aegis/exploit.go` and
`cmd/aegis/screenshot.go`. TDD. Commit.

### Task 7.2: B-2 — Unify `scrape.sanitizeSegment` and `validator.SanitizeFilename`
Move one to delegate to the other; remove duplication. TDD. Commit.

### Task 7.3: B-3 — Circuit breaker for `scanner.Scanner` worker pool
Use `sony/gobreaker` (well-known lib) or 50-line custom implementation.
TDD. Commit.

### Task 7.4: B-4 — Security headers middleware for API
Add `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`
middleware. TDD. Commit.

### Task 7.5: B-5 — Atomic session writes
Write to `session.enc.tmp`, then `os.Rename` (atomic on same FS).
TDD. Commit.

### Task 7.6: B-6 — Real intel IOC normalization
Replace raw JSON cache with STIX 2.1-like object schema.
TDD. Commit.

### Task 7.7: B-7 — CVE database mirror + correlation
`internal/cve/` package: download/parse NVD JSON feed, store in sqlite,
expose `Lookup(product, version) []CVE`. TDD. Commit.

### Task 7.8: B-8 — Nuclei template compatibility
Parse Nuclei YAML, translate `{{interact}}` etc. to Aegis terms.
Out-of-scope for this batch — file as separate plan.

### Task 7.9: B-9 — SARIF output format
Add `findings.sarif.json` output. TDD. Commit.

### Task 7.10: Batch 7 quality gate

All 4 commands green; SPEC §3 backlog B-1..B-7, B-9 closed (B-8 deferred).
Commit `chore: backlog closure batch`.

---

## Batch 8: Final v4 Audit

### Task 8.1: Re-run audit framework

**Steps:**
1. Re-read all 85 Go files
2. Update `SYSTEM_AUDIT_2026-06-02_v4.txt` with:
   - New findings introduced by batches 1-7
   - Resolution status of v3 backlog
   - v1 finding closure rate (target: 16/38 = 42.1%)
3. Verify zero regressions on v2 and v3 fixes
4. Commit `docs: v4 audit report`

### Task 8.2: Update SPEC + PRD status to reflect v4

**Files:**
- Modify: `docs/SPEC.md` (mark §3 backlog items DONE as closed)
- Modify: `docs/PRD.md` (add Change Log entry for v4)

**Quality gate:** SPEC §10 commands green; SPEC/PRD no longer reference
items that are now DONE.

### Task 8.3: Update `docs/CHECKLIST.md` and `README.md` for v4

Commit.

---

## Bounded Execution Spec

ITERATION BUDGET:  15 iterations
EXIT ON ANY OF:
  (a) All 8 batches complete + quality gate green
  (b) Budget exhausted
  (c) 3 consecutive iterations with no measurable progress
  (d) Environmental failure (e.g. network) not recoverable in 1 turn

CHECK-IN RULE:     Every 3 iterations or at end of budget, emit a progress
                   report: commits since last check-in, what was done,
                   what's left, what's blocked.

COMMIT RULE:       Every task ends with a commit OR a documented reason
                   why not (e.g. "skipping; needs network").

---

## Risk Register

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Subagent timeouts on big files (e.g. `scrape.go` 1648 LOC) | HIGH | MED | Per skill pitfall #5, read critical files in parent context; do not re-delegate |
| Wordlist size bloats binary | MED | LOW | Use `//go:embed` with `//go:generate` to keep wordlists under `internal/recon/wordlists/`; document size in SPEC |
| CVE database mirror too large | MED | MED | Defer B-7 to v5; use small embedded table for v4 |
| Test coverage drops below 80% during refactor | MED | HIGH | Add `go test -coverprofile` check to the per-batch quality gate |
| User wants to stop mid-batch | LOW | LOW | Bounded budget + per-batch commits make resume easy |

---

## Out of Scope (explicitly)

These are NOT in this plan; they require separate plans or are deferred:

- **B-8: Nuclei template compatibility** — file as a separate plan with
  its own bite-sized breakdown
- **Smart contract analysis** — out of Aegis's stated scope (PRD §2)
- **Multi-target orchestration** — out of scope; Aegis is single-target
- **Rust / language change** — Go per user direction 2026-06-02
- **Vulnerability exploitation** — `internal/exploitable/` is detection-only
  by design (PRD §3.1)

---

*Plan complete. Ready to execute. Recommend: start with Batch 1 (detector
FP gates) since it directly addresses the user's "false positives and
inconsistent results" concern.*
