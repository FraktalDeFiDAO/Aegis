# Aegis v4 Comprehensive Remediation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.
> **Status:** Ready to execute. Based on v4 audit (2026-07-12) covering 29 Go source files across 17 packages.
> **Previous work:** The 2026-06-02 hardening plan batches 1-8 remain valid but do NOT address the 115 v4 findings.

**Goal:** Fix all 31 CRITICAL and 35 HIGH findings from the v4 audit, close the 10 SPEC §3 backlog items, and pass all 7 quality gates (gofmt, vet, build, test -race, golangci-lint, gosec, 80% coverage).

**Architecture:** Fix by pattern, not by file. Pattern A (response body leaks) affects 4+ files — fix all at once. Pattern B (race conditions) affects injector.go — single fix. Pattern C (stubs) affects workflow.go — integrate with real packages. Pattern D (missing TLS config) affects 9 files — fix in batch.

**Tech Stack:** Go 1.25 (container: go1.24.3 via scripts/go-run.sh), go-rod/rod, cobra, yaml.v3, sqlite3, stdlib (net/http, crypto/aes, regexp, sync).

**Quality gates** (SPEC §10 — run after every batch):
```bash
./scripts/go-run.sh gofmt -l cmd internal && \
./scripts/go-run.sh go vet ./... && \
./scripts/go-run.sh go build ./... && \
./scripts/go-run.sh go test -count=1 -race ./...
```
Plus CI: golangci-lint zero, gosec no HIGH+, coverage ≥ 80%.

---

## How to Read This Plan

- **Phases** group findings by pattern, not severity order. Each phase fixes one pattern across all affected files.
- **Tasks within a phase** are sequential.
- **Phases are committed in order.** Do NOT skip ahead.
- **Quality gate per phase:** the four SPEC §10 commands must pass.
- **Frequent commits:** every file edit gets its own commit for full revertability.
- **Git flow:** branch `audit/v4-comprehensive-remediation-2026-07-12` → per-task commits → final PR to master.

---

## Phase 0: Pre-Flight (Baseline + Infrastructure)

### Task 0.1: Record current baseline metrics

**Objective:** Capture the current state so we can measure progress.

**Files:** (read-only)
- All test files
- go.mod
- .woodpecker.yaml

**Steps:**
1. Count current tests: `find . -name "*_test.go" -exec grep -c "^func Test" {} + | paste -sd+ | bc`
2. Run current gates and record failures
3. Count TODOs/FIXMEs/stubs
4. Save baseline to `.hermes/v4-baseline.txt`

**Commit:** `chore(audit): record v4 baseline metrics`

### Task 0.2: Verify Go version alignment

**Objective:** SPEC says Go 1.25; container image provides go1.24.3. Align.

**Files:**
- Modify: `go.mod` (if needed — verify go 1.25 directive works with go1.24.3)
- Modify: `scripts/go-run.sh` (ensure it uses correct image)
- Modify: `docker/Dockerfile` (ensure it uses golang:1.25-bookworm)

**Steps:**
1. Check if go.mod `go 1.25` line compiles with go1.24.3
2. If not, update Docker image to `golang:1.25-bookworm` or use `golang:1.24-bookworm` consistently
3. Document the actual toolchain version in SPEC

**Commit:** `chore: align Go toolchain version (1.24.3 container, 1.25 directive)`

### Task 0.3: Update stale audit pointer files

**Objective:** AUDIT_FINDINGS.md (already updated), AUDIT_REPORT.md, IMPLEMENTATION_PLAN.md, NEW_MODULES_README.md all point to stale v3 state or are outdated.

**Files:**
- Modify: `AUDIT_REPORT.md` — rewrite as v4 report with the 115 findings table
- Modify: `IMPLEMENTATION_PLAN.md` — point to THIS plan
- Modify: `NEW_MODULES_README.md` — update for current module set

**Commit:** `docs: update audit pointers for v4 comprehensive remediation`

---

## Phase 1: HTTP Client Hardening (Pattern D + E — 11 files)

Every `http.Client` must have `Timeout` + explicit `Transport` with `tls.Config`.
Two files use `http.DefaultClient` — must create proper clients.

### Task 1.1: Fix intel/intel.go — DefaultClient + body leak

**Files:**
- Modify: `internal/intel/intel.go`

**Changes:**
1. Replace `http.Get(feed.URL)` with per-feed `http.Client{Timeout: 30s, Transport: &http.Transport{TLSClientConfig: &tls.Config{}}}`
2. Fix `defer resp.Body.Close()` inside loop — close immediately after `Decode`
3. Add `containsTarget` depth limit (max 10 levels)

**Commit:** `fix(intel): add HTTP client timeout + fix body leak + depth limit`

### Task 1.2: Fix response/handler.go — DefaultClient + status check

**Files:**
- Modify: `internal/response/handler.go`

**Changes:**
1. Create `http.Client` with `Timeout` + explicit `Transport`
2. Check `resp.StatusCode >= 400` and return error

**Commit:** `fix(response): add HTTP client timeout + status code check`

### Task 1.3: Add explicit TLS config to 9 HTTP clients

**Objective:** Every http.Client in the codebase gets explicit `tls.Config{}` in its Transport.

**Files:**
- Modify: `internal/platform/detector.go` (line ~185)
- Modify: `internal/content/acquisition.go` (line ~87)
- Modify: `internal/scrape/scrape.go` (lines ~235, ~244)
- Modify: `internal/apiextract/extractor.go` (line ~49)
- Modify: `internal/assets/discover.go` (line ~72)
- Modify: `internal/rendercheck/rendercheck.go` (line ~377 — add Timeout too)
- Modify: `internal/exploitable/elasticsearch.go` (add to client)
- Modify: `internal/exploitable/jenkins.go` (add to client)
- Modify: `internal/exploitable/mongodb.go` (add to client)
- Modify: `internal/exploitable/redis.go` (add to client)

**Pattern for each:**
```go
// Before:
client := &http.Client{Timeout: 10 * time.Second}

// After:
client := &http.Client{
    Timeout: 10 * time.Second,
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{},
    },
}
```

**Commit per file:**
- `fix(platform): add explicit TLS config to HTTP client`
- `fix(content): add explicit TLS config to HTTP client`
- ... (one commit per file for full revertability)

### Task 1.4: Phase 1 quality gate

Run SPEC §10 commands. All must pass. If tests break due to TLS changes, fix tests.

**Commit:** `chore(audit): phase 1 HTTP client hardening complete`

---

## Phase 2: Resource Leak Fixes (Pattern A — exploitable/ package)

Every exploitable scanner tries HTTP then HTTPS sequentially.
Only the last successful `defer resp.Body.Close()` executes — prior responses leak.

### Task 2.1: Fix elasticsearch.go response body leaks

**Files:**
- Modify: `internal/exploitable/elasticsearch.go`

**Changes:**
- In `isElasticsearch` (line ~155): close HTTP response before trying HTTPS
- In `checkUnauthenticatedAccess` (line ~237): same pattern
- Remove local `min()` function (use builtin since Go 1.21+)

**Commit:** `fix(exploitable/elasticsearch): close response bodies before retry; use builtin min`

### Task 2.2: Fix jenkins.go response body leaks

**Files:**
- Modify: `internal/exploitable/jenkins.go`

**Changes:**
- In `isJenkins` (line ~148): close each response before next URL attempt
- In `getVersion` (line ~196): restructure to close response before next Get

**Commit:** `fix(exploitable/jenkins): close response bodies before retry`

### Task 2.3: Fix mongodb.go response body leak + BSON reliability

**Files:**
- Modify: `internal/exploitable/mongodb.go`

**Changes:**
1. Fix `defer resp.Body.Close()` pattern for HTTP→HTTPS retry
2. Fix `msgLength` check — use `responseTo` field (bytes 8-11)
3. Compute BSON document length from `len(bsonDoc)` instead of hardcoding `0x14`
4. Fix truncated remediation string `"security.authorization: ***"`
5. Use proper BSON parser or read full message length for `isMongoDB`

**Commit:** `fix(exploitable/mongodb): body leak + BSON protocol fixes`

### Task 2.4: Fix redis.go response parsing + TLS integration

**Files:**
- Modify: `internal/exploitable/redis.go`

**Changes:**
1. Fix RESP protocol parsing (don't break after first bulk string)
2. Fix `strconv.Atoi(port)` error handling — return error on invalid port
3. Fix `ScanTLS` Lua sandbox check to use TLS connection, not plaintext
4. Add authorization warning for active `EVAL` exploit payload

**Commit:** `fix(exploitable/redis): RESP parsing + TLS fixes + auth warning`

### Task 2.5: Fix exploitable/scanner.go worker pool safety

**Files:**
- Modify: `internal/exploitable/scanner.go`

**Changes:**
1. Add `defer recover()` in worker goroutines to prevent deadlock on panic
2. Add `sync.WaitGroup` for workers; close `findingChan` after `wg.Wait()`
3. Add target count limit to `ScanNetwork` (max 256 targets)
4. Copy `ip` before `incrementIP` to avoid iterator corruption
5. Replace `[]interface{}` return with typed `Finding` interface

**Commit:** `fix(exploitable/scanner): worker pool safety + WaitGroup + typed findings`

### Task 2.6: Phase 2 quality gate

**Commit:** `chore(audit): phase 2 resource leak fixes complete`

---

## Phase 3: Race Condition Fixes (Pattern B — browser/ + runner/)

### Task 3.1: Fix browser/injector.go race conditions

**Files:**
- Modify: `internal/browser/injector.go`

**Changes:**
1. Add `sync.Mutex` for `consoleErrors` slice — lock on append
2. Use scoped event handler (`EachEvent` returns cancel function) for dialog detection
3. Protect `result.DialogTriggered`/`result.DialogMessage` with mutex
4. Fix `injectIntoScript` — use `json.Marshal` to escape payload instead of `%q`
5. Add `Close()`/`Stop()` method to cancel event listeners

**Commit:** `fix(browser/injector): race conditions + payload escaping + cleanup`

### Task 3.2: Fix browser/automation.go cleanup paths

**Files:**
- Modify: `internal/browser/automation.go`

**Changes:**
1. Store `launcher` for cleanup in `Close()` — prevent orphaned browser processes
2. Replace `Must*` rod calls with error-checking versions
3. Make `time.Sleep` context-aware (`select { case <-time.After: case <-ctx.Done() }`)
4. Create `screenshotsDir` if it doesn't exist
5. Check `page.Close()` error; use `defer` for `browser.Close()`

**Commit:** `fix(browser/automation): cleanup paths + context-aware sleep + Must* removal`

### Task 3.3: Fix runner/runner.go thread safety

**Files:**
- Modify: `internal/runner/runner.go`

**Changes:**
1. Add `sync.RWMutex` for `Variables` map
2. Fix `time.ParseDuration` error handling — return error on parse failure
3. Document that `RunAll` is not concurrent-safe; add mutex if needed
4. Validate system chromium binary before using (health check)

**Commit:** `fix(runner): mutex for Variables + error handling`

### Task 3.4: Fix workflow/workflow.go race condition on results

**Files:**
- Modify: `internal/workflow/workflow.go`

**Changes:**
1. Protect `r.results` with mutex during parallel execution
2. Implement `notify` action case (or return error for unsupported actions)
3. Add "partial" workflow status concept

**Commit:** `fix(workflow): results mutex + notify action + partial status`

### Task 3.5: Phase 3 quality gate

**Commit:** `chore(audit): phase 3 race condition fixes complete`

---

## Phase 4: Stub Replacement (Pattern C — workflow.go + recon/)

### Task 4.1: Integrate executeCrawl with real crawler

**Files:**
- Modify: `internal/workflow/workflow.go`
- May need to modify: `internal/crawler/crawler.go` (export needed types)

**Changes:**
Replace hardcoded single-page result with actual `crawler.Crawler.Run()` call.

**Commit:** `feat(workflow): integrate executeCrawl with crawler package`

### Task 4.2: Integrate executeInject with browser/injector

**Files:**
- Modify: `internal/workflow/workflow.go`

**Changes:**
Replace `"status": "requires_browser"` stub with actual `injector.InjectPayload()` call.
Requires a browser instance to be available in workflow context.

**Commit:** `feat(workflow): integrate executeInject with browser injector`

### Task 4.3: Implement executeExtract pattern matching

**Files:**
- Modify: `internal/workflow/workflow.go`

**Changes:**
Replace empty matches array with regex-based pattern extraction from page content.

**Commit:** `feat(workflow): implement executeExtract regex pattern matching`

### Task 4.4: Replace recon/web2.go DiscoverSubdomains stub

**Files:**
- Modify: `internal/recon/web2.go`
- Create: `internal/recon/wordlists/subdomains-top1k.txt` (~1000 entries)

**Changes:**
1. Embed wordlist via `//go:embed`
2. Loop candidates, `net.LookupHost` each
3. Return resolved subdomains only (remove hardcoded 3-entry stub)
4. Accept logger via constructor option (fix resource leak on repeated `logger.New()`)

**Commit:** `feat(recon): real subdomain enumeration from embedded wordlist`

### Task 4.5: Phase 4 quality gate

**Commit:** `chore(audit): phase 4 stub replacement complete`

---

## Phase 5: Input Validation + Safety Defaults

### Task 5.1: Fix content/acquisition.go inverted allowPrivateHosts default

**Files:**
- Modify: `internal/content/acquisition.go`

**Changes:**
1. Change `allowPrivateHosts: true` default to `false` (matches SPEC §6)
2. Replace `MustConnect()` with error-handling `Connect()`
3. Replace `MustPage()` with error-handling `Page()`
4. Replace `time.Sleep(2*time.Second)` with `WaitIdle()` or `WaitRequestIdle()`
5. Move `page.Close()` to `defer` immediately after page creation
6. Add `io.LimitReader` for response body reads

**Commit:** `fix(content): safe defaults + Must* removal + defer close + size limits`

### Task 5.2: Fix ato/detector.go issues

**Files:**
- Modify: `internal/ato/detector.go`

**Changes:**
1. Add max attempts cap for `CheckBruteForce` (max 50)
2. Drain response body before close (`io.Copy(io.Discard, resp.Body)`)
3. Pre-compile regexes as package-level vars (token predictability)
4. Document `CheckRedirect` behavior (prevents following redirects)
5. Return error on `io.ReadAll` failure instead of partial response
6. Downgrade HS256 JWT flagging from MEDIUM to INFO severity

**Commit:** `fix(ato): brute force cap + body drain + precompiled regexes`

### Task 5.3: Fix platform/detector.go issues

**Files:**
- Modify: `internal/platform/detector.go`
- Modify: `internal/platform/eol.go`

**Changes:**
1. Pre-compile all regexes as package-level vars
2. Remove or implement `detectCDNs` (currently dead code)
3. Remove dead `parseVersion`/`versionGreaterOrEqual` in eol.go
4. Use `io.LimitReader` for body reads
5. Compare against `Framework` enum, not `String()` outputs

**Commit:** `fix(platform): precompiled regexes + dead code removal + size limits`

### Task 5.4: Fix scope/scope.go protocol handling

**Files:**
- Modify: `internal/scope/scope.go`

**Changes:**
1. Make protocol configurable (not hardcoded HTTP for IPs, HTTPS for domains)
2. Try HTTPS first, fall back to HTTP

**Commit:** `fix(scope): configurable protocol; HTTPS-first for domains`

### Task 5.5: Fix scrape/scrape.go worker safety

**Files:**
- Modify: `internal/scrape/scrape.go`

**Changes:**
1. Move browser lifecycle to ScrapeScope level (not per-target)
2. Use WaitGroup for workers; close results channel after all finish
3. Fix `close(jobs)` before workers drain issue

**Commit:** `fix(scrape): browser lifecycle + worker WaitGroup`

### Task 5.6: Phase 5 quality gate

**Commit:** `chore(audit): phase 5 input validation + safety defaults complete`

---

## Phase 6: Code Quality — Deduplication + Consistency

### Task 6.1: Extract shared version comparison to exploitable/version.go

**Files:**
- Create: `internal/exploitable/version.go`
- Modify: `internal/exploitable/elasticsearch.go` (remove local compareVersions)
- Modify: `internal/exploitable/jenkins.go` (remove local compareVersions)
- Modify: `internal/exploitable/mongodb.go` (remove local compareVersions)
- Modify: `internal/exploitable/redis.go` (remove local compareVersions)

**Commit:** `refactor(exploitable): extract shared version comparison`

### Task 6.2: Extract shared resolveURL to urlutil package

**Files:**
- Create: `internal/urlutil/urlutil.go` (with resolveURL + contains)
- Modify: `internal/content/acquisition.go` (remove local resolveURL)
- Modify: `internal/assets/discover.go` (remove local resolveURL, contains)
- Modify: `internal/apiextract/extractor.go` (remove local resolveURL)
- Modify: `internal/platform/detector.go` (remove local resolveURL, contains)

**Commit:** `refactor: extract shared URL utilities to urlutil package`

### Task 6.3: Fix config/config.go error handling + unexported field

**Files:**
- Modify: `internal/config/config.go`

**Changes:**
1. Return `nil, err` on unmarshal error (not partial config)
2. Export `scenarios` field or add accessor methods

**Commit:** `fix(config): error handling on unmarshal + export scenarios`

### Task 6.4: Fix integration package issues

**Files:**
- Modify: `internal/integration/scanner.go`
- Modify: `internal/integration/complete.go`

**Changes:**
1. Validate `owasp25.NewScanner("")` parameter
2. Ensure `References` initialized to empty slice, not nil
3. Add cleanup for `exploitableScan`, `owaspScanner`, `platformDetector` in `Close()`
4. Remove dead `browser *rod.Browser` field from CompleteScanner

**Commit:** `fix(integration): cleanup + nil safety + dead field removal`

### Task 6.5: Fix exploitable/elasticsearch.go version parsing

**Files:**
- Modify: `internal/exploitable/elasticsearch.go`

**Changes:**
Check `Sscanf` error for non-numeric version segments in `compareVersions`.

**Commit:** `fix(exploitable/elasticsearch): version parsing error handling`

### Task 6.6: Phase 6 quality gate

**Commit:** `chore(audit): phase 6 deduplication + consistency complete`

---

## Phase 7: Documentation + SPEC Alignment

### Task 7.1: Update SPEC.md to reflect current state

**Files:**
- Modify: `docs/SPEC.md`

**Changes:**
1. Update component statuses where fixes changed them (PARTIAL→DONE, STUB→PARTIAL)
2. Update §3 Backlog — mark closed items
3. Add Change Log entry for v4 remediation
4. Note Go toolchain version discrepancy (1.25 directive, 1.24.3 container)

**Commit:** `docs(spec): update component statuses for v4 remediation`

### Task 7.2: Update PRD.md Change Log

**Files:**
- Modify: `docs/PRD.md`

**Changes:**
Add v4 entry documenting what was fixed and what remains.

**Commit:** `docs(prd): add v4 change log entry`

### Task 7.3: Update TESTING.md with new test contracts

**Files:**
- Modify: `docs/TESTING.md`

**Changes:**
Document the detector contract tests added in Phase 1.

**Commit:** `docs(testing): document v4 test contracts`

### Task 7.4: Phase 7 quality gate

**Commit:** `chore(audit): phase 7 documentation alignment complete`

---

## Phase 8: Final v4 Audit Verification

### Task 8.1: Run full quality gates

```bash
./scripts/go-run.sh gofmt -l cmd internal
./scripts/go-run.sh go vet ./...
./scripts/go-run.sh go build ./...
./scripts/go-run.sh go test -count=1 -race ./...
```

**Commit:** `chore(audit): v4 quality gates pass`

### Task 8.2: Check coverage

```bash
./scripts/go-run.sh go test -coverprofile=coverage.out ./internal/...
./scripts/go-run.sh go tool cover -func=coverage.out | grep total
```

Target: ≥ 80% on internal/**

**Commit:** `chore(audit): v4 coverage check`

### Task 8.3: Update AUDIT_REPORT.md with final state

**Files:**
- Modify: `AUDIT_REPORT.md`

**Changes:**
Write comprehensive v4 report documenting all fixes, remaining backlog, and closure rate.

**Commit:** `docs: v4 final audit report`

### Task 8.4: Clean up and prepare for PR

**Steps:**
1. `git log --oneline audit/v4-comprehensive-remediation-2026-07-12` — verify commit chain
2. Merge/rebase against master
3. Open PR with findings summary

---

## Bounded Execution Spec

ITERATION BUDGET:  25 iterations (8 phases × ~3 tasks per phase)
EXIT ON ANY OF:
  (a) All 8 phases complete + quality gates green
  (b) Budget exhausted
  (c) 3 consecutive iterations with no measurable progress
  (d) Environmental failure not recoverable in 1 turn

CHECK-IN RULE:     Every 3 iterations or at end of budget, emit progress report.
COMMIT RULE:       Every task ends with a commit.

---

## Risk Register

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Container Go version mismatch breaks build | LOW | HIGH | Verified in Task 0.2 before any code changes |
| HTTP client timeout breaks existing tests | MED | MED | Run quality gate after each file; fix tests inline |
| Worker pool WaitGroup changes deadlock scanners | MED | HIGH | Test exploitable scanners individually before gate |
| Stub replacement introduces new bugs | MED | MED | Write failing test before integration (TDD) |
| Coverage drops below 80% during deduplication | LOW | MED | Monitor coverage at Phase 8 gate |
| User wants different priority ordering | LOW | LOW | Per-phase commits make re-ordering trivial |

---

## Out of Scope (explicitly deferred)

- B-8: Nuclei template compatibility — separate plan
- B-9: SARIF output format — separate plan  
- B-10: (was B-9 in old SPEC) — already deferred
- Smart contract / EVM analysis — out of Aegis scope
- Multi-target orchestration — out of scope
- Fuzz harness — out of scope per PRD §3.2
- Go 1.25 language features requiring go1.25 compiler — use go1.24-compatible code

*Plan complete. Begin execution with Phase 0 (baseline).*