# Audit Findings — v4 Comprehensive (2026-07-12)

## Status

| Severity   | Count |
|------------|-------|
| CRITICAL   | 31    |
| HIGH       | 35    |
| MEDIUM     | 17    |
| LOW        | 11    |
| INFO       | 15    |
| **TOTAL**  | **109** |

## Key Patterns

### Pattern A: Response Body Leaks in exploitable/
Every scanner (elasticsearch, jenkins, mongodb, redis) tries HTTP then HTTPS
sequentially without closing the intermediate response body. `defer resp.Body.Close()`
inside conditional branches only closes the last successful response.

### Pattern B: Race Conditions in browser/injector.go
`consoleErrors` slice and dialog result fields are written from event handler
goroutines without synchronization (no mutex, no channel).

### Pattern C: Stub Functions in workflow.go
`executeCrawl`, `executeInject`, `executeExtract` are placeholders that return
empty/hardcoded results. The notify action has no implementation.

### Pattern D: Missing Explicit TLS Config
9 HTTP clients have `Timeout` but no explicit `Transport` with `tls.Config`.
SPEC §1 says: "Every TLS config defaults to verified; unverified mode is opt-in."

### Pattern E: Missing HTTP Client Timeouts
`intel/intel.go` and `response/handler.go` use `http.DefaultClient` with no timeout.

### Pattern F: Code Duplication
- `compareVersions`/`versionInRange` duplicated across 4 exploitable scanners
- `resolveURL` duplicated across 4 packages
- `contains` helper duplicated across 2 packages

## Authoritative Sources

- `AUDIT_REPORT.md` — v4 comprehensive report with full finding details
- `docs/plans/2026-07-12-v4-comprehensive-remediation.md` — active remediation plan
- `.hermes/cache/delegation/subagent-summary-0-20260712_074203_196428.txt` — raw subagent output (115 findings)

## Previous Audit Versions

| Version | Date       | Findings | Status      |
|---------|------------|----------|-------------|
| v1      | 2026-05-02 | 87       | 12/38 closed (31.6%) |
| v2      | 2026-06-02 | 38       | 16/38 target, 9 fixes in PR #1 |
| v3      | 2026-06-02 | 0 open   | Claimed resolved (now known stale) |
| v4      | 2026-07-12 | 115      | In remediation |