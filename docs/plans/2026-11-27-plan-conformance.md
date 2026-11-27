# Aegis plan conformance — 2026-11-27

**Verdict: partially implemented; not fully to specification.**

This reconciles the June hardening plan, July v4 remediation plan, July browser
connector design, November feasible-features plan, and current SPEC/PRD. It does
not replace acceptance criteria or mark old checklists complete based on test
counts. Historical execution entries remain historical, not current status.

## Evidence baseline

Baseline commit: `afd7bf3`. Full `go test -count=1 -race -coverprofile=... ./...`
passed on Linux with Go 1.24.3. The baseline has 36.5% total and **44.4% internal
statement coverage** (3,478/7,827 internal statements). This is not branch
coverage and does not satisfy the SPEC's 80% branch-coverage gate. Lint/security
scanner gates and live Firefox/macOS/Windows/store-install acceptance remain
separate from unit/race test success. A green test suite alone does not establish readiness.

## Confirmed fixes in this batch

- V4 2.5: reject CIDRs above 256 addresses before allocating/enumerating; copy
  the IP iterator; bound workers and queue state; handle zero/negative workers;
  join workers and close results deterministically. A recovered scanner panic
  produces an explicit typed `ScanFailure`, while other targets continue.
  Service result APIs now return the closed `Finding` interface rather than
  unconstrained `interface{}` values. Result order remains completion order.
- V4 2.4 / SPEC detection-only: removed the Redis Lua `io.popen('id')` execution
  probe instead of adding an authorization warning around active exploitation.
  TLS scanning no longer opens a plaintext Lua-probe connection. Redis INFO
  uses a bounded complete RESP bulk read; malformed, oversized and truncated
  replies fail. `ScanURL` validates scheme/host/port and routes `rediss` to TLS.
- V4 2.1: removed the local `min` shadow so the builtin is used.
- V4 3.4: serialize reuse of a Go workflow runner; propagate parent deadlines to
  nested steps; honor parallel limits and join workers before exposing results.
  Nested failure propagates, and continued failures produce `partial` status.
- V4 4.1–4.3 safety correction: unsupported Go workflow crawl/inject/extract steps
  now fail explicitly instead of inventing successful results. Their actual
  integrations remain **unimplemented**, not closed by this safety correction.
- Connector phase 5: Go `Page.Screenshot(true, ...)` dispatches the real full-page
  command; malformed base64 returns an error. Unsupported document-script
  injection also returns an error instead of an empty successful identifier.
- CI uses the setup action's actual Chrome-for-Testing executable for isolated
  integration, rather than assuming an Ubuntu `chromium` apt package/path. PRs
  targeting release branches now run CI, supporting stacked review.

## Findings that must not be applied literally

- The v4 text says only the last deferred body close runs. Go runs all registered
  defers. The inspected Elasticsearch/Jenkins fallback paths advance only after
  request errors; they do not demonstrate the claimed sequence of successful
  response leaks. Keep bounds/close/error testing, but do not manufacture a fix
  from that explanation. Mongo wire-protocol correctness is a separate open issue.
- The v4 Redis task requests a warning around an active shell probe. The current
  SPEC/PRD explicitly require detection-only service probes; that constraint wins.
- Removing arbitrary extension evaluation for store safety supersedes the older
  connector examples that promise arbitrary script execution. Dedicated commands
  are the supported contract. Unsupported methods must not pretend to succeed.

## Connector phase matrix

| Phase | Status | Evidence and remaining acceptance gap |
| --- | --- | --- |
| 0 Foundation | Partial | Authenticated hello, private discovery, rotation/reconnect and one reader are tested. Cancellation/resume/worker-suspension semantics still need a complete failure matrix. |
| 1 Observability | Partial | Debugger capture, bounded/redacted records, snapshots and crawler flags exist. Browser-specific fallback and complete event/capture contracts remain to verify. |
| 2 Tabs/frames | Partial | Native groups, saved workspace, strict ARIA controls, child frames and open shadow roots are covered by Chromium fixtures. Go `Frame`/`MainFrame` remain rod placeholders; request-idle is approximate; live Firefox acceptance is open. |
| 3 Recording/replay | Partial | Recording, storage, replay, CLI and policy gates exist. Version/schema validation, retries, variable substitution and full shortcut/artifact UI are not established. Current replay's `screenshots` field contains DOM snapshots, not an image timeline. |
| 4 Scheduling | Partial | Interval alarms, run history and missed-run records exist. Alarm and keepalive dispatch can overlap without a persisted run lease; one-shot/cron choices, bounded concurrency and complete management UI remain open. |
| 5 Transfers/capture | Partial | Native/stream upload and download hash tests, trusted input and full-page PNG exist. Go full-page routing fixed here; element clipping and capture-context/redaction contracts remain open. |
| 6 Permissions | Implemented, acceptance partial | Real one-time approvals, exact scopes, remote self-grant/evaluation rejection, private bridge auth and deletion are tested. Manual browser/platform matrix and exhaustive dispatch coverage remain release gates. |
| 7 Product/release | Partial | CLI, skills, compatibility docs, manifests, installers and package verification exist. Clean store-assigned ID/native install, external publisher details, live platform matrix, and full quality-gate parity remain open. |

## Core remediation matrix

| Area | Status and next acceptance evidence |
| --- | --- |
| June detector/crawl/session/API contracts | Existing tests pass; audit individual positive/negative/edge contracts before closing the whole plan. Root instructions still contain stale environment/CLI descriptions. |
| V4 phase 0/toolchain | Module says Go 1.24; SPEC says Go 1.25+. Resolve the supported-version contract and wrapper/container docs together; do not claim aligned from a Go 1.24.3 test. |
| V4 phase 1 HTTP | Pending hardening was committed earlier; verify all outbound clients, TLS opt-ins, response limits and redirects against the per-task list. |
| V4 phase 2 protocols/resources | Worker/CIDR/Redis issues fixed here. Mongo OP_MSG builders lack required sections/$db; reply matching reads the wrong field and mock responses are synthetic. Real protocol tests and bounded BSON parsing remain open. |
| V4 phase 3 races/lifecycle | Workflow fixes covered here. Browser injector still appends console state without a mutex and its dialog listener lifecycle is incomplete; automation/runner cleanup tasks remain open. |
| V4 phase 4 stubs | Go workflow integrations remain unsupported and now report failure honestly. Recon still returns three invented subdomains; replace it with resolved results and deterministic resolver tests. |
| V4 phase 5 defaults | Content acquisition still permits private hosts by default, uses MustConnect, and reads bodies without a bound. Brute-force limits, platform bounds, scope protocol and scrape lifecycle tasks remain open. |
| V4 phase 6 quality | Version/URL deduplication, config errors, integration consistency and Elasticsearch parsing require task-level evidence; not closed by the present tests. |
| V4 phases 7–8 final verification | Current matrix linked from plan pointers and SPEC/PRD. Full closure of 115 historic findings, lint/gosec results, coverage and manual gates is outstanding. No final v4 closure claim. |

## Verification for this change

- Full fresh Go race suite with coverage, vet, build and gofmt: passed.
- Internal statement coverage after this batch: **45.7%**, below the target;
  branch coverage remains unmeasured.
- Extension unit tests: 23 passed. Python: native installer 4, skill installer 3,
  browser helper 5, release planner 6 passed.
- Isolated Chromium integration: passed, including authenticated connections,
  real popup approval/denial, strict targeting, transfers and full-page capture.
  Remote CI exposed a Chrome-for-Testing 158 harness defect: a built-in extension
  also had a `background.js` worker and was selected by filename alone. Reproduced
  with CI's exact browser; fixed worker selection to verify the manifest name and
  assert policy setup/readback before testing approvals. The complete suite then
  passed locally on both system Chromium and Chrome for Testing 158.
- `golangci-lint v1.64.8` (default linters, uncapped diagnostics): **failed**,
  79 diagnostics across production/tests: 67 errcheck, 4 gosimple, 4 unused,
  4 staticcheck (the latter include related-location diagnostics). No diagnostics
  point to the new conformance test files. Existing issues remain a release gate.
- `gosec v2.22.0 -severity high`: **failed**, 18 HIGH-rated diagnostics,
  with no package-load errors. Rule counts: G115 integer conversions 4, G404
  non-cryptographic randomness 1, G402 TLS 11, G101 credential-pattern matches 2.
  These require triage; they are not automatic confirmation of exploitable
  vulnerabilities. Explicit TLS test-mode options, type-conversion bounds,
  reconnect jitter and enum labels need contextual assessment.


Regression tests cover oversized IPv4/IPv6 CIDRs, worker panic/zero-worker cases,
fragmented/malformed Redis frames, invalid Redis URLs, absence of Lua execution on
an old-version fixture, full-page command routing, invalid screenshot encoding,
unsupported script injection, false workflow success, partial status, nested
failure/deadline propagation, parallel limits, and concurrent runner reuse.

Run the full race/build/vet suite and extension/Python checks before merging.
The isolated Chromium suite uses a separate profile and local fixtures; the live
user browser and account-security flow are not part of this pass.

## Next implementation order

1. Complete protocol correctness and injector/lifecycle safety (v4 phases 2–3).
2. Replace Go workflow/recon stubs with real implementations and tests (phase 4).
3. Fix acquisition defaults/bounds and remaining input-safety tasks (phase 5).
4. Finish connector schema/replay/scheduler/typed-frame contracts from the matrix.
5. Close lint/security/coverage and manual platform/store gates with evidence.

The batch prioritizes confirmed safety defects across overlapping plans. This is
an explicit deviation from the old per-file/strict-phase commit recipe: related
production changes and their regression tests travel together in reviewable
commits. Unverified tasks remain open.
