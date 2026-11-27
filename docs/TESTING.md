# Testing Aegis

## Local test gate

Use Podman because the host may not have Go installed:

```bash
podman run --rm --userns keep-id \
  -v "$(pwd):/workspace" -w /workspace \
  -e GOCACHE=/workspace/.cache/go-build \
  -e GOMODCACHE=/workspace/.cache/gomod \
  docker.io/library/golang:1.25-bookworm bash -c '
    gofmt -l cmd internal
    go vet ./...
    go build ./...
    go test -count=1 ./...
  '
```

Release gate adds race detector:

```bash
./scripts/go-run.sh go test -count=1 -race ./...
```

## Detector false-positive gates

Every detector in `internal/scanner`, `internal/owasp25`, `internal/xss`, and
`internal/waf` must have:

1. Positive test: known-vulnerable input produces findings
2. Negative test: realistic safe input produces no findings
3. Edge-case test: empty, huge, unicode, binary, and truncated input does not panic

A detector without all three test types is not considered complete.

## Determinism gates

- Crawler: same config and same mock server must produce the same page set
- Session: same encrypted session and key must round-trip through a fresh manager
- API: `/health`, `/crawl`, auth, malformed JSON, rate limit, and dump quota must be contract-tested

## Network tests

Network-dependent tests must be skippable in offline CI. Prefer `httptest.NewServer`
for unit and integration tests. External targets such as `scanme.nmap.org` should be
used only in explicitly marked integration tests.

## Coverage target

CI target: 80% branch coverage on `internal/**`. If a package cannot reasonably hit
80% because it wraps Rod/Chromium or external network behavior, add focused mockable
units rather than lowering the global target.

## Plan conformance regression checks (2026-11-27)

Current status and outstanding acceptance gates are tracked in
[the plan-conformance matrix](plans/2026-11-27-plan-conformance.md).

```sh
go test -race ./internal/exploitable ./internal/workflow ./internal/connector
go test -count=1 -race -coverprofile=/tmp/aegis-coverage.out ./...
go vet ./...
go build ./...
node --test extension/tests/*.test.cjs
go build -o /tmp/aegis-candidate ./cmd/aegis
node scripts/test-browser-connector.cjs /tmp/aegis-candidate
```

Service tests use local fixtures, including deliberately fragmented/malformed
RESP frames and an old Redis banner that must never trigger Lua execution.
Worker tests cover CIDR bounds, zero workers, panic isolation, and completion.
Workflow tests distinguish unsupported/partial/failed outcomes and verify nested
cancellation, concurrency limits and safe runner reuse. Connector tests verify
full-page routing and rejection of malformed image data/unsupported injection.

The Go coverage profile measures statements, not branches. Do not describe it as
meeting the SPEC's branch-coverage criterion. Lint and security diagnostics need
triage rather than being erased by blanket exclusions. Browser integration uses
an isolated profile; it does not prove live Firefox or clean store installation.
