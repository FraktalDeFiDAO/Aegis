# Aegis

Aegis is a Go-native CLI for authenticated web crawling and vulnerability triage.
It captures an authenticated browser session, crawls a scoped target with Rod/Chromium,
dumps rendered content and assets, and scans the dump for secrets, DOM XSS, OWASP-style
patterns, WAF indicators, exposed APIs, and session/ATO weaknesses.

Aegis is intentionally focused: one authorized target, one reproducible crawl, one
finding set. It is not a Burp Suite/Caido replacement, not an active exploitation
framework, and not a multi-target internet scanner. The current goal is to make every
implemented feature solid, deterministic, tested, and Go-native.

## Current capability

- Authenticated browser session capture (`auth`)
- Scoped Rod/Chromium crawling with depth limits (`crawl`)
- Static and rendered-content scanning (`scan`)
- DOM XSS and OWASP-pattern detection
- WAF fingerprinting and bypass payload generation
- API endpoint extraction from rendered content
- ATO scenario runner with multiple browser instances (`exploit`)
- Screenshot and render-difference checks
- REST API with fail-closed auth, rate limiting, and bounded dump directories
- URLHaus-based threat-intel lookup
- Detection-only service probes for Jenkins, Elasticsearch, MongoDB, and Redis

Known gaps are documented in `docs/SPEC.md` §3 and implemented through
`docs/plans/2026-06-02-go-native-hardening-remediation.md`.

## Build

The host may not have Go installed. Use the Podman-backed wrapper:

```bash
./scripts/go-run.sh go build -o aegis ./cmd/aegis/
```

Direct container command:

```bash
podman run --rm --userns keep-id \
  -v "$(pwd):/workspace" -w /workspace \
  -e GOCACHE=/workspace/.cache/go-build \
  -e GOMODCACHE=/workspace/.cache/gomod \
  docker.io/library/golang:1.25-bookworm \
  go build -o aegis ./cmd/aegis/
```

## Test gates

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

Use `go test -race ./...` for the release gate when the environment can tolerate
the extra runtime and cgo overhead.

## CLI workflow

```bash
# 1. Capture an authenticated session
aegis auth --session ./session.enc --target-url https://target.example

# 2. Crawl the target using the captured session
aegis crawl --config configs/config.yaml --dump ./dump --session ./session.enc

# 3. Scan the dump
aegis scan --input ./dump --format json --output findings.json
```

API mode:

```bash
export AEGIS_API_TOKEN='change-me'
aegis api --addr 127.0.0.1:8080
curl -H "Authorization: Bearer $AEGIS_API_TOKEN" http://127.0.0.1:8080/health
```

## Documentation

- `docs/PRD.md` — product requirements and scope
- `docs/SPEC.md` — technical specification and quality gates
- `docs/TESTING.md` — testing strategy
- `docs/api-reference/index.md` — current API endpoints
- `docs/architecture/overview.md` — current architecture
- `docs/plans/2026-06-02-go-native-hardening-remediation.md` — implementation plan to strengthen gaps

## Security posture

Aegis is designed for authorized testing only. It blocks private/loopback targets by
default unless explicitly configured, stores sessions encrypted with AES-256-GCM, and
requires API authentication unless `AEGIS_API_ALLOW_UNAUTH=true` is deliberately set
for development.

## Live browser connector

See [extension setup](extension/README.md) for Chrome/Brave/Chromium and Firefox,
[connector compatibility](docs/CONNECTOR_COMPATIBILITY.md), and the bundled
[model skills](skills/aegis-browser/SKILL.md). Package with
`bash scripts/package-extension.sh`; Chrome loads `dist/extension/chrome`.

The current 1.1.2 package is a development candidate. Follow the
[Chrome Web Store readiness checklist](docs/chrome-web-store/README.md) before
public distribution and the [Git workflow](docs/workflow/git.md) for changes.
