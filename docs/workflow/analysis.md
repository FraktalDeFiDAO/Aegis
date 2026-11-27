# Analysis Workflow

Aegis analysis is a single-target Go-native workflow:

```text
1. Define target scope
2. Capture authenticated browser session
3. Crawl target with depth and scope limits
4. Dump rendered/static content and assets
5. Run scanners over the dump
6. Generate findings report
7. Optionally run ATO scenario or screenshot/render checks
```

## 1. Scope

Create or update a YAML config in `configs/`:

```yaml
target: https://example.local
maxDepth: 3
includeExternal: false
allowPrivateHosts: false
userAgent: "AegisBot/1.0"
```

Private/loopback scanning must be explicit via config.

## 2. Auth capture

```bash
aegis auth --session ./session.enc --target-url https://example.local
```

The session is encrypted with AES-256-GCM and stored with owner-only permissions.

## 3. Crawl

```bash
aegis crawl --config configs/config.yaml --dump ./dump --session ./session.enc
```

Crawl output includes SQLite state, pages, assets, screenshots when enabled, and
crawl errors. The crawler must stay in configured scope.

## 4. Scan

```bash
aegis scan --input ./dump --format json --output findings.json
```

Scanners include secrets, OWASP patterns, DOM XSS, WAF indicators, API extraction,
platform detection, and ATO/session signals.

## 5. Optional workflows

ATO scenario:

```bash
aegis exploit --config configs/workflows/example.yaml
```

Screenshot:

```bash
aegis screenshot --url https://example.local --output screenshot.png
```

Render check:

```bash
aegis rendercheck --url https://example.local
```

## 6. Quality checks

Before trusting a result set:

- Run the Go test gate (`gofmt`, `go vet`, `go build`, `go test`)
- Confirm detector false-positive gates are present for modified detectors
- Confirm repeated crawls of the same mock target are deterministic when testing crawler changes
- Confirm API runs with auth enabled unless this is an explicit dev run

## Out of scope

This workflow does not include smart-contract bytecode analysis, Android analysis,
desktop binary analysis, or multi-target internet recon. Those are outside current
Aegis scope.
