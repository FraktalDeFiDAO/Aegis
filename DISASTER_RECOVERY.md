# Disaster Recovery — Aegis

This document covers recovery procedures for Aegis when the on-call engineer
is paged. Aegis is a Go-based security scanner; outages are usually
environmental (browser launch, network, container) rather than data corruption.

## Contact & escalation
- Repository: https://github.com/FraktalDeFiDAO/Aegis
- Build host: Btrfs root, podman overlay driver, golang:1.25-bookworm image
- All tooling runs in Podman (no host Go install)

## 1. API server won't start

**Symptom:** `aegis api` exits immediately with "AEGIS_API_TOKEN is required".

**Cause:** The API server has fail-closed auth (since v0.0.1-bounty-hardening).
`AEGIS_API_TOKEN` must be set unless `AEGIS_API_ALLOW_UNAUTH=true` is exported.

**Fix:**
```bash
export AEGIS_API_TOKEN="$(openssl rand -hex 32)"
aegis api --addr 127.0.0.1:8080
```

For dev only:
```bash
export AEGIS_API_ALLOW_UNAUTH=true
```

**Verification:**
```bash
curl -fsS http://127.0.0.1:8080/health
# {"status":"ok"}

curl -fsS -H "Authorization: Bearer $AEGIS_API_TOKEN" \
  -X POST http://127.0.0.1:8080/crawl -d @config.json
```

## 2. Browser won't launch (Rod / Chromium)

**Symptom:** `failed to launch browser` or "Chrome not found" in logs.

**Cause:** Chromium binary not on `PATH` or no-sandbox flags missing.

**Fix (Linux container):**
```bash
# Install Chromium dependencies (Debian/Ubuntu)
apt-get update && apt-get install -y \
  chromium libnss3 libatk1.0-0 libatk-bridge2.0-0 libxss1 libgbm1 \
  libasound2 libxshmfence1 libxcomposite1 libxrandr2 libxdamage1

# Or set CHROME_BIN to a discovered binary
export CHROME_BIN=/usr/bin/chromium
```

**Fix (Podman rootless):** Rod needs `--no-sandbox`; see `internal/browser/launcher.go`.

## 3. SQLite lock on crawler store

**Symptom:** `database is locked` errors during deep crawl.

**Fix:** WAL checkpoint and graceful close.
```bash
# If process hung:
pkill -f "aegis crawl"
# Verify no leftover lock files
ls -la workspace/store.db*
```

`internal/crawler/store.go` runs `PRAGMA journal_mode=WAL` on open; ensure
the process exits cleanly to checkpoint WAL.

## 4. Container build / module cache issues

**Symptom:** `go build` fails with cache permission errors or missing modules.

**Fix:**
```bash
# Clean Podman-side cache and rebuild
rm -rf .cache/gomod .cache/go-build
./scripts/go-run.sh go mod download
./scripts/go-run.sh go build ./...
```

The `scripts/go-run.sh` wrapper uses `--userns=keep-id` and mounts
`~/.cache/go-build` and `~/.cache/gomod` so the next run is fast.

## 5. Rate-limit lockout (legitimate user)

**Symptom:** API returns `429 Too Many Requests`.

**Cause:** Per-client token bucket (default 60 req/min, burst 10).

**Fix:** Raise the limits via env vars:
```bash
export AEGIS_API_RATE_PER_MIN=600
export AEGIS_API_RATE_BURST=50
```

To disable rate limiting entirely (dev only):
```bash
export AEGIS_API_RATE_PER_MIN=0
```

## 6. Corrupted session file

**Symptom:** `decrypt session: cipher: message authentication failed`.

**Cause:** Wrong key, or session file written by an older key version.

**Fix:** Delete the session file and re-capture:
```bash
rm -f session_lock.json
aegis auth --session session_lock.json --target-url https://target.com
```

Session files are AES-256-GCM encrypted; the key is the 32-byte hex passed
via `--key` (or a fresh one is generated and printed if not provided).

## 7. Roll back a bad release

```bash
git log --oneline -10
# Find the last good commit
git checkout <good-sha>
./scripts/go-run.sh go build -o /tmp/aegis ./cmd/aegis/
# Test
/tmp/aegis --help
# Roll back
git checkout master
```

## 8. Scan artifacts polluting the repo

If `aegis-scan-*.{html,json,md}` files reappear at the repo root or in
`scan-output/`/`scan-results/`, they should be ignored. The `.gitignore`
already covers:
- `aegis-scan-*`
- `scan-output/`
- `scan-results/`
- `screenshots/`
- `api_dump/`
- `workspace/`

Clean them with:
```bash
git rm -r --cached aegis-scan-* scan-output/ scan-results/ screenshots/ 2>/dev/null
rm -rf aegis-scan-* scan-output/ scan-results/ screenshots/ api_dump/
```

## Postmortem checklist

After any incident:
1. Capture `aegis --version` and the last 200 lines of logs
2. Note Podman image digest and host kernel
3. Check the .woodpecker CI pipeline for any recent regressions
4. Update this document if a new failure mode is discovered
