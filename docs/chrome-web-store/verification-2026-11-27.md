# Candidate verification — 2026-11-27

Candidate: 1.2.0. Local host: Linux. This record supersedes the 1.1.2 candidate
record for current release preparation; it is not store approval or legal/privacy
certification.

## Passed implementation gates

- `gofmt` cleanliness, `git diff --check`, `go vet ./...`, and `go build ./...`.
- Full `go test -count=1 ./...` and full `go test -race -count=1 ./...`.
- The API package additionally passed 10 ordinary runs and 3 race runs after its
  asynchronous crawl test was isolated and dump pruning was serialized.
- Node syntax checks and 23 extension unit tests, including approval/denial/
  timeout/disconnect, exact scopes, DOM-read gating, cookie-value omission,
  schedule redaction, and scheduled-command policy enforcement.
- Python tests: native-host installer 4, skill installer 3, browser helper 5,
  release planner 6. YAML parsing passed for CI and release-candidate workflows.
- Final isolated Chromium integration passed against local fixtures only. It
  covers authenticated startup, wrong-token rejection, workspace/frame/shadow
  DOM behavior, exact-byte transfers, trusted input, dialogs, drag/drop,
  downloads, full-page PNG capture, controller self-grant/evaluation rejection,
  real popup denial and one-time approvals (including DOM text reads), CLI error
  persistence, and workflow policy replay.
- Native-host tests cover owned shutdown, same-port reuse, and rediscovery of a
  live bridge that moved to a fallback port. Connector tests cover rotated-token
  reconnect and preservation of a custom bridge when discovery has no token.
- Portable ZIP creation was exercised without a `zip` executable using the
  Python fallback. Chrome ZIP structure, assets, importScripts, CRC, and version
  passed `scripts/verify-extension-package.py`.
- `python3 scripts/build-release.py` produced the Linux amd64 release directory;
  every `SHA256SUMS` entry passed, including the included native-host installer.
  The included installer also completed a dry-run from that release directory.

## Final local artifacts

- Chrome extension ZIP SHA-256:
  `c048364bdb56819d2da8f77f58a6714bee49a9a657c81407f31b1322694627aa`.
- Linux release directory:
  `dist/release/aegis-connector-1.2.0-linux-amd64` (ignored build output).
- Screenshot: `docs/chrome-web-store/assets/screenshot-01.png`, 1280x800 RGB,
  generated from the real extension popup and an isolated sanitized approval.
  SHA-256: `2738d2cd2e4eef9cd8303c946381ca483bd5e22d3b83300c8b87b8fe59de7d7b`.
  The image-analysis service timed out, so no image-model review is claimed;
  source content and dimensions were checked and final human review remains.

## Still required outside local code

- Confirm publisher legal identity, verified store account, support/contact,
  audience/countries, downstream AI disclosures, and jurisdiction-specific
  privacy declarations. The prepared policy is not legal review.
- Merge the reviewed commit and run required CI plus the manual Linux/macOS/
  Windows release-candidate matrix. Live native behavior on macOS/Windows and
  Firefox remains unverified.
- Register the store-assigned extension ID and test a clean store-installed
  extension with the final companion, approvals, trusted scopes, and deletion.
- Push/merge through the release PR and enable master branch protection. No
  public release, tag, store submission, or publisher verification was performed.
