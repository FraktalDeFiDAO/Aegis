# Candidate verification — 2026-11-26

Candidate: 1.1.2. Linux local verification:

- `go test ./...`: passed after correcting an existing vet diagnostic in a WAF
  test message that contained percent-encoded text.
- `go vet ./...`: passed. The SQLite dependency emits C const-qualifier warnings.
- Focused race tests for cmd/aegis, connector/bridge and nativehost: passed.
- Node extension tests: 15 passed, including group/window routing, stale group
  failure before creation, grouping rollback, internal-page policy separation,
  scheduled-command policy enforcement, native credential delivery in hello,
  and rejection of credential-less native ready responses.
- Python tests: native-host installer 2, skill installer 3, browser helper 5,
  release planner 6 passed.
- Real isolated Chromium integration: passed. Covers extension startup, automatic
  tab grouping/window, frames and open shadow roots, Angular-style ARIA controls,
  strict ambiguity rejection, transfers with SHA-256, trusted input, full-page
  capture, native dialogs, drag/drop, and policy/workflow failure handling.
- Packaged Chrome ZIP structure, root manifest, referenced assets, CRC, and version
  checked by `scripts/verify-extension-package.py`.
- Live user browser: opened a dedicated Fraktal Media Center App content tab,
  added it to the existing native Aegis group, focused it, and verified its URL
  and persisted target membership. No declaration values were changed.

The live browser was running 1.1.1 during that workspace correction. The packaged
1.1.2 group-routing changes require a manual extension reload. Clean store install,
Windows/macOS, public release authentication, privacy and policy compliance remain
unverified. See README.md for submission blockers.

## Authentication hardening continuation

- Public WebSocket tests reject missing/wrong tokens for both roles, preserve an
  authenticated controller after a failed local-origin replacement attempt, and
  verify token generation/rotation through private runtime state.
- CLI discovery tests require a matching loopback controller URL and owner-only
  state; `/ws` and `/ws?client=aegis` resolve equivalently without exposing the
  token in the URL.
- Native-host owned and reused bridge tests authenticate real WebSocket
  connections with the returned credential. Extension tests cover hello token
  delivery and rejection of a credential-less native ready response.
- `go vet ./...`, `go build ./...`, `go test -count=1 ./...`: passed. Focused race
  tests for cmd/aegis, crawler, connector/bridge and nativehost: passed. SQLite
  emits the same C const-qualifier warnings noted above.
- Full isolated Chromium integration passed after rebuilding the CLI. It now also
  rejects a wrong controller token and authenticates the unpacked extension and
  every CLI/raw-controller connection. All existing interaction, transfer,
  grouping, capture and policy checks remain green.
- Repackaged Chrome candidate structure/CRC/version checks passed. SHA-256:
  `570aa3b3bb0d6a06838d5e0f3191868378620c68f8f7991b0043615bb2edcc95`.
