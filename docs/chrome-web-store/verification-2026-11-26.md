# Candidate verification — 2026-11-26

Candidate: 1.1.2. Linux local verification:

- `go test ./...`: passed after correcting an existing vet diagnostic in a WAF
  test message that contained percent-encoded text.
- `go vet ./...`: passed. The SQLite dependency emits C const-qualifier warnings.
- Focused race tests for cmd/aegis, connector/bridge and nativehost: passed.
- Node extension tests: 13 passed, including group/window routing, stale group
  failure before creation, grouping rollback, internal-page policy separation,
  and scheduled-command policy enforcement.
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
