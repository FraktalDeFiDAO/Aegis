# Connector Compatibility Matrix (Feasible Features)

## Scope
Covers browser-extension connector features implemented/planned per `docs/plans/2026-11-15-connector-feasible-features-plan.md`. Localhost-only, deterministic local controls; no cloud/session sync, no AI safety classifier parity.

## Browser support

| Capability | Chrome/Brave/Chromium (MV3) | Firefox (MV2 temp add-on) | Notes |
|---|---:|---:|---|
| Core control (nav/tabs/elements/cookies/storage/screenshot) | Primary | Best-effort | Internal pages (`chrome://`, `about:`) unsupported by extension APIs |
| Authenticated protocol v1 handshake/correlation/progress-cancel hooks | Yes | Yes (best-effort) | Token-bearing hello required before registration/commands |
| Runtime discovery/state (`~/.config/aegis/connector/runtime.json` or XDG) | Yes | Yes | Localhost-only; owner-only token, per-start generation, live-process lock, reconnect refresh |
| Observability (debugger console/network/page state) | Best-effort, capability-gated | Limited/varies | `chrome.debugger` availability/UX differs; attach is explicit and may show indicator |
| Tab groups (native) | Yes (`tabGroups`) | Fallback logical target set | Deterministic targeting should use explicit tab IDs when available |
| Recording/workflows (local storage, replay, export/import CLI) | Best-effort | Best-effort | Sensitive-field redaction default; MV3 lifecycle can interrupt long sessions |
| Scheduling/alarms/notifications + run history | Best-effort | Best-effort | Depends on browser running/extension loaded/bridge availability; missed runs recorded best-effort |
| Downloads/uploads/visual evidence | Native file paths, streamed files, download retrieval; debugger/downloads gated | Streamed/payload uploads; native debugger controls unavailable | Same-machine filesystem for native paths/retrieval; stream one file up to 256 MiB |
| Explicit frame targeting | Browser frame IDs, per-tab selection and per-command override | webNavigation/content-script route (not yet live verified) | Frame 0 explicitly selects top document; cross-origin Chromium tested |
| Trusted input / native JS dialogs / full-page PNG | Debugger-backed mouse, keys, text, drag/drop, dialogs, capture | Unsupported | Browser/OS settings and arbitrary desktop control remain outside this layer |
| Local policy modes & gating | One-time popup approvals and exact trusted scopes | Same implementation; live verification pending | Controllers cannot self-approve, change policy, or execute arbitrary JavaScript. No classifier/prompt-injection screening |
| Arbitrary controller `evaluate`/`evaluateAll` | Removed | Removed | Dedicated page/element commands replace normal connector operations |

## Validation status (automated vs manual)

| Area | Automated in repo CI/local container | Manual required |
|---|---|---|
| Go protocol/bridge/connector/crawler/cmd build & tests | Yes (`go build ./...`, `go test ./...`, selected `-race`) | No |
| Extension JS/manifest syntax | Yes (`node --check`, `jq`) | No |
| Isolated Chromium extension↔bridge E2E, including authentication | Yes (`node scripts/test-browser-connector.cjs ./aegis`) | No |
| Live-profile UI flows, browser permissions, MV3 lifecycle behavior | No | Yes (Chrome/Brave/Firefox) — see `docs/plans/2026-11-15-connector-manual-smoke-checklist.md` |

## Known limitations / residual risks
- Extension service worker suspension (MV3) can delay/miss alarms or in-memory state; persisted storage and alarms mitigate but do not guarantee continuous background execution.
- Debugger-based capture can affect page behavior/performance and requires user-visible debug indicators/permissions where applicable.
- Full parity with Claude in Chrome UX/AI features is explicitly out of scope; policy enforcement is local and deterministic only.
