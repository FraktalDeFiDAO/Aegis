# Plan: Integrate Feasible Claude-in-Chrome Features into Aegis Connector

**Date:** 2026-11-15 (amended 2026-11-16)\
**Status:** Proposed\
**Scope:** Add browser-automation and connector capabilities to Aegis that are feasible within the existing extension+bridge architecture and aligned with Aegis’s authorized security-scanning workflows. This plan targets practical parity for automation/observability/workflow features, not parity with Anthropic’s Claude product stack.

## 1. Scope & boundaries

### Goals (feasible, in-scope)
Add browser-automation/product capabilities that fit Aegis (authorized security scanning/crawling/exploitation workflows) and run locally via the existing extension+bridge architecture:
- Reliable long-running/background operation (reconnect, queueing, state)
- Console/network/page-error observability (debug capture)
- Richer multi-tab orchestration, tab groups, and SPA/frame fidelity
- Workflow recording, replay, and reusable shortcuts/scripts
- Scheduled/recurring browser tasks with notifications
- Download/upload handling relevant to scanning workflows
- Enhanced screenshot/visual capture
- Local permission, site allow/deny, and action-confirmation controls (Aegis-local, not AI safety classifiers)
- CLI/integration, docs, and tests

### Non-goals (not feasible / not parity)
- Claude side-panel AI chat, agent reasoning, contextual prompt suggestions, Cowork skills/plugins/connectors
- Cross-surface session/history sync (web/mobile/desktop/Anthropic account)
- Claude Code / Claude Desktop coupling, 1Password sign-in integration
- Anthropic prompt-injection classifiers, model-based action screening, org-wide admin policy enforcement
- Cloud-hosted multi-user control plane
- AI page understanding/summarization, contextual suggestions, and built-in site-specific knowledge/navigation intelligence (Aegis provides deterministic automation controls only)

## 2. Current baseline (repo)
- **Extension:** `extension/{background.js,content.js,popup.*,manifest.chrome.json,manifest.firefox.json,README.md}` — WebSocket bridge client, DOM/tab/cookie/storage/screenshot commands, basic event forwarding.
- **Bridge/connector:** `internal/connector/bridge/{protocol.go,server.go,handler.go,session.go}`, `internal/connector/{connector.go,page.go,element.go,session.go}`.
- **CLI integration:** `cmd/aegis/main.go`, `cmd/aegis/exploit.go`, `internal/crawler/crawler.go` (`--connector`, `--bridge-url`).
- **Existing plan:** `docs/plans/2026-07-18-browser-extension-connector.md` (connector implemented baseline).

### Gaps to address first
- Command/result correlation and concurrency in connector (`readLoop` vs `sendCommand` readers), limited observability.
- No recording/scheduling/downloads/tab-groups/permissions UX.
- MV3 service-worker lifetime constraints not fully addressed for long-running/background work.

## 3. Delivery phases

### Phase 0 — Foundation hardening & protocol evolution (prerequisite)
**Objective:** make the bridge reliable enough for long-running/background features.

- **Protocol/versioning** (`internal/connector/bridge/protocol.go`, extension shared handling):
  - Add protocol `version`, `capabilities`, and `hello/handshake` exchange (extension reports browser, MV2/MV3, supported commands/permissions).
  - Add request correlation fields (`requestId`/`id` consistency), structured error codes, progress/stream events, and cancellation (`cancel` command).
  - Define new event types: `console`, `network`, `pageError`, `download`, `recording`, `task`, `permissionPrompt`.
- **Bridge server** (`internal/connector/bridge/server.go`, `handler.go`, `session.go`):
  - Single dispatcher for pending command futures; fix races/timeouts; support multiple logical clients/sessions if needed and explicit extension-vs-controller roles.
  - Reconnect/session-resume semantics, buffered event replay window, heartbeat/keepalive tuning, graceful shutdown.
  - Persist minimal runtime state (active tab map, bridge port/token file for discovery) under a controlled local path.
- **Connector (Go)** (`internal/connector/connector.go`, `page.go`, `element.go`, `session.go`):
  - Replace dual-read design with one reader + pending-response map; context-aware timeouts/cancel; auto-reconnect with backoff.
  - Align API with crawler/session/exploit needs (typed results, event subscription).
- **Extension core** (`extension/background.js`, `content.js`):
  - MV3 keepalive strategy (alarms/port heartbeat) and robust reconnect; queue outbound events while disconnected.
  - Permission checks and capability-gated command dispatch.
- **Background semantics (define & enforce):**
  - **Supported conditions:** browser running, extension enabled/loaded, localhost bridge reachable, and (for MV3) wake windows driven by alarms/heartbeats or active ports.
  - **Not guaranteed:** operation while browser is fully closed, across OS sleep/hibernate, under MV3 suspension without a scheduled wake, during debugger-attach side effects, or against sites that throttle/block automation.
  - **Failure modes:** command timeout/cancel, extension disconnect, tab closed/navigated away, attach denied, permission denied.
  - **Behavior:** bounded retry with backoff for transient disconnects; persist task/run state before sleep boundaries; emit `task` events and user notifications on completion/failure/approval-needed; mark runs interrupted when guarantees cannot be met.
- **Tests/acceptance:** unit tests for protocol parse/serialize, pending-command resolution/cancel/timeout, reconnect; integration test with mock WS client (`internal/connector/bridge/bridge_test.go`, `internal/connector/connector_test.go`).
- **Exit criteria:** stable command round-trips under reconnect, no lost/duplicated responses, versioned handshake, and documented/enforced background semantics.

### Phase 1 — Observability: console, network, DOM/page errors
**Objective:** expose debug signals comparable to “console logs / live debugging” (feasible subset).

- **Extension**:
  - Use `chrome.debugger` (already permitted) via controlled attach/detach per tab/session to collect Console/Runtime/Network/Log events; fallback to page-injected hooks for console/error where debugger unavailable.
  - Capture: console messages, uncaught exceptions, failed requests, response metadata/headers (bounded/redacted), navigation/load timings.
  - **DOM/page-state capture (bounded, redacted):** structured page snapshot helpers for analysis/debug evidence (e.g. serialized DOM subtree/HTML excerpt, key attributes/text, accessibility/query snapshots, or equivalent `DOM.snapshot`-style data) with size limits and explicit opt-in for sensitive-content inclusion.
  - Commands/events: `debug.attach/detach`, `debug.getConsole`, `debug.getNetwork`, `debug.getPageState`/`page.snapshot` (or equivalent), streaming `consoleError`/`networkEvent`/`pageError`; redaction rules for secrets/cookies/auth headers.
  - **Per-browser capability notes:** Chrome/Brave/Chromium (MV3) primary for `chrome.debugger`-based capture with user-visible debugging indicator; Firefox (MV2) may lack full debugger/event parity—capability-gate commands, fall back to injected hooks/limited metadata where possible, and document unsupported fields.
- **Bridge/connector**: route/buffer/query observability and page-state events; add APIs to subscribe/pull by tab/time window with retention/size caps.
- **CLI/Aegis integration** (`cmd/aegis/*`, scanner/crawler hooks as applicable): optional flags to record console/network/page-state artifacts into dump/report (e.g. `--capture-console`, `--capture-network`, `--capture-page-state`) with size caps.
- **Tests:** protocol/event tests, mock debugger-event ingestion, page-snapshot serialization/redaction tests, capability-gating tests.
- **Exit criteria:** Aegis can capture and persist scoped console/network/error and bounded page-state evidence during connector-mode runs without breaking normal crawling, with graceful degradation on limited browsers.

### Phase 2 — Multi-tab orchestration, tab groups, and interaction fidelity
**Objective:** support multi-tab workflows and more reliable page control.

- **Manifest/permissions** (`extension/manifest.chrome.json`, `manifest.firefox.json`): add `tabGroups` (Chrome/MV3), evaluate `downloads` now or Phase 5; document Firefox parity/limits (no equivalent `tabGroups` in MV2—use capability-gated fallback such as logical tab sets/labels tracked by the extension without browser-native groups).
- **Extension commands**: `createTabGroup`, `addTabToGroup`, `removeTabFromGroup`, `listTabGroups`, `focusTabGroup`; improve `switchFrame`/frame-targeted execution, `waitForNavigation`/network-idle semantics, `select`/file-input awareness, robust element resolution, full-page & element screenshot correctness.
- **Multi-tab UX & targeting semantics:**
  - User-visible flow for selecting/assigning tabs to an Aegis working set (popup controls and/or explicit command-driven grouping), with clear indication of which tabs are controlled/recorded.
  - Deterministic **active target set** for each run/workflow (ordered tab IDs/handles, active tab, and group membership) persisted in run state; commands must target explicit tab/frame handles rather than implicit “current tab” when ambiguity exists.
  - Define focus/activation rules and behavior when a target tab closes or navigates outside scope.
- **Connector/page API**: expose tab/group handles, logical target sets, and frame context; ensure crawler/exploit can target specific tabs deterministically.
- **Tests:** unit/integration for tab-group/logical-set command routing, frame/wait behavior, and target-resolution/close semantics (where automatable).
- **Exit criteria:** workflows can operate across grouped/multiple tabs with deterministic targeting and documented user-visible selection/assignment behavior (including Firefox fallback).

### Phase 3 — Workflow recording, shortcuts, and replay
**Objective:** “record a workflow / shortcuts” equivalent for automation (local).

- **Extension recorder** (`extension/background.js`, `content.js`, optional `recorder.js`): record user actions (nav, click, input, select, scroll, waits/assertion hints) with selectors/snapshots metadata; start/stop/pause, sensitive-field masking.
- **Storage/format**: versioned workflow schema in `chrome.storage.local` and export/import as JSON file; shortcut metadata (name, description, target/site scope).
- **Replay engine**: execute recorded steps via existing command pipeline with retries/timeouts/variable substitution (URLs, secrets placeholders—not stored raw unless explicitly allowed).
- **Run artifacts (optional, bounded):** export per-run action trace (step, target, timing, result/error) and optional screenshot timeline/keyframe captures for debugging, evidence, and replay analysis; redact/mask sensitive fields and apply size/retention limits.
- **Popup/UI** (`extension/popup.*`): record controls, shortcut list/run/delete/export/import, last-run status and artifact export controls.
- **Bridge/CLI** (`internal/connector/bridge/*`, `cmd/aegis/`): `aegis workflow record|list|run|export|import` (or subcommands) using connector; store workflows in project/user config path as specified; support optional trace/screenshot artifact output paths.
- **Security:** never record passwords/tokens by default; redact values; require explicit opt-in for sensitive capture.
- **Tests:** schema validation, replay step translation, trace/artifact serialization, and redaction tests.
- **Exit criteria:** a recorded browser workflow can be saved, replayed, and invoked as a shortcut/CLI action, with optional auditable run artifacts.

### Phase 4 — Scheduling, notifications, and background tasks
**Objective:** recurring/background execution without cloud dependency.

- **Manifest/permissions**: add `alarms`, `notifications` (and `storage` already present) in MV3; MV2 mapping for Firefox.
- **Extension scheduler** (`extension/background.js`): persist schedules (cron-like/simple interval/one-shot), run workflows or predefined actions; MV3 alarm-driven wakeups; user-visible notifications on completion/failure/approval-needed.
- **Task model**: task definitions, run history, logs, enable/disable, bounded concurrency.
- **Run artifacts (optional, bounded):** retain last-run status and optional trace/screenshot timeline artifacts for scheduled runs (same schema/redaction/limits as Phase 3) for audit/debug.
- **Background semantics (operational):** schedules run only under supported conditions from Phase 0 (browser/extension/bridge available, MV3 wake windows); missed runs are recorded as skipped/interrupted with reason, retried per policy where safe, and surfaced via history/notification.
- **Popup/UI**: schedule management, notification preferences, and run-history/artifact visibility.
- **CLI/bridge**: commands to create/list/delete schedules and fetch run history/artifacts (for local automation parity).
- **Tests:** schedule serialization/next-run calculation, missed-run/interruption handling, alarm handler logic (unit-level), notification payload formatting.
- **Exit criteria:** recurring local tasks run reliably within MV3 constraints and declared conditions, with user notifications and explicit handling/reporting of missed or interrupted runs.

### Phase 5 — Downloads, uploads, and visual capture enhancements
**Objective:** handle files and richer evidence capture.

- **Manifest/permissions**: add `downloads` (and minimal host/access as required).
- **Downloads** (`extension/background.js`, protocol): list/observe downloads, wait-for-download, capture path/metadata (not exfiltrating contents by default), optional controlled download to scan workspace when explicitly requested.
- **Uploads** (`extension/content.js`, connector): set file inputs from local file references provided by Aegis (connector-mediated, explicit paths, size/type checks). Scope is **programmatic file-input/upload for workflows/scans**, not chat/side-panel attachment UX.
- **Visual capture**: full-page stitch (if feasible) or viewport+scroll captures, deterministic element clip, region metadata; annotate capture context (URL/tab/timestamp) for reports. Scope is **evidence/artifact capture**, not assistant image-sharing UX; support optional redaction/masking of sensitive regions per policy.
- **Run artifacts:** captured screenshots/clips may be linked into per-run trace/timeline artifacts (Phases 3–4) with bounded size/retention.
- **Tests:** command/response tests for download events and file-input operations (mocked where needed), plus clipping/metadata correctness where automatable.
- **Exit criteria:** scans/workflows can upload fixtures and collect/download artifacts and improved screenshots/clips as evidence with deterministic context metadata.

### Phase 6 — Local permissions, site controls, and UX polish
**Objective:** safer local operation (Claude-like control concepts, local-only).

- **Policy engine (local)**: site allow/deny lists, per-origin action permissions, modes enforced in bridge/extension before executing sensitive commands.
- **Permission-mode parity matrix (local, deterministic — no classifier/screening parity):**

  | Claude in Chrome mode (reference) | Aegis-local mode | Behavior in Aegis | Not equivalent to Claude |
  |---|---|---|---|
  | Manually approve | `manual-approve` | Every gated/sensitive action requires explicit user approval before execution (popup/notification or CLI prompt). | No model/intent or prompt-injection classifier review. |
  | Automatically approve (safety-checked) | `auto-with-prompts` | Pre-approved trusted scopes/actions may proceed; actions outside policy or always-gated categories pause for approval. | No Anthropic automatic action screening/safety classifier; decisions are deterministic policy/rule-based only. |
  | Skip all approvals | `unattended` (trusted scope only) | No interactive prompts within explicitly trusted, scoped policy; still subject to hard blocks and audit logging. | Not “safety-checked autonomy”; use only for explicitly trusted targets/workflows. |

  **Explicit limitation:** Phase 6 provides local policy enforcement and auditability only. It does **not** implement prompt-injection defenses, model-based action screening, or Anthropic safety classifiers.
- **Default-gated sensitive actions (require confirmation unless explicitly policy-allowed for trusted scope):** `eval`/script execution, cookie/storage read-write/export, downloads and uploads/file-input assignment, cross-origin navigation or navigation outside allowed scope, form submission/credential-entry flows, tab debugger attach/observability capture, and destructive/permanent operations (e.g. close/remove data). Hard-block internal/unsupported pages (`chrome://`, `about:`) and actions denied by site policy regardless of mode.
- **Prompt/approval channel**: extension popup/notification approval for gated actions; CLI `--approve/--policy` flags and non-interactive defaults for CI-like use; clear reason/context shown for each prompt.
- **Popup UX**: connection state, active tab/session, active target set, recent actions, recording/schedule status, policy settings, and approval queue.
- **Hardening**: audit log of actions/decisions, strict localhost-only bridge binding and required shared-secret hello authentication using the private discovery file/native messaging (mandatory since 2026-11-26).
- **Tests:** policy evaluation unit tests, mode/allow/deny enforcement in handler, default-gating coverage.
- **Exit criteria:** sensitive actions are controllable/auditable locally with clear defaults and documented mode semantics/limitations.

### Phase 7 — Aegis product integration, documentation, and rollout
**Objective:** make features usable in real Aegis workflows.

- **CLI & workflows** (`cmd/aegis/main.go`, relevant subcommands): flags/subcommands for capture modes, workflow run/record/schedule management, connector diagnostics (`aegis connect status`), policy config.
- **Crawler/exploit/session integration** (`internal/crawler/`, `internal/session/`, `cmd/aegis/exploit.go`): opt-in use of observability artifacts, recorded steps, multi-tab/session import-export parity, stable fallback to Rod when extension unavailable.
- **Docs**: update `extension/README.md`, add/update `docs/` usage (connector features, permissions, security model, limitations), and implementation/operations notes; refresh `docs/plans/2026-07-18-browser-extension-connector.md` or add a successor plan/status doc.
- **Compatibility matrix**: Chrome/Brave/Chromium (MV3) primary; Firefox (MV2) best-effort with documented feature gaps (tabGroups/debugger/scheduling differences).
- **Validation gates** (per repo guidance): `gofmt`, `go vet ./...`, `go build ./...`, `go test -count=1 ./...` (and `-race` for release gate where feasible); manual extension smoke tests on Chrome + Firefox for record/replay/schedule/download/policy flows.

## 4. Cross-cutting design considerations
- **Security & privacy:** localhost-only WS, least-privilege permissions, redact secrets/tokens/PII in logs/network/recordings/page snapshots, explicit opt-in for sensitive capture, bounded storage/retention.
- **MV3 constraints:** service-worker suspension → alarms/heartbeats, idempotent handlers, persisted state; avoid assumptions of long-lived in-memory state.
- **Performance & limits:** command timeouts, backpressure/buffering caps, payload size limits for screenshots/network/page-state bodies and run artifacts, per-tab debugger attach overhead.
- **Data formats:** versioned JSON schemas for workflows, schedules, policies, run traces, and captured artifacts to allow migration.
- **Feature detection:** handshake capabilities drive graceful degradation instead of hard failures (including tab groups, debugger/observability, and browser-specific command support).

## 5. Key risks & mitigations
| Risk | Mitigation |
|---|---|
| `chrome.debugger` disrupts user session / site behavior | Attach only on demand, visible indicator, scoped capture, detach on stop; capability-gate on browsers without full support |
| MV3 worker lifecycle breaks schedules/reconnect | Alarms-based wakeups, persisted queues/state, reconnect backoff; explicit missed/interrupted-run handling |
| Firefox MV2/MV3 API gaps (tab groups, debugger, alarms behavior) | Capability negotiation, documented unsupported features, logical fallback paths (e.g. non-native tab sets) |
| Sensitive data leakage in recordings/network/page-state/run artifacts | Default redaction/masking, opt-in capture, bounded payloads, retention limits |
| Dual-reader/protocol races cause hangs | Phase 0 single-reader dispatcher + correlation tests |
| Misinterpreting local policy as Claude safety/classifier parity | Explicit mode matrix/limitations, deterministic rule-based gating, audit logs, no AI screening claims |
| Scope creep into “AI agent” parity | Enforce non-goals; implement deterministic automation controls only |

## 6. Suggested implementation order & rough sizing
1. **Phase 0** (largest leverage, ~3–5 days) — required for all else (incl. background semantics)\
2. **Phase 1** (~3–4 days) — observability incl. bounded page-state capture and capability gating\
3. **Phase 2** (~2–3 days) — multi-tab fidelity, target-set semantics, and Firefox fallbacks\
4. **Phase 3** (~3–5 days) — recording/replay/shortcuts and optional run artifacts\
5. **Phase 4** (~2–3 days) — scheduling/notifications with missed/interrupted-run handling\
6. **Phase 5** (~2–3 days) — downloads/uploads/visual evidence capture\
7. **Phase 6** (~2–4 days) — local permission-mode matrix, default gating, UX/audit\
8. **Phase 7** (~2–3 days) — integration/docs/validation\

**Total:** ~19–30 engineering days, deliverable incrementally per phase with tests and docs at each milestone.
