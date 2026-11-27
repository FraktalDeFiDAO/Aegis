# Aegis Connector — Manual Smoke Checklist (Browser)

**Date:** 2026-11-16\
**Purpose:** Blocker mitigation for environments without automated extension-load/browser UI validation. Use when automated smoke is not feasible.

## Preconditions
- Build/run Aegis from repo per `README.md` (host Go or Podman/golang:1.25-bookworm workflow).
- Load extension unpacked: Chrome/Brave/Chromium (`extension/manifest.chrome.json` context: load `extension/` with MV3 manifest as default if applicable) or Firefox (`extension/manifest.firefox.json` as temporary add-on; ensure correct manifest selected per browser workflow).
- Bridge reachable on localhost (default `ws://127.0.0.1:9876/ws` or Aegis-provided port). No remote exposure.

## Matrix
| Area | Chrome/Brave/Chromium (MV3) | Firefox (MV2 best-effort) |
|---|---|---|
| Connect/reconnect | Verify popup connect/disconnect, auto-reconnect/backoff, status updates | Same; note any MV2 differences |
| Core commands | navigate, tabs, click/type/fill, waits, dedicated page/element reads and guarded edits, cookies/storage, screenshot | Same; capability-gate where unsupported |
| Observability | debugger attach/detach (user-visible indicator), console/network/page-state capture, redaction/bounds | Fallback/limited; document unsupported fields |
| Multi-tab/groups | native `tabGroups`, deterministic target set, frame targeting | Logical tab-set fallback (no native groups) |
| Record/replay | record start/stop/pause, workflow store/export/import (if UI/CLI), replay trace, redaction | Same best-effort |
| Schedule/notifications | alarms/notifications, run history, missed/interrupted handling | Best-effort per MV2 support |
| Downloads/uploads | download list/wait metadata, upload.file (content-provided) | Capability-gated |
| Policy/approvals | manual-approve / auto-with-prompts / unattended (trusted scope), default-gated actions, audit/log events | Same deterministic local behavior |

## Test steps (execute and record results)
1. **Connect:** Start bridge (`aegis` connector mode or standalone flow), open popup, confirm “Connected”. Kill/restart bridge and confirm reconnect/backoff without lost command correlation for new commands.
2. **Core navigation/tabs:** `listTabs`, `newTab`, `switchTab`, `navigate`, `getTitle/getCurrentUrl`, `closeTab` on non-internal pages.
3. **DOM/actions:** `querySelector(All)`, `click`, `type/fill/clear/select`, waits (`waitForSelector/load/idle/timeout/navigation`), `extractData`.
4. **Approvals and evaluation removal:** `evaluate`/`evaluateAll`, remote `policy.set`, and remote `approval.respond` must be rejected. In manual mode, deny one command and approve another once through the real popup. Verify unattended mode only allows exact trusted origin/path scopes.
5. **Cookies/storage (gated/redacted):** get/set/delete/clear cookies and local/session storage on authorized target; verify no secret leakage in logs.
6. **Screenshots/visuals:** `captureVisibleTab`, element screenshot/full-page flow if available; confirm context metadata and bounds.
7. **Observability:** attach debugger on allowed tab, generate console/network/errors, fetch/get streams/buffers and page snapshot; verify redaction, caps, and detach indicator.
8. **Multi-tab/groups:** create/add/list/focus/remove groups or logical set; verify deterministic active target set and explicit tab targeting.
9. **Recording/replay:** record actions, stop/save, replay workflow, inspect trace/artifacts; confirm sensitive-field masking.
10. **Scheduling:** create/list/delete schedule, trigger run, verify completion/failure/approval-needed notification and missed/interrupted marking after restart/unavailable window.
11. **Downloads/uploads:** observe/list/wait downloads metadata; test `upload.file` with provided content payload (not arbitrary local path injection).
12. **Policy/security:** verify hard-block of `chrome://`/`about:`/internal URLs, allow/deny lists, mode matrix behavior, and localhost-only operation.

## Pass criteria
- No crashes/hangs; structured errors for unsupported/denied actions.
- No secrets/PII in persisted artifacts or logs by default.
- Graceful degradation on capability gaps (documented).

## Residual risk if not executed
- Browser-specific UI/runtime regressions (MV3 worker lifecycle, debugger UX, native tabGroups) may remain undetected. Automated Go/mock checks mitigate protocol/logic but not full extension runtime.
