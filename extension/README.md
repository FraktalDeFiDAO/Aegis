# Aegis Browser Extension

Bridges Aegis security scanner to your live browser session (Chrome/Brave/Chromium/Firefox).

## What it does

Instead of launching a separate headless Chromium, the Aegis Extension lets Aegis
control your **existing, authenticated browser** — with all your tabs, saved
passwords, extensions, and profile settings intact.

Protocol v1 (additive, backward-tolerant) supports versioned hello/capabilities handshake,
request correlation, structured errors/progress/cancel hooks, event sequencing/replay hints,
and capability-gated feature dispatch.

## Install

### Chrome / Brave / Chromium (Developer Mode)

1. Open `chrome://extensions` (or `brave://extensions`)
2. Enable **Developer mode** (toggle in top-right)
3. Click **Load unpacked**
4. Run `bash scripts/package-extension.sh`, then select `dist/extension/chrome`
5. The Aegis shield icon appears in your toolbar

### Firefox (Temporary Add-on)

1. Open `about:debugging#/runtime/this-firefox`
2. Click **Load Temporary Add-on**
3. After packaging, select `dist/extension/firefox/manifest.json`
4. The Aegis shield icon appears in your toolbar

## Usage

### Automatic bridge startup (Linux Chrome / Brave / Chromium)

The extension can launch the bridge through Chrome Native Messaging. Install the
small native host once; subsequent browser/extension startups launch it automatically:

```bash
go build -o dist/aegis-native-host ./cmd/aegis-native-host
python3 scripts/install-native-host.py --browser brave
```

Use `--browser chrome` or `--browser chromium` for those browsers. The installer
copies the host to `~/.local/lib/aegis/` and registers only the installed Aegis
extension ID. It discovers that ID from the browser's local configuration; if
needed, pass `--extension-id <ID from the extension manager>`. `--dry-run` shows
the destination paths without changing anything. No administrator privileges are needed.

After installation, reload Aegis in the extension manager to apply the
`nativeMessaging` permission. Keep host `127.0.0.1` and port Auto (9876). If a port
is occupied, the native host reports the selected fallback port automatically.
An existing Aegis bridge is reused; a bridge launched by the extension stops when
its native messaging port closes. Firefox and installations without the native
host can continue using a manually started bridge. Per-user registration supports Linux and macOS manifests and Windows HKCU registration; clean native verification is still required on each OS.
The native host returns a per-start authentication token through the registered
native-messaging port. No token entry is required for this automatic flow.

### Manual bridge startup

Start Aegis with the `--connector` flag:

```bash
# Keep the local bridge running for the extension (Auto uses port 9876)
aegis connect serve

# From another terminal, use that bridge to list browser tabs
aegis connect --connector --bridge-url 'ws://127.0.0.1:9876/ws?client=aegis' send --command listTabs

# Capture session from your live browser
aegis auth --connector --target-url https://target.example

# Crawl using your authenticated browser
aegis crawl --connector --config configs/config.yaml --dump ./dump

# Optional connector capture artifacts (best-effort)
aegis crawl --connector --capture-console --capture-network --capture-page-state --dump ./dump

# Run exploits in your real browser context
aegis exploit --connector --type session-hijack --target https://target.example

# Bridge diagnostics
aegis connect status
aegis connect info

# Read local policy (changes require the extension popup)
aegis connect --connector policy
aegis connect --connector audit --limit 100
aegis connect --connector audit-report --type policy --outcome denied --limit 200
aegis connect --connector send --command listTabs

# Workflows/schedules (connector required)
aegis workflow list --connector
aegis workflow record start --connector --name "my-flow"
aegis workflow record pause --connector
aegis workflow record stop --connector
aegis workflow run --connector --id <id>
aegis workflow run --connector --id <id> --trace-out trace.json --capture-screenshots
aegis workflow export --connector --id <id> --output wf.json
aegis workflow import --connector --file wf.json
aegis workflow delete --connector --id <id>
aegis schedule list --connector
aegis schedule create --connector --workflow-id <id> --interval-minutes 60
aegis schedule runs --connector --limit 50
aegis schedule delete --connector --id <id>

# Visual capture (connector required)
aegis connect --connector send --command screenshot.fullPage --params '{}' --output screenshot.json
```

For manual setup, `aegis connect serve` prints the runtime-state path. Copy the
`token` value from that owner-only file (normally
`~/.config/aegis/connector/runtime.json`, or `$XDG_CONFIG_HOME/aegis/connector/runtime.json`)
into the popup's **Manual Bridge Token** field, then connect. Do not paste the
token into URLs, shell arguments, issues, or logs. The CLI reads the same file
automatically when its bridge URL matches. Restarting the bridge rotates the
token; update the manual field after each restart. Controllers configured from
runtime discovery refresh URL and token automatically during reconnect. Only one
live bridge may own a discovery path; a second process fails instead of
overwriting credentials, and stale process locks are recovered conservatively.

Build a platform package with CLI, native host, extension ZIPs, installation
notes, and checksums using `python3 scripts/build-release.py`. The manual
`release-candidate` workflow runs this packaging on Linux, macOS, and Windows
without publishing a release.

If the bridge server is not already running, Aegis starts it automatically.
The extension connects to `ws://127.0.0.1:<port>/ws` (localhost only).

## How it works

```
Your Browser <--WebSocket--> Bridge Server (Go) <--WebSocket--> Aegis CLI
```

1. Aegis starts a local WebSocket bridge server on `127.0.0.1`
2. The extension and controller each authenticate with a token-bearing hello and exchange capabilities before registration
3. Aegis sends commands (navigate, click, extract, screenshot, observe, workflow/task ops, etc.)
4. The bridge relays commands to the extension with correlation/timeout/cancel handling
5. The extension executes operations (capability/policy gated) and returns results/events

## Features (best-effort, capability-gated)

### Stable nested-control targeting (1.1.1)

Element queries now return `ariaLabel`, `accessibleName`, role, disabled/checked
state and unique ARIA-based selectors. This exposes native buttons inside nested
Angular components, including Google Play's repeated declaration buttons.
CSS DOM interactions accept `strict:true` to require exactly one visible,
enabled target. Read `extension.info` for running version/feature flags; older
versions ignore unknown strict parameters. Always verify the resulting form
before entering or saving answers. Workflow replay also checks each step's policy
and reports a failed step as a failed command.

### Browser-control upgrade (1.1)

Chrome/Brave/Chromium 125+ can select local file paths through the debugger API,
without loading large files into base64 commands. Browser and CLI must share
the filesystem. Native operations display the browser's debugger indicator;
competing DevTools/debugger sessions may prevent attachment. Policy gates apply.

```bash
aegis connect --connector upload --tab-id 123 --selector 'input[type=file]' --file ./app-release.aab
# Multiple-enabled input; repeat --file.
aegis connect --connector upload --tab-id 123 --selector '#files' --file ./one.pdf --file ./two.pdf
# Child frame: one file, maximum 256 MiB, chunked and SHA-256 verified.
aegis connect --connector upload --tab-id 123 --frame-id 7 --selector '#file' --file ./document.pdf
# Start/wait/retrieve/hash, or retrieve a known completed download ID.
aegis connect --connector download --tab-id 123 --url https://example.com/file --output ./new-file.bin
aegis connect --connector download --tab-id 123 --id 42 --output ./new-copy.bin
```

File selection reports `selected:true, serverConfirmed:false`; verify the site's
upload result separately. Page change handlers may start uploading automatically.
`--transport stream` forces chunked transfer; `--transport native` requests path
selection. Streaming accepts one file up to 256 MiB, uses 256 KiB chunks and a
final SHA-256 check, and expires after two idle minutes. Native selection avoids
that memory limit. Download retrieval preserves existing files/symlinks and fails
on interruption or size mismatch.

`listFrames` returns browser frame IDs. `switchFrame {frameId}` selects a per-tab
frame; `switchMain` selects 0. Per-command `frameId` (including 0) overrides it.
Content messages and injection target exactly one frame. Top-level navigation
resets selection. `>>>` enters open shadow roots in CSS queries/interactions.

Raw commands added:

- `input.click {x,y,button?}`, `input.drag {from:{x,y},to:{x,y}}`: trusted viewport
  mouse events, including HTML5 drag/drop data.
- `input.type {text,selector?}`, `input.key {key,code?,modifiers?}`: browser text and
  keyboard input; modifiers alt/ctrl/meta/shift.
- `dialog.get`, `dialog.handle {accept:true|false,promptText?}`: observed native
  JavaScript alert/confirm/prompt. Input can return `dialogPending:true`; handle
  explicitly. For other triggers, attach debugger before opening the dialog.
- `screenshot.fullPage`: one base64 PNG of actual document dimensions, up to 100 MP,
  replacing the previous unstitched tiles.
- `download.start {url,filename?}`, `download.list`, `download.wait`: IDs and state.

`connect send --params-file` keeps JSON payloads out of process arguments;
`--timeout 60s` controls the deadline. Saved command failures return nonzero.

These are page/extension controls, not arbitrary desktop automation. Native OS
file pickers, browser settings/security UI, hardware credentials, and closed
shadow roots remain outside this layer.

Validation: `node scripts/test-browser-connector.cjs ./aegis` launches a separate
headless Chromium profile against local fixtures and an isolated authenticated bridge.
It verifies wrong-token rejection, extension/controller authentication,
controller self-grant/evaluation rejection, real popup approval and denial,
file/server hashes, downloads, cross-origin frames, trusted input/native JS
dialogs/HTML5 dragging, full-page PNG dimensions and workflow policy denials.
The user's browser profile and real accounts are not used.

- **Core:** navigation/tabs/elements/interactions/waits/dedicated page reads/cookies/storage/screenshot, session capture. Arbitrary controller evaluation is unavailable.
- **Observability (Phase 1):** debugger attach hooks and buffered console/network/page-state snapshot commands (`debug.*`, `page.snapshot`) with bounded/redacted payloads where supported; graceful degradation when unavailable.
- **Multi-tab/targeting (Phase 2):** native tab groups on supported Chromium; logical target-set fallback on Firefox/unsupported browsers; persisted active target set (best-effort).
- **Workflows/scheduling (Phase 3–4):** local recording/workflow/schedule storage and replay handlers, step capture during recording, run history hooks, CLI list/run/export/import/delete; alarms/notifications where permitted; missed/interrupted handling best-effort under MV3 constraints.
- **Downloads/uploads/visuals (Phase 5):** download list/wait (permission-gated), file-input upload helper for provided data payloads (browser security limits apply), screenshot/evidence capture helpers.
- **Local policy/approvals (Phase 6):** deterministic local modes `manual-approve`, `auto-with-prompts`, `unattended` (trusted scope), allow/deny hooks, gated sensitive actions, popup policy controls, bounded local audit log (`audit.list`). **No prompt-injection/model safety classifier parity.**

## Approvals, trusted scopes, and retained data

`manual-approve` and `auto-with-prompts` create one-time popup approvals for
sensitive work. Approval waits up to 20 seconds and cancels on disconnect; the
controller cannot resolve it. `unattended` is not a wildcard bypass: every
sensitive command must match a trusted HTTP(S) origin, optionally restricted to
a path such as `https://example.com/app`. `*` and lookalike origins do not match.
Policy changes and approval decisions are accepted only from extension UI pages.
Workflow, scheduled, and capture steps use the same approval module.

Cookie and local/session-storage values are omitted or replaced unless the
caller explicitly sets `includeValues:true`. Workflows, recordings, runs, and
audit entries are bounded and redacted for common secret patterns. The popup's
Clear Stored Task Data action deletes workflows, recordings, schedules, run and
audit history, target state, and schedule alarms. It does not delete downloads,
bridge configuration, controller output, or downstream service data. Redaction
is not guaranteed to find every secret; review captures before sharing them.

## Security

- Bridge server binds to **127.0.0.1 only** — no network exposure
- Controller and extension must authenticate before registration or commands; failed authentication cannot replace a session
- Per-start 256-bit tokens are delivered through native messaging or an owner-only (`0600`) discovery file, never in WebSocket URLs
- A PID-backed discovery lock prevents concurrent credential overwrites; reconnect refreshes rotated URL/token state
- `/info` requires bearer authentication; `/health` exposes only non-sensitive discovery metadata
- Arbitrary controller JavaScript and remote policy/approval changes are disabled
- Sensitive commands require exact trusted scopes or one-time popup approval; pending work cancels on disconnect
- Cookie/storage values require explicit inclusion, records are bounded/redacted, and task data can be cleared in the popup
- No secrets/PII logging by default; sensitive captures redacted/bounded where implemented
- Sensitive actions can be gated by local policy mode; hard blocks for internal/unsupported pages
- Commands are accepted only from authenticated localhost WebSocket connections

## Limitations

- Chrome/Brave/Chromium (MV3) primary; Firefox (MV2) best-effort with documented capability gaps (tabGroups/debugger/scheduling/permissions behavior may differ)
- Some operations are unavailable on internal pages (`chrome://`, `about:`, etc.)
- Native local-path selection requires Chromium debugger support and a shared filesystem; streamed uploads are one file up to 256 MiB
- Scheduled/background behavior depends on browser/extension/bridge availability (MV3 service-worker lifecycle)
- Isolated Chromium transfer/control tests are automated; real-site flows, Firefox and native browser/OS UI still need manual validation

## Troubleshooting

### Extension shows "Disconnected"

- Ensure Aegis is running with `--connector` or bridge is started
- Check that the bridge server started (Aegis prints the address) and `aegis connect status`
- Click the extension icon and verify the host/port match the bridge address
- Reload the extension after upgrading the bridge/native host. Old extensions without token support cannot authenticate.
- For manual setup, copy the current token from the private runtime file; bridge restarts rotate it.

### Commands time out

- The page may be on restricted/internal URLs (extensions can't access these)
- Navigate to a regular HTTP/HTTPS page and try again
- Check the browser console/service worker logs for errors

### Capability/policy denied

- Command may be unsupported in this browser/manifest mode or blocked by local policy
- Adjust policy mode/trusted scopes or resolve pending approvals in the extension popup; `aegis connect --connector policy` is read-only

## Supported Commands (core + additive)

| Category | Commands |
|----------|----------|
| Navigation | navigate, goBack, goForward, reload, getCurrentUrl, getTitle |
| Tabs | listTabs, newTab, closeTab, switchTab, getTabInfo |
| Element | querySelector, querySelectorAll, getElementText, getElementAttribute, getElementHtml |
| Interaction | click, doubleClick, rightClick, hover, type, fill, clear, press, select, check, scroll |
| Wait | waitForSelector, waitForNavigation, waitForLoad, waitForIdle, waitForTimeout |
| Dedicated page/element reads and guarded edits | page.html, page.text, element.visible/property/setAttribute/remove, getElementBoundingBox |
| Screenshot | screenshot, screenshotElement, captureVisibleTab |
| Cookies/Storage | getCookies, setCookie, deleteCookie, clearCookies, local/session storage ops |
| Frames/Extract | switchFrame, switchMain, listFrames, extractData |
| Observability | debug.attach/detach/getConsole/getNetwork/getPageState, page.snapshot |
| Groups/Targeting | createTabGroup, addTabToGroup, removeTabFromGroup, listTabGroups, focusTabGroup, target.get/set |
| Workflows/Scheduling | record.start/stop/pause, workflow.list/get/save/delete/run, schedule.create/list/delete/runs |
| Files | download.list/wait, upload.file |
| Policy/Audit | policy.get (read-only), audit.list/report; popup-only policy changes and approvals |

## Browser Compatibility

| Browser | Status |
|---------|--------|
| Chrome 88+ | Primary (MV3) |
| Brave 1.28+ | Supported (MV3) |
| Chromium 88+ | Supported (MV3) |
| Firefox 109+ | Best-effort (MV2, capability-gated gaps) |
| Edge 88+ | Likely compatible (untested) |
