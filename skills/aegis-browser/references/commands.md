# Commands

Send through `scripts/browser.py <command> --params '<JSON object>'`.
These are Aegis commands, not Playwright locators or CDP methods. Advertised
capabilities can exceed implementation coverage; verify each result.

All page commands take `tabId`. Selectors use `document.querySelector` CSS;
role/text pseudo-selectors from other tools are unsupported. `>>>` enters open
shadow roots. All page commands accept `frameId`; use real IDs from `listFrames`.

Extension 1.1.1 adds `ariaLabel`, `accessibleName`, role, disabled/checked state
and unique ARIA-based selectors to element metadata. Native buttons inside
Angular/custom wrappers can be targeted directly by those attributes.
Use `extension.info` to read the running version and feature flags; older
extensions do not advertise this command and must be treated as lacking strict
target enforcement until reloaded/verified.
Use `strict:true` for CSS DOM interactions when selecting a declaration/form
control: it requires one visible, enabled match. Older versions ignore this
parameter, so verify the running version and inspect uniqueness independently.

| Command | Additional parameters | Response / behavior |
|---|---|---|
| `extension.info` | none | Running extension version and implemented strict-target/metadata/workflow-policy features |
| `listTabs` | none | `data.tabs[]`: `id`, `url`, `title`, `active`, `windowId` |
| `getTabInfo` | none | Tab metadata for `tabId` |
| `getCurrentUrl`, `getTitle` | none | `data.url` or `data.title` |
| `listFrames` | none | Real browser frame IDs, URLs, parent IDs, selected frame |
| `switchFrame`, `switchMain` | `frameId` for switchFrame | Selects frame; per-command `frameId:0` overrides selection |
| `newTab` | `url` (explicit HTTP/S), `active` (default true) | `data.tabId`; updates persisted target when active; initial URL may be empty |
| `switchTab` | `tabId` | Activates tab and updates persisted target; not proof of OS foreground window |
| `closeTab` | `tabId` | Closes that tab; keep task scope explicit |
| `navigate` | `url` | Changes location via content script; verify after load |
| `goBack`, `goForward`, `reload` | none | History/reload acknowledgment, then verify |
| `querySelector` | `selector` | `data.found` plus metadata |
| `querySelectorAll` | `selector` | `data.count`, `data.elements[]` with reusable selectors, text, bounding boxes |
| `getElementText` | `selector` | `data.text`; a missing element may return empty text |
| `getElementAttribute` | `selector`, `attribute` | `data.value` or null |
| `click` | `selector` | Interaction acknowledgment; inspect result |
| `input.click` | viewport `x`, `y`, optional `button` | Trusted Chromium mouse input |
| `input.drag` | `from:{x,y}`, `to:{x,y}` | Trusted pointer/HTML5 drag events; verify drop outcome |
| `input.type` | `text`, optional `selector` | Browser text insertion into focused/selected element |
| `input.key` | `key`, optional `code`, `modifiers` | Browser keyboard events; modifiers alt/ctrl/meta/shift |
| `dialog.get` | none | Observed native JavaScript dialog, if any |
| `dialog.handle` | explicit `accept`, optional `promptText` | Handles observed alert/confirm/prompt; verify page afterward |
| `fill` | `selector`, `value` | Replaces input value, dispatches events; verify value afterward |
| `type` | `selector`, `value` | Appends; use `fill` to replace |
| `clear` | `selector` | Clears input |
| `select` | `selector`, `value` | Sets select value |
| `press` | `selector`, `key`, optional `modifiers` array | Synthetic keyboard events; native/default browser actions are not guaranteed |
| `scroll` | `x`, `y` | Scrolls page |
| `scrollIntoView` | `selector` | Reveals element |
| `waitForSelector` | `selector`, `timeout` in ms | Existence, not visibility/enabled state |
| `waitForLoad` | none | DOM ready/interactive check |
| `screenshot`, `captureVisibleTab` | none | `data.screenshot`: base64 PNG of active tab in target's window |
| `screenshot.fullPage` | optional `fullPage:false` | Chromium debugger-backed single PNG up to 100 MP |
| `page.snapshot` | `maxChars`, `includeSensitive` (default false) | Best-effort redacted HTML/headings/forms; policy may deny |
| `policy.get` | none | Reads policy without changing it |

## Navigation and forms

Inspect the target before interacting. Use returned selectors rather than
inventing IDs, and requery after DOM changes:

```bash
python3 <skill-dir>/scripts/browser.py querySelectorAll --params '{"tabId":123,"selector":"a"}'
# Choose a returned selector for the requested destination.
python3 <skill-dir>/scripts/browser.py click --params '{"tabId":123,"selector":"a#observed-id"}'
python3 <skill-dir>/scripts/browser.py getCurrentUrl --params '{"tabId":123}'
python3 <skill-dir>/scripts/browser.py getTitle --params '{"tabId":123}'
```

Use bounded condition checks for asynchronous updates. If navigation replaces
the document and causes a content-script error, inspect tab metadata before
retrying the navigation. Verify submitted work via the actual confirmation/state,
not the `clicked`/`filled` acknowledgment.

## Screenshots

Activate the intended tab with `switchTab`, then save the response:

```bash
python3 <skill-dir>/scripts/browser.py screenshot --params '{"tabId":123}' --output /tmp/aegis-capture.json
```

Decode `data.screenshot` as base64 to PNG and visually inspect it before claiming
visual verification. `captureVisibleTab` captures the active tab in the window
even when another `tabId` is provided; account for user focus changes. `screenshot.fullPage` uses debugger capture with document dimensions
and returns a single PNG; it does not require activating another tab.

## Results and source of truth

Success: `{"type":"result","success":true,"data":{...}}`.
Failure: `{"success":false,"error":"...","err":{"code":"...","message":"..."}}`.
No result file, invalid JSON, or missing/non-true `success` fails verification.
For `unsupported`, choose a supported narrow command or report the limitation.
For timeout/disconnect after a write, reconcile before replaying. Stub `ok`
responses are not completed work.

Before unfamiliar commands, read the relevant source in the Aegis checkout:

- `extension/background.js`: dispatch, `evaluatePolicy`, tab/screenshot handlers.
- `extension/content.js`: selectors, serialization, interaction/navigation handlers.
- `cmd/aegis/connect.go`: CLI flags and response serialization.
- `internal/connector/bridge/protocol.go`: envelopes and error types.
