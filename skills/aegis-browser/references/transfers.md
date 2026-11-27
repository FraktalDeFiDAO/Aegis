# Files and frame-aware browser control (extension 1.1)

Read live capabilities; the running extension must be reloaded after an update.
Use the resolved Aegis executable path below. Chromium native controls require
version 125+ and debugger permission; they display its attachment indicator.
Do not detach a user's other debugger/DevTools session to steal control.

## Upload a local file

```bash
aegis connect --connector upload --tab-id 123 --selector 'input[type=file]' --file /path/app-release.aab
aegis connect --connector upload --tab-id 123 --selector '#files' --file /path/one.pdf --file /path/two.pdf
```

Native selection passes explicit absolute paths to Chromium; large file bytes
are not base64-loaded into JSON. Browser and CLI must share the filesystem.
The CLI validates regular local files and checks the selected filenames/sizes.
Multiple files require a multiple-enabled input. `>>>` enters open shadow roots.

This returns `selected:true, serverConfirmed:false`, not proof of server acceptance.
Changing a file input can start a site's automatic upload. Observe its progress,
error/success UI and server receipt before claiming completion. Hash release
artifacts before selection and preserve the tested file during upload.

## Child frames or a browser without native selection

Use real frame IDs from `listFrames`. Explicit per-command `frameId` including 0
overrides the selected per-tab frame; `switchMain` resets selection to the top.

```bash
aegis connect --connector upload --tab-id 123 --frame-id 7 --selector '#file' --file /path/report.pdf
aegis connect --connector upload --tab-id 123 --selector '#file' --transport stream --file /path/report.pdf
```

Auto uses native selection for frame 0 and streamed selection for child frames.
Streaming is one file, maximum 256 MiB, in 256 KiB base64 chunks with ordered
acknowledgments and a final SHA-256 check. Inactive transfers expire after two
minutes. A failed transfer is canceled best-effort. Do not blindly replay it.
Native child-frame selection can work when the debugger exposes an unambiguous
frame; ambiguous/out-of-process frames may require streaming. Respect permission
denials rather than using another transport to evade them.

## Download and retrieve

```bash
aegis connect --connector download --tab-id 123 --url https://example.com/file --output /path/new-file.bin
aegis connect --connector download --tab-id 123 --id 42 --output /path/new-copy.bin
```

The first form starts a browser download; the second identifies a specific
existing one. Both poll its exact ID, require completion, check the browser's
reported size, and copy/hash the completed file to a new local destination.
Browser and CLI must share the filesystem. Existing destinations and symlinks
are preserved; interrupted downloads fail. Never approve a browser security
warning through this path. Distinguish browser completion from successful local
retrieval by requiring the CLI's byte count, SHA-256 and output file.

For page-triggered downloads, inspect `download.list` to identify the intended ID
before retrieval. `download.wait` reports a structured failure on interruption.

## Trusted interaction, dialogs, and capture

- `input.click {x,y,button?}` and `input.drag {from:{x,y},to:{x,y}}` use viewport
  coordinates and trusted browser events, including HTML5 drag data. Inspect a
  fresh screenshot and verify results; coordinate dispatch is not proof of a drop.
- `input.type {text,selector?}` inserts text in the focused/selected element.
  `input.key {key,code?,modifiers?}` sends keyboard events and native default actions.
- Browser-backed input may return `dialogPending:true`. Read `dialog.get`, then
  use `dialog.handle {accept:true|false,promptText?}` only for the intended native
  JavaScript alert/confirm/prompt. Other triggers require debugger attachment
  before the dialog opens. Never auto-accept dialogs merely to unblock execution.
- `screenshot.fullPage` returns one base64 PNG using document dimensions, capped
  at 100 megapixels. Save the envelope and decode/view `data.screenshot`.

These commands stay inside page/extension permissions. OS file pickers, browser
settings/security UI, arbitrary desktop applications and closed shadow roots
remain outside this layer. Never interpret broader capabilities as authorization
to bypass a denied action.

Raw commands support private `--params-file` and a bounded `--timeout 60s`.
The skill helper uses private temporary parameter files rather than putting
payloads in CLI arguments. Require result success and verify the actual outcome.
