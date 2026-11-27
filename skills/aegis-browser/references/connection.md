# Connection recovery

Examples use `aegis` as shorthand for the resolved executable path.

1. `aegis connect status`: require reachable health and `extensionConnected=true`.
   A missing runtime-state file alone is not a failure: the default bridge on
   `127.0.0.1:9876` can still work.
2. `aegis connect info`: inspect capabilities only when needed; it also includes
   recent tab events, so avoid dumping unrelated history.
3. `socket: operation not permitted` is a sandbox restriction. Request supported
   escalation for the same scoped command; do not misdiagnose the extension or
   start extra bridges to evade the execution boundary.

## Lifecycle and discovery

The extension connects to `com.aegis.bridge` through native messaging. The host
starts a loopback WebSocket bridge or reuses one. Auto initially means 9876;
the host reports a fallback port when occupied. The native host stops a bridge
it owns when its port closes; externally started bridges survive.

The CLI discovers a loopback address in
`${XDG_CONFIG_HOME:-~/.config}/aegis/connector/runtime.json`, otherwise tries 9876.
Never use an off-machine address from runtime state. For an explicitly identified
alternate local bridge, pass the helper
`--bridge-url 'ws://127.0.0.1:PORT/ws?client=aegis'`.

For a loaded but disconnected extension, check host `127.0.0.1`, port Auto, and
native-host registration. An updated extension needs a reload to apply code and
permissions. When browser tools block internal extension-manager URLs, leave
that reload to the user; do not use another transport to circumvent the block.

## Setup/repair only when needed and authorized

From the Aegis checkout:

```bash
go build -o dist/aegis-native-host ./cmd/aegis-native-host
python3 scripts/install-native-host.py --browser brave --dry-run
python3 scripts/install-native-host.py --browser brave
```

The installer supports Linux `brave`, `chrome`, and `chromium`. It copies to
`~/.local/lib/aegis/`, registers in the browser's per-user NativeMessagingHosts
directory, and allows only the installed Aegis extension ID. If discovery fails,
supply `--extension-id` from the extension manager. Apply environment approvals
for writes outside the workspace. Reload package `dist/extension/chrome` to apply
the `nativeMessaging` permission. Routine browser tasks do not imply permission
to reinstall software or rewrite browser configuration.

For manual operation, keep `aegis connect serve` running in a persistent terminal
and connect to its printed loopback address. Go may be outside PATH
(`/home/admministrator/go/bin/go` here). Older binaries may have `--connector`
but lack `connect`; inspect tooling and rebuild only within authorized scope.

After recovery, require healthy bridge, connected extension, then a successful
read explicitly targeting the intended tab. Health alone is insufficient.
