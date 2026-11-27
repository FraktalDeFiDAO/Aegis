# Connector release support

## Packaging

`python scripts/build-release.py` builds the CLI and native host for the current
OS/architecture, packages both extension variants, includes the native-host
installer, writes installation notes, and creates `SHA256SUMS`. Run it on each
supported release OS. The manual
`release-candidate` GitHub workflow performs this matrix without publishing a
release or tag.

## Installation and identity

Native messaging is per-user and restricted to the extension ID supplied to
`install-native-host.py`. Production installations must use the store-assigned
ID, not an unpacked development ID. Linux and macOS install a manifest under the
user's browser configuration. Windows registers the manifest under HKCU.
Reload the extension after registration. Clean store-installed verification is
still required before public availability.

## Verification and support policy

Verify every downloaded file against `SHA256SUMS` before installation. Release
candidates are not security-certified or store-approved. Do not publish a
candidate until its reviewed commit passes CI, approval/privacy review, and a
clean store installation. Support requests belong at
https://github.com/FraktalDeFiDAO/Aegis/issues with OS, browser, extension
version, and sanitized diagnostics. Never include bridge tokens, cookies, page
contents, session files, or private runtime state.
