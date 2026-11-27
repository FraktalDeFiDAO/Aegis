# Aegis Browser Connector privacy policy

Effective date: 2026-11-27

Publisher: FraktalDeFiDAO (repository owner; legal entity name and store account
verification must be confirmed before submission).

Support and privacy requests: https://github.com/FraktalDeFiDAO/Aegis/issues

Public policy URL after repository publication:
https://github.com/FraktalDeFiDAO/Aegis/blob/master/docs/chrome-web-store/privacy-policy.md

## Purpose and data processed

Aegis Browser Connector links a separately installed local Aegis controller to a
browser for explicitly authorized automation. Depending on the requested action,
it can process page content, URLs and titles, form values, cookies, browser
storage, screenshots, console/network diagnostics, frame information, download
metadata, and selected file content. Actions may use existing authenticated
website sessions and can affect signed-in accounts.

Controller and extension connections require a per-start token. Arbitrary
controller-provided JavaScript and controller policy changes are disabled.
Sensitive work requires either a matching locally configured trusted scope or a
one-time approval in the extension popup. A controller cannot approve its own
work.

## Local transmission and downstream services

Commands and results travel over an authenticated loopback WebSocket to the local
controller. The extension contains no vendor analytics or advertising endpoint.
A connected controller or AI agent may transmit processed data to its configured
services. Those services and their retention practices are outside this
extension's control and must be reviewed in the controller configuration. No
claim is made that page, authentication, financial, health, or other personal
data never leaves the local machine when such a controller is configured.

The publisher does not sell browser data or use it for advertising.

## Storage and retention

- Bridge configuration, manually entered bridge tokens, policy, trusted scopes,
  workflows, schedules, target state, and bounded run/audit histories use
  extension-local storage. Removing the extension removes that storage.
- Workflows are bounded to 200 saved items and 100 recording-derived items, run
  history to 200 entries, and audit history to 500 entries. Schedules and trusted
  scopes remain until changed or deleted. Pending approvals and event/debugger
  queues are memory-only and bounded; approvals expire after 20 seconds and are
  canceled on disconnect.
- The popup's Clear Stored Task Data action deletes workflows, recordings,
  schedules, run history, audit history, target state, and schedule alarms. It
  does not delete bridge configuration, downloads, or controller output.
- The bridge discovery token is generated per start, stored in an owner-only
  runtime file, rotated on restart, and removed on clean shutdown. Native-host
  tokens in the extension remain in memory. A same-user process able to read the
  runtime file can authenticate; this is not a defense against same-user malware.
- Downloads, CLI output, native-host registration/binaries, controller logs, and
  data sent to another service persist independently. Delete them through their
  respective locations or service controls. Extension removal does not delete
  these items.

Redaction covers known sensitive field names and common secret patterns, but no
redaction system is guaranteed to identify every secret. Screenshots, page
contents, recorded values, and downstream captures may contain confidential
information. Review scope before capture and do not record confidential
workflows without explicit authorization.

## Permissions

The extension requests only permissions used by its documented features:
native messaging for the local companion, tabs/webNavigation for task and frame
routing, tab groups for the visible workspace, cookies/storage for authorized
session operations and local state, scripting for the fixed content handler,
debugger for trusted input/native file selection/full-page capture/diagnostics,
alarms/notifications for connection and approval/schedule notices, downloads for
authorized file operations, and host access for user-selected sites and frames.
`activeTab` is not requested. Arbitrary controller evaluation is not available.

## User choices and deletion

Users can disconnect, deny each approval, remove trusted scopes, clear stored
task data, remove the extension, unregister the native host, and delete local
artifacts. Use the support link for privacy questions. Do not submit tokens,
cookies, page contents, screenshots, runtime files, or other secrets with a
support request.

## Policy updates

Material updates will be published at the public policy URL with a revised
effective date. Store listing details, publisher legal identity, account
verification, and any jurisdiction-specific disclosures must be confirmed before
submission.
