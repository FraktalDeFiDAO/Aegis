# Permission review

Reviewed against the 1.2.0 packaged manifests. `activeTab` was removed as
redundant. Remaining permissions have a demonstrated fixed-feature use; broad
access does not permit arbitrary controller JavaScript or self-approval.

| Permission | Required use | Disposition |
| --- | --- | --- |
| nativeMessaging | Start/reuse the registered local companion | Required for automatic setup |
| webNavigation | Resolve frame IDs and reset frame routing | Required for explicit frame targeting |
| tabs | Find task tabs and read task URL/title metadata | Required for controller routing |
| tabGroups | Keep task tabs in the visible Aegis workspace | Chromium feature; Firefox has no native equivalent |
| cookies | Explicit authorized cookie/session operations | Required; values require explicit inclusion and policy authorization |
| storage | Configuration, policy, trusted scopes, workflows, schedules, bounded history | Required; deletion control is in the popup |
| scripting | Inject the fixed content handler when needed | Required; no controller-provided script is injected |
| debugger | Trusted input, native file selection, full-page capture, fixed diagnostics | Required for those opt-in features; fixed local expressions only |
| alarms | Connection keepalive and schedules | Required; sensitive scheduled steps use the same approval module |
| notifications | Approval and schedule messages | Required for local decision visibility |
| downloads | Start, track, and retrieve authorized downloads | Required for download commands |
| `<all_urls>` | Operate user-selected sites and child frames | Required for arbitrary authorized targets; policy scopes restrict unattended work |

Page contents, URLs/titles, typed/recorded values, cookies, screenshot pixels,
download metadata, and file bytes can reach the authenticated local controller.
Connected AI agents may forward data to third parties under their configuration.
The privacy policy must not claim “no data collected” merely because the first
hop is loopback.
