# Permission review worksheet

These are implementation justifications, not a completed least-privilege review.
Compare against the final packaged manifest before submitting.

| Permission | Implemented use | Review required |
| --- | --- | --- |
| nativeMessaging | Launch installed local companion | Document separate installation and supported OS |
| webNavigation | Resolve frame IDs and reset frame routing on navigation | Verify scope needed |
| activeTab | Active tab access | Assess redundancy with host access |
| tabs | Find task tabs and read URL/title | Explain browsing metadata access |
| tabGroups | Keep task tabs in visible workspace | Chrome/Chromium only; logical Firefox fallback |
| cookies | Explicit cookie get/set/delete commands | Consider optional permission and sensitive-data controls |
| storage | Configuration, policy, workspace, workflows, audit/run history | Document retention/deletion and recorded values |
| scripting | Inject content handler into supported tabs | Limit to task sites where feasible |
| debugger | Trusted input, native upload, full screenshot, diagnostics | Consider optional permission; disclose powerful access |
| alarms | Reconnect keepalive and scheduled workflows | Preserve per-action authorization |
| notifications | Policy and schedule messages | Verify necessary vs optional |
| downloads | Start, track and locate downloads | Explain local file metadata and companion copying |
| <all_urls> | Operate user-selected sites and child frames | Consider optional host grants; justify broad access if retained |

Page contents, URLs/titles, typed/recorded values, cookies, screenshot pixels,
download metadata and file bytes can reach the local controller. Connected AI
agents may forward those data to third parties under their configuration.
Do not check “no data collected” solely because the extension uses loopback.
