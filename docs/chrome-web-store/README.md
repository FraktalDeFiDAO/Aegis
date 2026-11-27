# Chrome Web Store candidate 1.2.0

Current local verification: `docs/chrome-web-store/verification-2026-11-27.md`.

Status: **not ready for public submission**. ZIP preparation and automated
verification do not establish Web Store policy compliance or approval.

## Authentication status

The bridge now requires a token-bearing hello as the first message from both the
controller and extension, before registering either connection or accepting
commands. A fresh 256-bit token is generated on each bridge start. The native
host returns it only through the registered extension's native-messaging port;
the CLI reads it from the owner-only runtime state file. Failed authentication
cannot replace an authenticated connection, and restarting the bridge rotates
the credential. See verification-2026-11-26.md for the executed tests.

## Completed security and release hardening

- Real one-time popup approvals cover direct commands, workflows, schedules, and
  captures. Controllers cannot call `policy.set` or `approval.respond`; unattended
  work requires exact trusted origins/paths. Wildcards are rejected.
- Arbitrary `evaluate`/`evaluateAll` was removed. Basic operations use dedicated
  commands; debugger helpers use fixed local expressions rather than controller
  script. `activeTab` was removed and every remaining permission is justified.
- Cookie/browser-storage values require explicit inclusion. Persisted records use
  sensitive-key/common-token redaction and bounded retention, and the popup has a
  task-data deletion action. `/info` requires bearer authentication.
- Discovery has a live-process lock, stale recovery, mandatory owner-only writes,
  and reconnect refresh for rotated URL/token state.
- `assets/screenshot-01.png` is a genuine isolated 1280x800 approval screenshot.
- Linux/macOS/Windows native-host registration is implemented and tested at the
  path/dry-run level. `scripts/build-release.py` produces platform packages and
  SHA256SUMS; the manual matrix workflow packages without publishing.
- CI now includes full-repo race tests and the isolated Chromium approval suite.

## Feature/spec acceptance

The [plan conformance matrix](../plans/2026-11-27-plan-conformance.md) records
remaining connector/core gaps and quality gates. Packaging/security verification
does not establish full plan completion.

## Required before public submission

- Confirm the publisher's legal identity, store account verification, support
  contact, countries/audience, and any jurisdiction-specific declarations. The
  privacy policy and reserved GitHub URL are prepared, but legal review and the
  downstream AI configuration disclosure remain publisher responsibilities.
- Use the **store-assigned extension ID** to register native messaging. Run a
  clean store-installed test with the final companion and verify popup approval,
  denial, trusted scopes, and deletion. Live Windows/macOS behavior remains
  unverified; do not advertise it as manually verified until tested.
- Push the final reviewed commit, require green CI including Chromium, run the
  manual release-candidate matrix, review/merge the release PR, and enable master
  branch protection. These external actions cannot be completed by local code.

## Build and verify

From repository root, with Go matching go.mod, Python 3, Node 24, and zip:

```sh
go test ./...
go vet ./...
go test -race ./...
node --test extension/tests/*.test.cjs
python3 scripts/test-install-native-host.py
python3 scripts/test-install-browser-skill.py
python3 skills/aegis-browser/scripts/test_browser.py
python3 skills/google-play-developer/scripts/test_plan_release.py
go build -o aegis ./cmd/aegis
node scripts/test-browser-connector.cjs ./aegis
bash scripts/package-extension.sh
python3 scripts/verify-extension-package.py dist/extension/aegis-connector-chrome.zip
python3 scripts/build-release.py
node scripts/capture-store-screenshot.cjs ./aegis
```

The browser integration runner uses a separate Chromium profile and local fixture
server. It does not exercise a clean store-installed extension on every supported
browser/OS. `AEGIS_TEST_CHROMIUM` selects the test executable (see runner).

Package: `dist/extension/aegis-connector-chrome.zip`, with `manifest.json` at root.
Generated files stay out of Git; CI uploads the candidate ZIP as a workflow
artifact. Do not tag 1.2.0 as a public release while blockers remain.

## Listing draft

Name: Aegis Browser Connector

Single purpose: Connect explicitly authorized local Aegis automation to the user's
browser workspace to inspect pages and perform browser tasks.

Description:

Aegis Browser Connector connects the Aegis command-line companion to your browser.
Keep task tabs together in a visible Aegis group, inspect page controls, complete
forms, and manage authorized uploads and downloads. Frame and open shadow-root
support help automate modern web applications.

A separately installed local companion is required; the Web Store extension alone
does not install a native executable. Automatic companion setup currently supports
Linux Chrome, Brave, and Chromium. Review the setup documentation before installing.
Browser actions can affect signed-in accounts. Review task scope and local access
settings before connecting automation. This extension does not control the operating
system desktop or browser security pages.

Category candidate: Developer Tools. Language: English.
Support/repository: https://github.com/FraktalDeFiDAO/Aegis
Privacy URL: https://github.com/FraktalDeFiDAO/Aegis/blob/master/docs/chrome-web-store/privacy-policy.md (available after merge).

## Reviewer test instructions draft

1. Install the candidate extension in a clean Linux Chrome profile. Record its ID.
2. Obtain the matching companion from the reviewed release commit; build the CLI
   and `dist/aegis-native-host` using the documented Go version.
3. Register the native host using `python3 scripts/install-native-host.py
   --browser chrome --extension-id STORE_ID`. Reload the extension manually.
4. Verify bridge connected in the popup and with `aegis connect status`. Leave
   policy gates intact. A permission denial must remain a denial.
5. Run the isolated local fixture integration suite above for interactions,
   transfers, frame routing, grouping, and policy failures. No Google Play
   account or other private credentials are needed for this suite.
6. Repeat using the actual store-installed extension and finalized authenticated
   companion installation; the fixture suite alone is insufficient for review.

References checked 2026-11-26:
- https://developer.chrome.com/docs/webstore/publish
- https://developer.chrome.com/docs/webstore/cws-dashboard-listing
- https://developer.chrome.com/docs/webstore/cws-dashboard-privacy
- https://developer.chrome.com/docs/webstore/cws-dashboard-test-instructions
