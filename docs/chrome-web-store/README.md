# Chrome Web Store candidate 1.1.2

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

## Required before public submission

- Complete local approval enforcement: `approval.respond` is a placeholder,
  `policy.set` is callable by the bridge, and unattended/trusted scope behavior is
  broad. A controller must not be able to grant itself permission. Audit every
  dispatch path, recording, workflow, schedule, debugger and transfer command.
- Review `evaluate`/`evaluateAll` and debugger command execution with MV3 remote
  code rules. Do not certify “no remote code” until arbitrary code execution from
  the controller is removed or shown to comply with official policy.
- Review secret handling in stored workflows, recordings, console/network events,
  and screenshots. Key-name redaction does not guarantee that values and page
  contents contain no secrets. Publish truthful retention and deletion details.
- Minimize permissions, considering optional cookie/debugger/site access.
  `activeTab` is potentially redundant with broad host access; remove any
  permission without a demonstrated feature need. See permissions.md.
- Finalize the publisher identity, support contact, public privacy-policy URL,
  data-use disclosures, countries/audience, and account verification. Confirm
  whether any downstream AI services receive page data; their processing must be
  explained. The draft privacy policy is not a completed legal declaration.
- Provide at least one genuine, sanitized 1280x800 or 640x400 product screenshot.
  The existing 128px icon is packaged. Do not use private Play Console imagery.
- Provide installable native-host/CLI releases with checksums and support policy.
  Current automatic native-host installer supports Linux only. Windows/macOS
  installers and live Chrome testing remain outstanding. Do not advertise those
  platforms as automatically supported.
- Use the **store-assigned extension ID** to register native messaging. The
  unpacked development ID is not the public store ID. Pass the store ID through
  `install-native-host.py --extension-id ID` and test a clean installation.
- Review and merge the release PR after CI succeeds. Protect master with required
  CI/review in repository settings; branch protection is not installed by code.

## Build and verify

From repository root, with Go matching go.mod, Python 3, Node 24, and zip:

```sh
go test ./...
go vet ./...
go test -race ./cmd/aegis ./internal/connector/... ./internal/nativehost
node --test extension/tests/*.test.cjs
python3 scripts/test-install-native-host.py
python3 scripts/test-install-browser-skill.py
python3 skills/aegis-browser/scripts/test_browser.py
python3 skills/google-play-developer/scripts/test_plan_release.py
go build -o aegis ./cmd/aegis
node scripts/test-browser-connector.cjs ./aegis
bash scripts/package-extension.sh
python3 scripts/verify-extension-package.py dist/extension/aegis-connector-chrome.zip
```

The browser integration runner uses a separate Chromium profile and local fixture
server. It does not exercise a clean store-installed extension on every supported
browser/OS. `AEGIS_TEST_CHROMIUM` selects the test executable (see runner).

Package: `dist/extension/aegis-connector-chrome.zip`, with `manifest.json` at root.
Generated files stay out of Git; CI uploads the candidate ZIP as a workflow
artifact. Do not tag 1.1.2 as a public release while blockers remain.

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
Privacy URL: pending publisher confirmation and hosting.

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
