# Build and signing

## Reuse the project's release procedure

Inspect native Android/Flutter/React Native/other project structure, release CI,
flavors, build type, applicationId overrides, and tests. Run the documented
release build and appropriate tests. Do not replace the signing configuration
or bump dependencies merely to publish. A Play release generally needs an AAB;
use APK only where the app's supported legacy workflow explicitly requires it.

Check the built artifact, not just source configuration:

- Exact package, version code/name, SDK levels, release variant and debuggable flag.
- Version-code uniqueness and ordering against uploaded artifacts/current tracks.
  A build rejected after upload may still have consumed a version code; inspect
  Play's artifact state before reusing or incrementing it.
- Signing certificate matches the app's registered upload key; record only public
  certificate fingerprints and secure key references.
- Artifact SHA-256/size, R8 mapping/native symbols where relevant, release notes,
  and the tests performed on that actual build.
- Current target SDK, SDK policy and native compatibility requirements, including
  16 KB page-size rules when applicable. Verify the current policy and app scope;
  do not hard-code annual deadlines or assume all dependencies comply.

## Signing distinctions

Play App Signing uses an app signing key for distributed APKs and an upload key
to authenticate uploads. They may differ; API integrations often need the Play
app-signing certificate rather than the local upload certificate. Upload-key
reset and app-signing-key upgrade are different workflows. Never generate a
replacement identity or reset a key without explicit scope and verified recovery
requirements. Preserve backups securely; do not expose keystore passwords.

For AABs, use Gradle/Android Studio or `jarsigner`; `apksigner` is for APKs and
cannot sign an app bundle. A ZIP ending in `.aab` is not proof of validity or
correct signing. Verify the JAR signature and inspect certificate fingerprints
using the existing JDK/project tools. Android's self-signed signing certificates
are expected; distinguish certificate trust-chain warnings from an invalid or
absent artifact signature. A valid signature still needs a match to Play's
registered key. Do not put password literals on command lines.

Sources: [Play App Signing](https://support.google.com/googleplay/android-developer/answer/9842756),
[bundletool](https://developer.android.com/tools/bundletool),
[versioning](https://developer.android.com/studio/publish/versioning),
[current target API policy](https://support.google.com/googleplay/android-developer/answer/11926878),
[16 KB compatibility](https://developer.android.com/guide/practices/page-sizes).

## Local release-plan helper

`scripts/plan_release.py` invokes trusted local bundletool using argument arrays:
`validate --bundle=...`, then `dump manifest --bundle=... --module=base`.
Supply either a trusted bundletool JAR (executed with Java) or its launcher path.
Obtain missing tools only through the project's approved source/procedure.

Require an expected `--package` and explicit `--track`; the helper reads version
metadata from the actual manifest. It rejects debuggable bundles, invalid version
codes, package mismatches, and invalid rollout/status combinations. Its default
status is `draft`. `--status inProgress --fraction 0.05` means a proposed 5%
rollout, never an executed one. Validate track support before applying that plan.

Optional `--notes-file` contains a JSON list of localized notes:
`[{"language":"en-US","text":"Release notes"}]`.
Use Play's current locale/length requirements, avoid unsupported claims, and
review exactly the text that will be submitted.

The output's `proposedRelease` is a candidate release, not a complete track
replacement. Inspect/merge current releases, countries, and rollout state before
API writes. The helper does not check signing, the remote version inventory,
policy, account eligibility, device behavior, or authorization, and never uploads.
