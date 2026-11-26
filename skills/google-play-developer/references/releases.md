# Upload, review, and release

## Choose the execution route

Prefer existing maintained project CI, fastlane lanes, or Gradle publishing
tasks after reading their configuration and final side effects. A task named
`upload` can also commit or distribute. Inspect track, release status, review
flags, credentials, artifact glob, and metadata behavior before running it.
Do not install/configure a new release framework when a scoped API call or the
console is sufficient. For console work, verify the account/package, form fields,
pending changes, and resulting state after each logical action.

## Prepare the transaction

Read current artifacts, tracks, release statuses, rollout/country settings,
review state, and Publishing overview. Capture the release being changed and
its version codes. Package names and exact track IDs must match the request;
never assume a custom closed track is named `alpha` or `beta`.

Prepare a release record from the real artifact and test evidence. Recompute
SHA-256 immediately before upload. If a previously tested artifact already
exists in Play, promote that exact version rather than rebuild/reupload it.
If an upload is interrupted, check artifact/version inventory before retrying.

Apply current country, target-SDK, signing, listing, and policy restrictions.
Resolve app-specific blockers in the console; a completed local plan does not
prove the account is eligible to publish.

## Android Publisher API edits

Use an authenticated client with scope `https://www.googleapis.com/auth/androidpublisher`.
Keep tokens in memory and out of logs/shell arguments. Use structured payloads,
bounded HTTP timeouts, and response/status checks. Consult current method docs
for schemas/allowed fields rather than inventing SDK method names.

Typical transaction against `/androidpublisher/v3/applications/{packageName}`:

1. `POST /edits` (`edits.insert`) creates an edit. Record its ID and expiry.
2. Read `/edits/{editId}/tracks` and relevant artifact/listing/tester resources.
   Persist the relevant before-state without secrets. Serialize work per package;
   console changes or competing edits can invalidate this edit. Avoid mixing UI
   writes into an open API transaction.
3. For a new AAB, upload bytes using `edits.bundles.upload` at the documented
   media-upload endpoint under `/upload/androidpublisher/v3/.../bundles`.
   Use a sufficiently long bounded upload timeout. Compare the returned version
   code and available artifact hash with the local release record.
4. Build the intended track resource from the current track plus authorized
   changes. `PUT .../tracks/{track}` (`edits.tracks.update`) sets that resource;
   sending only one candidate release can unintentionally remove others.
   Preserve or explicitly account for every existing release/version and
   country setting. Use string values in release `versionCodes`.
5. Apply only requested notes/metadata/tester changes. Call
   `POST /edits/{editId}:validate` and inspect the result. Validation is server
   consistency checking, not policy approval or a device test.
6. Before `POST /edits/{editId}:commit`, verify authorization for the resulting
   state, including whether this exposes an internal build, submits review, or
   can publish automatically. Prepare the before/after and release record first.
   Commit's request body is empty. Set review-related query options deliberately.
7. Check the commit response and re-read track state using a fresh edit/read,
   cleaning up any temporary inspection edit when appropriate. Inspect the
   console's Publishing overview/review state before claiming submission or
   availability. Keep the resulting edit/release identifiers for recovery.

Edits group changes until commit; not all Publisher API resources are transactional.
Billing/catalog/order operations can take effect independently and are outside
ordinary release scope. A timed-out commit is uncertain, not safely replayable.
Inspect current state before creating another edit or repeating any mutation.

Sources: [edits lifecycle](https://developers.google.com/android-publisher/edits),
[bundle upload](https://developers.google.com/android-publisher/api-ref/rest/v3/edits.bundles/upload),
[track update](https://developers.google.com/android-publisher/api-ref/rest/v3/edits.tracks/update),
[validation](https://developers.google.com/android-publisher/api-ref/rest/v3/edits/validate),
[commit](https://developers.google.com/android-publisher/api-ref/rest/v3/edits/commit).

## Release state and audience

`draft` does not serve the release. `inProgress` represents a staged release;
`userFraction` is a fraction such as `0.05`, not the integer percentage `5`.
Staged rollouts are for updates, not an app's first publication; inspect the
app's actual release history before proposing one.
Only use a fraction for supported staged states/tracks; omit it for `draft` and
`completed`. `completed` serves the track's eligible audience, not necessarily
the public: a completed internal release is still internal. `halted` and resume
operations require inspecting the existing release and current supported flow.
Do not create a new bundle just to halt an existing rollout.

Review is separate from these track statuses. `changesNotSentForReview` is not
a universal draft/managed-publishing flag; read its current method semantics and
inspect actual pending changes. Never retry with a more permissive review flag
merely because the conservative request was rejected.

Managed publishing controls when eligible approved changes go live; it is not
the same as keeping them unsent for review and does not cover internal tests.
Check the actual UI availability and app constraints. “Send for review,”
“approved/ready to publish,” and “publish changes” are separate transitions.

Sources: [release schema/status](https://developers.google.com/android-publisher/api-ref/rest/v3/edits.tracks),
[publishing controls](https://support.google.com/googleplay/android-developer/answer/9859654).

## Production and monitoring

Use the rollout fraction, countries, timing, and stopping point the user
authorized. If missing, prepare a concrete plan and clarify before exposing
production. Do not silently turn a staged rollout into 100%. Verify the exact
version, eligible audience, review state, and observed availability after action.

Monitor Android vitals/crashes/ANRs, core backend metrics, upgrade/migration
behavior and user reports against agreed criteria. Promote the tested artifact
and preserve release notes/symbols/mapping as applicable. A store search result
alone may lag; distinguish remote track state from actual tester/device delivery.
Record post-release evidence and a practical halt/recovery path.

Source: [prepare and roll out](https://support.google.com/googleplay/android-developer/answer/9859348).
