# Declarations and recovery

## App content

Inspect the merged manifest, dependencies/SDKs, runtime behavior, backend data
flows, permission prompts and existing owner disclosures. Reconcile Data safety,
privacy-policy URL, ads, app access, target audience, content rating, account
deletion, sensitive permissions, and app-specific declarations with the actual
release. Use the current dashboard as the required-fields source. SDK behavior
counts; absence of direct network calls in app code is not proof of no collection.

Prepare truthful answers and flag unknowns for the owner. Never infer “no ads,”
“no data collection,” or “children-safe” merely from the app's description. Confirm
that the privacy-policy page is accessible and appropriate; do not invent legal
claims. Reviewer credentials should be dedicated, least-privilege, and usable
under the review instructions; keep them out of public notes/screenshots.

Sources: [App content](https://support.google.com/googleplay/android-developer/answer/9859455),
[Data safety](https://support.google.com/googleplay/android-developer/answer/10787469),
[Developer policies](https://play.google.com/about/developer-content-policy/).

## Diagnose the actual failure

| Symptom | Investigate before retrying |
|---|---|
| 401/authentication | Expiry, token scope and intended identity; refresh credentials through the supported flow |
| 403/permission | Play Console invitation/app/track rights and API enablement; Cloud IAM alone is insufficient |
| Package not found | Wrong account/package, missing app/setup/initial console upload, or insufficient access; do not invent another package |
| Version already used | Inspect all artifacts/tracks and partial uploads; reuse/promote only when correct or create a deliberate higher version |
| Wrong signing certificate | Compare expected upload fingerprint with artifact; locate correct key, never overwrite/rotate reflexively |
| Draft-app status restriction | Inspect app setup and required draft workflow; do not force completed/production |
| Stale/conflicting/expired edit | Re-read remote state, reconcile authorized changes, recreate one edit; do not stomp concurrent work |
| Review/validation rejection | Record exact reason, affected version and policy link; fix the real issue and prepare evidence |
| Timeout/connection loss after write | Check uploaded version, track, review state and pending changes before replay |
| Tester cannot install | Eligibility/opt-in account, country, device compatibility, version precedence, links and rollout propagation |

Record useful error codes/messages without credentials. Use bounded retries for
transient reads; mutation retries require reconciliation or documented idempotency.
Do not add permissions, falsify declarations, flip review flags, change country
audience, or substitute signing identities to make an error disappear.

## Recovery semantics

Before modifying release state, inspect the live release and supported Google
operations. Halting a rollout can stop further delivery where supported; it
does not remove a version already installed on devices or undo server-side data
migrations. Do not promise a downgrade by uploading an older version code.

Use the console/API's current halt/resume/recovery flow for the actual release
status, or prepare a fixed build with a higher valid version code. Completed
release recovery and staged-rollout halting can differ. Verify who will receive
which version afterward and ensure migrations/backends tolerate the resulting
mix. Preserve the user's authorization boundary for halts and follow-up releases.

For rejection or access denial, draft a factual remediation/appeal from evidence.
Sending an appeal is an external communication and needs the task's explicit
scope; this skill does not authorize contacting Google or testers automatically.

Sources: [tracks and rollout behavior](https://developers.google.com/android-publisher/tracks),
[staged rollout help](https://support.google.com/googleplay/android-developer/answer/6346149).
