---
name: google-play-developer
description: Set up Google Play developer accounts and apps, prepare signed Android releases, manage internal/closed/open testing, upload bundles, submit for review, and operate production rollouts. Use for Play Console onboarding, publishing, testing eligibility, signing, release failures, and recovery; preserve the requested app, account, track, and publication scope.
---

# Google Play Developer

Carry out the requested Play Console work through existing project automation,
the Android Publisher API, or the user's authenticated browser. Scope every
operation to the correct developer account, package, and track. Account creation,
app creation, artifact upload, review submission, and publication are distinct
operations; report only states verified after the operation.

## Establish the requested outcome

Inspect existing repository release instructions, CI workflows, signing setup,
and app configuration before choosing tools. Recover known account/app details
from connected sources and the current console rather than asking again. Ask
only for missing decisions that materially change the task, such as personal
versus organization account or an ambiguous target app.

Record the developer identity, exact package name/application ID, artifact/build
variant, target track and its actual identifier, version code, current release
state, and requested stopping point. Resolve ambiguity before external writes.
Default release preparation to a local plan/draft; “prepare” or “test” does not
authorize production. Existing explicit release authorization remains valid for
the specified artifact/track/scope; do not add a blanket confirmation step to
routine authorized work.

Read only the relevant branch:

- Account registration, verification, app creation, or API access:
  [account-and-app.md](references/account-and-app.md).
- AAB builds, versioning, keys, or artifact inspection:
  [build-and-signing.md](references/build-and-signing.md).
- Test tracks, testers, production eligibility, or pre-launch quality:
  [testing.md](references/testing.md).
- Upload, promotion, review, managed publishing, production rollout, or API edits:
  [releases.md](references/releases.md).
- Declarations, rejection, operational failures, or rollback:
  [policy-and-recovery.md](references/policy-and-recovery.md).

For completing the App content checklist, use the focused
[`google-play-app-content` skill](../google-play-app-content/SKILL.md), including
its declaration evidence ledger and ready-to-use Fraktal Media Center prompt.

## Execute with evidence

1. Read the live account/app/track state. Prefer existing scoped credentials and
   project tooling. Use Aegis with its `aegis-browser` skill for console actions
   when available; otherwise use the supported browser tool. Inspect fresh page
   state after actions and verify account/package before any write.
2. Complete the authorized preparatory work: build/test, inspect the artifact,
   draft release notes/listing changes, validate declarations against actual app
   behavior, and reconcile current track contents. Surface concrete blockers.
3. Prepare a reviewable release record with artifact path and SHA-256, package,
   version code/name, signing-certificate check, track, release status, rollout
   fraction/countries if applicable, notes, test evidence, remaining blockers,
   and whether the next action uploads, sends review, or makes content available.
4. Perform only the authorized transition. Apply the active environment's
   confirmation/handoff rules at the action that requires them, after the work
   is concrete. Confirm a scope change instead of silently expanding audience,
   rollout, privileges, account ownership, or expenditure.
5. Re-read the authoritative result. A successful build, upload response, edit
   validation, edit commit, approval, and public availability are different
   evidence levels. Return the exact attained state, version/track identifiers,
   relevant console link, and any remaining manual step.

For repeatable artifact preparation:

```bash
python3 <skill-dir>/scripts/plan_release.py \
  --aab /path/to/app-release.aab --package com.example.app \
  --track internal --bundletool /path/to/bundletool.jar \
  --out /tmp/play-release-plan.json
```

The helper creates a local draft plan; it performs no Google API calls. It
validates and dumps the bundle using bundletool, checks the expected package and
version, and hashes the artifact. Signing, policy compliance, track conflicts,
and real device tests remain separate checks. Read the build reference first.

## Boundaries that affect execution

- Use the user's real account/entity details. Identity evidence, OTP/MFA,
  CAPTCHA, legal agreements, registration payments, and permission grants need
  the applicable user handling/confirmation. Do not invent verification data or
  imply these steps can always be completed autonomously.
- Keep keystores, passwords, service-account JSON, access/refresh tokens, and
  reviewer credentials out of chat, repositories, screenshots, logs, and process
  arguments. Reference secure credential locations and use supported secret
  storage or short-lived credentials. Do not rotate keys to fix a build error.
- Write factual declarations from code, SDK behavior, and owner-confirmed data
  practices. A local manifest scan alone cannot prove Data safety compliance.
- Scope testing to authorized devices/accounts. Publishing does not authorize
  unrelated billing/order/refund actions, deleting apps, changing ownership, or
  bypassing Google restrictions. Never buy/fabricate tester participation.
- For ambiguous API timeouts or UI failures after a write, inspect remote state
  before retrying. Serialise edits for one package; reconcile concurrent changes.

## Freshness

The references were checked against official Google documentation on 2026-11-26.
At execution, verify current policy deadlines, target SDK requirements, tester
eligibility, fees, country availability, and API behavior in the live console
and linked official sources. Do not turn a dated example into a permanent rule.
