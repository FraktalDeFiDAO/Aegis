# Testing and eligibility

## Select the correct distribution mechanism

Read the exact track IDs from the app. Internal, closed, open, and production
tracks differ; a custom closed-track name is not necessarily `alpha`. Form-factor
track identifiers may differ too. Internal App Sharing is a separate artifact
sharing feature, not an internal testing release or a substitute for closed-test
eligibility. Read the current console's tester/country/review constraints.

For a first test release, prepare an internal draft unless another track is
specified. Publishing to a test track still distributes an artifact; confirm
the intended tester audience and authorized stopping point. Do not silently
move a test release into production.

Configure the actual tester list/Google Group and obtain the opt-in URL. A group
invite, tester-list entry, opt-in, installation, and meaningful usage are distinct
evidence. Share links or invite people only within explicit communication scope.
An app's absence from search does not prove a test release failed; use the
appropriate opt-in/store link with an eligible account.

App pricing and country-distribution changes can affect other tracks. Inspect
their full scope before treating them as isolated test-track settings.

Source: [test releases](https://support.google.com/googleplay/android-developer/answer/9845334).

## Personal-account production access

As checked on 2026-11-26, personal accounts created after 2023-11-13 generally
need a closed test with at least 12 testers continuously opted in for 14 days
before applying for production access. Recheck the current official rule and
this account's console at execution; organization accounts and older accounts
have different eligibility conditions. Internal testing does not satisfy this
closed-test requirement. Meeting the numerical threshold is not a guaranteed
production-access approval.

Record the account type/date, actual closed-test eligibility evidence, tester
feedback and resulting fixes, and the console's access status. Draft honest
production-access responses from real testing. Do not fabricate engagement,
timer evidence, feedback, or paid/fake testers. Approval is a separate Google
decision; report pending/rejected accurately and follow the stated remediation.

Source: [personal-account testing requirements](https://support.google.com/googleplay/android-developer/answer/14151465).

## Quality evidence

Use authorized devices/emulators and test the exact release variant: fresh
install, upgrade from the live version, login/logout, permissions, offline/error
paths, core workflows, deep links, localization/accessibility, background work,
and purchases/subscriptions if in scope. Use license testers/test products rather
than making unrequested real purchases. Do not wipe or uninstall a user's app
with data as an incidental test setup step.

Inspect pre-launch reports for crashes, ANRs, performance, security and
accessibility findings; configure dedicated reviewer/test accounts when needed.
Treat unavailable reports as missing evidence, never a passing test. Google
reviewer access must work without depending on the owner's MFA session.

Define release-specific acceptance criteria and monitoring/stop conditions from
the app's baseline. Capture failed tests, affected devices/builds, fixes, and
retests; do not equate build success or edit validation with behavioral QA.

Source: [pre-launch reports](https://support.google.com/googleplay/android-developer/answer/9842757).
