# Accounts, app creation, and API access

## Developer account

First establish whether the requested account already exists and whether the
user is its owner or an invited collaborator. Use Google Play Console, not the
separate Android Developer Console for distribution outside Play.

Choose personal versus organization from the actual publishing entity and
Google's requirements; do not choose an inaccurate type to evade testing.
For registration, collect only the missing required details: the intended Google
account, entity/contact information, country, verification readiness, and fee
approval. Distinguish public developer contact fields from private verification
details. Explain which fields will be public before supplying sensitive data.

Prepare the registration through the official console. Hand the user identity
document entry/uploads and MFA/OTP as appropriate; follow active confirmation
rules for contractual acceptance and the actual registration payment. Verify
the owner/developer ID and remaining verification tasks after signup. Pending
verification is not an operational publishing account.

Organizations may need D-U-N-S and organization verification; use the current
Google instructions for exemptions/support rather than substituting an
individual's details. Follow any device/contact verification steps shown.

Sources: [registration](https://support.google.com/googleplay/android-developer/answer/6112435),
[account types](https://support.google.com/googleplay/android-developer/answer/13634885),
[required information](https://support.google.com/googleplay/android-developer/answer/13628312).

## Create/configure an app

Confirm the package/application ID, app name, default language, app/game type,
free/paid choice, and public support contact. A package name is not a display
name; choose the durable identity deliberately and match the built artifact.
Inspect the current form rather than assuming a fixed sequence of fields.
The create-app flow includes declarations/terms; prepare the form and obtain
the applicable action-time confirmation before accepting/submitting them.

Use the console's Create app flow. Do not invent a Publisher `applications.create`
endpoint: the current applications resource does not provide it. Establish
whether initial upload/setup must be completed in the console before API use.
Verify the created app under the intended developer and package.

Complete the dashboard from live requirements: listing and localized assets,
support contacts, category, privacy-policy URL, App content declarations, reviewer
access, countries, and pricing. A draft listing is not a published app. Defer
policy answers that cannot be supported by app evidence to the owner.

Sources: [app setup](https://support.google.com/googleplay/android-developer/answer/9859152),
[applications resource](https://developers.google.com/android-publisher/api-ref/rest/v3/applications).

## API access

Inspect existing CI/fastlane/Gradle Play Publisher setup first. For new setup,
enable the Android Publisher API in the correct Cloud project and configure an
appropriate OAuth identity or service account. Invite/grant that identity in
Play Console with the minimum app-specific permissions needed for the requested
track/action. Cloud IAM ownership alone does not confer Play Console access.

The OAuth scope is `https://www.googleapis.com/auth/androidpublisher`.
An API-access configuration no longer requires linking the Play developer
account to a Cloud project. A valid token is distinct from permission on the
requested package. Do not grant order/financial permissions for release work.

Prefer existing short-lived/CI credentials. Use secure secret storage when keys
are unavoidable; never print their contents or request them in chat. Provide
only scoped paths/identities in a handoff. Run a package-scoped read to verify
access before attempting uploads or publication. Handle new security-sensitive
permission grants under the environment's confirmation rules.

Sources: [API setup](https://developers.google.com/android-publisher/getting_started),
[authorization](https://developers.google.com/android-publisher/authorization).
