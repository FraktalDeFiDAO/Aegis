# Data safety and deletion

Inventory off-device flows from app code, SDKs, app-controlled WebViews, servers
and runtime configuration. Device-local processing is different from transmission;
ephemeral processing is not automatically exempt from declaration. Use current
Google definitions of collection, sharing and applicable exceptions.

For each flow record data type, recipient/SDK, purpose, whether optional,
retention/ephemeral handling, encryption, deletion path and evidence. Check
analytics, crash reporting, identifiers, login, media metadata and uploaded files.
HTTPS on one endpoint does not establish encryption for every flow. Permission
absence and a clean source search do not prove no collection. SDK guidance must
match the actual version and configuration.

Reconcile the complete inventory with the exact form branches and privacy
policy. Ask the owner for genuinely unknown server/provider practices rather
than guessing conservative-sounding answers.

Where account creation is supported, verify the required in-app and external
deletion request paths and associated-data handling. Sign-out or uninstall is
not account deletion. Check the submitted URL and any stated retention
exceptions. Do not perform real destructive deletion as incidental validation;
use an authorized disposable account where needed.

Sources: [Data safety definitions](https://support.google.com/googleplay/android-developer/answer/10787469),
[account deletion](https://support.google.com/googleplay/android-developer/answer/13327111),
[User Data policy](https://support.google.com/googleplay/android-developer/answer/10144311).
