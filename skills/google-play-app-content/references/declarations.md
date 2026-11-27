# Evidence by declaration

Use the actual current questions, not this table as a fixed questionnaire.
Record what the intended release does, including enabled SDKs/backend behavior.

| Card/branch | Evidence and distinctions that change the answer |
|---|---|
| Privacy policy | Check the real URL anonymously, including redirects/access restrictions, app/developer identity and consistency with actual practices. Editing or hosting a replacement policy is separate work if not authorized. |
| Ads | Inspect monetization, advertising SDKs and the actual screens/embedded content. “No AdMob dependency” does not establish no ads. Sponsorship, house promotion and paid features need the current definitions. |
| App access / sign-in details | Test whether any features depend on login, membership, geography, paywalls or other restrictions. Provide dedicated review access and complete steps where needed; do not declare unrestricted just because the landing screen is public. |
| Content rating | Answer the current questionnaire from actual accessible content and capabilities. A media app may expose mature/streamed/user-generated content even if its UI is innocuous. Distinguish authority-assigned ratings from the developer's intended audience. |
| Target audience and content | Establish intended users, design, marketing, content access and owner-confirmed audience. Do not choose adult-only merely to avoid child-directed obligations. |
| Data safety / account deletion | Use the data-flow inventory described in data-safety.md; reconcile it with privacy policy and functioning deletion mechanisms. |
| Advertising ID | Check merged AD_ID permission, resolved SDK dependencies, runtime flags and actual identifier use/purposes. Ads presence, advertising-ID use and other device identifiers are different questions. |
| Government apps | Establish actual government ownership/affiliation/use under the question's definitions. Public-sector content or an unrelated government customer does not alone establish affiliation. |
| Financial features | Inspect payments/subscriptions, wallets, lending, investments, crypto and financial content against the form's definitions. Do not assume ordinary paid features equal every financial category, or ignore real wallet functionality. |
| Health apps | Inspect actual health/medical/fitness features and data use, including integrations. A declaration may be required even when the supported answer is no health features. |
| Trader status | Reconcile this app's activity with account status and the owner's confirmed business facts. Do not make a legal classification from account type, revenue assumptions or a desire to clear the card. Verify any public contact/Terms of Service link before submission. |
| Foreground services | Inspect merged service declarations, foregroundServiceType values, associated permissions and actual runtime behavior. Supply accurate purpose, user initiation/visibility, interruption behavior and any requested demonstration evidence. Do not select mediaPlayback simply because the app is a media center. |
| Other conditional cards | Discover them live: for example sensitive permissions, photo/video access, VPN, full-screen intent, news, or special audience/use cases. Read the card's current official help and gather matching implementation evidence. |

## Interaction checks

Angular's component nesting is not itself an automation blocker. On the live
English App content page, native buttons had unique ARIA labels even though
their visible text was the repeated “Start declaration.” Aegis 1.1.1 exposes
`ariaLabel`, `accessibleName`, role, disabled/checked state and stable ARIA-based
selectors in element-query results. With older versions, inspect labels using
`getElementAttribute` or a task-scoped HTML read; do not infer their absence
from the old query metadata.

Example after verifying the live label and fresh tab ID:

```bash
python3 <aegis-skill-dir>/scripts/browser.py querySelectorAll --params '{"tabId":123,"frameId":0,"selector":"button[aria-label=\"Start Privacy policy declaration\"]"}'
# Require count == 1 and an enabled native button before interacting.
python3 <aegis-skill-dir>/scripts/browser.py click --params '{"tabId":123,"frameId":0,"selector":"button[aria-label=\"Start Privacy policy declaration\"]","strict":true}'
```

`strict:true` in extension 1.1.1 requires exactly one visible, enabled CSS target.
It is available for DOM interactions, not a universal guarantee on all commands.
Check `extension.info` for the running version and `features.strictCssTargets`.
Verify the new form's heading/URL after opening it, before entering any answer.
An old extension ignores an unknown strict parameter: check the installed
version and independently verify uniqueness when using an older version.

Resolve duplicate Start/Manage/Save buttons within the intended card or dialog.
Read all conditional fields after changing an answer. Custom Material menus,
radio groups, checkboxes, multi-step questionnaires and URL fields may need
different actions; verify the actual resulting selection. If no unique target
is available, inspect rather than clicking the first global match.

Save and reopen each form. Record the resulting Console status as observed,
not translated into “approved.” Content ratings may have their own submit/apply
step; inspect that scope and any contractual attestation before proceeding.

## Official references

- [App content overview, privacy, ads and review access](https://support.google.com/googleplay/android-developer/answer/9859455)
- [Content ratings](https://support.google.com/googleplay/android-developer/answer/9859655)
- [Target audience](https://support.google.com/googleplay/android-developer/answer/9867159)
- [Advertising ID policy](https://support.google.com/googleplay/android-developer/answer/6048248)
- [Current policy-declaration field definitions](https://developers.google.com/android-publisher/app-store-review/policy-declarations)
- [Foreground service requirements](https://support.google.com/googleplay/android-developer/answer/13392821)
- [Foreground service manifest declarations](https://developer.android.com/develop/background-work/services/fgs/declare)
- [Trader status](https://support.google.com/googleplay/android-developer/answer/17594752)

Use these to interpret the current form; they are not evidence of this app's
implementation. This workflow uses the Console through Aegis and does not assume
that every form has an available, authorized API endpoint.
