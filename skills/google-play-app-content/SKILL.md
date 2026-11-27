---
name: google-play-app-content
description: Complete and verify Google Play Console App content declarations using the live checklist, release evidence, SDK behavior, and owner-confirmed facts. Use for privacy policy, Data safety, app access, ads, ratings, audience, Advertising ID, trader status, foreground services, and conditional declarations. Saving declarations does not authorize publishing an app or inventing compliance answers.
---

# Google Play App Content

Complete the requested app's actual App content checklist, using truthful,
traceable answers and verified saves. This skill supports declaration work;
account creation, release uploads, review submission and production publishing
remain separate tasks. Use `google-play-developer` for those broader workflows.

## Establish scope and inventory

1. Confirm developer account ID, numeric Console app ID, package name, repository,
   and the release/artifact being represented. Recover known values from the
   conversation, existing tooling and Console; resolve identity conflicts before
   writing. Do not confuse another account's Policy status with this app's forms.
2. Use `aegis-browser` when working through Aegis. Reuse the dedicated Aegis group
   for new task tabs; preserve unrelated tabs. Read current capabilities and use
   only implemented commands. Include explicit, freshly observed tab/frame IDs.
3. Open App content and inventory both Needs attention and Actioned, including
   warnings, conditional cards, deadlines, and the exact current labels. The
   live checklist determines scope; never assume a fixed number of declarations.
4. Create a private evidence ledger using
   [the ledger template](assets/evidence-ledger.md). Record each observed card's
   before-state. Completed historical answers still need checking against the
   intended release; neither existing answers nor an empty warning list proves
   that the declarations are accurate.

For Fraktal Media Center, the ready-to-use
[task prompt](assets/fraktalmediacenter-app-content.txt) supplies expected
identifiers, not prefilled declaration answers. Reverify them at execution.

## Establish answers before entering them

Read [declarations.md](references/declarations.md) for the cards actually present.
For Data safety/deletion, also read [data-safety.md](references/data-safety.md).

Inspect release-relevant source, merged manifest, dependency/SDK versions,
runtime configuration, backend/provider behavior, user flows, existing privacy
policy and owner-approved disclosures. For every material answer, record the
proposed value, evidence location and unresolved assumptions. Policy documents
define questions; they do not prove what this app actually does.

Separate established facts, owner-confirmed facts, unknowns and contradictions.
Absence of a permission, a negative text search or a disabled development flag
alone cannot establish a negative declaration. Account for third-party SDKs,
remote configuration and embedded content. Never infer an age group, no ads,
no data collection, or no financial/health features from the app's name.

Continue independent, supported work while collecting unknowns. Ask one concise
batch of necessary owner questions, explaining which form each answer affects.
Do not ask the owner to rediscover facts available in the repository. Missing
backend practices, business status or intended audience may genuinely need the
owner. Where evidence conflicts, resolve it before submitting that declaration.

## Fill and verify one declaration at a time

- Locate the card by its heading/context before choosing Start declaration,
  Manage or Edit. Repeated button text is not a unique target. Reinspect after
  navigation and dynamic form changes; do not reuse stale Angular selector paths
  or assume a recorded workflow still matches the current form.
- Nested Angular tags do not imply that a control is unclickable. Inspect the
  underlying native button's `aria-label` or other accessible identity. Current
  Console examples include `button[aria-label="Start Privacy policy declaration"]`
  and `button[aria-label="Start Ads declaration"]`. Observe labels live rather
  than assuming they persist across locales or UI changes. Verify exactly one
  match, then use `strict:true` on supported DOM interaction commands. Click the
  actual button, not its wrapper. See the targeting example in declarations.md.
- Read each question, help text, conditional branch and current value. Enter only
  supported answers. Choose Not applicable only when the question and evidence
  support it; it is not a shortcut for unanswered questions.
- Use private parameter files for sensitive values. Reviewer credentials go only
  to the intended restricted review-access fields using an authorized secret
  source, never to logs, public notes, screenshots or the evidence ledger.
- Prepare concrete values before any confirmation required by the environment.
  Existing authorization to complete these forms covers ordinary supported
  saves; do not demand repeated blanket approval. Apply action-time rules for
  contractual attestations, sensitive disclosures or new permissions as relevant.
- Save, observe validation errors and wait for an actual success/state change.
  Reopen the form and compare persisted values with the ledger, then recheck the
  overview. A click acknowledgment or disabled Save button is not sufficient.
- If a save times out, reread before retrying. Do not repeatedly submit the same
  questionnaire or use another transport/policy mode to bypass a denied action.

Changing a declaration can queue public listing/review changes. Inspect the
Publishing overview where relevant. Do not click an app-wide Send for review or
Publish changes button unless that separate scope is explicitly authorized;
other pending changes may be included. A questionnaire's own Submit action must
be evaluated in its actual context rather than assumed to publish a release.

## Completion evidence

Account for every discovered card in the ledger as saved-and-reopened,
not-required-with-Console-evidence, blocked-with-specific-questions, or pending
Google processing/review. Distinguish form completion from Google acceptance.

Report the verified account/app/package, release evidence, before/after counts,
each card's disposition, remaining warnings/questions, and any pending review
state. Claim App content complete only when every required card is accounted
for, no required answer is unresolved and the live overview shows no remaining
declaration action. If Google's state is pending, say so; never promise approval.

Keep the ledger private and reference secrets by secure location only. Recheck
the official links when definitions, requirements or the UI have changed.
Reference material last checked: 2026-11-26.
