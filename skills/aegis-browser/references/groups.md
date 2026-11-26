# Dedicated Aegis workspace

The user wants Aegis work in a visible browser tab group named **Aegis**.
Reuse the existing group and persisted target set rather than creating a group
per command. Keep unrelated tabs/groups intact unless the task requires them.

## Discover and resume

Use the skill helper to request `target.get` and `listTabGroups`. Match the
persisted `targetSet.groupId` to a current native group, checking its title and
window. Re-read `listTabs` to verify the persisted tab IDs still exist. IDs can
change across browser restarts; do not reuse IDs from previous conversations.
If there are several Aegis groups and the intended one is ambiguous, clarify.
If the group was closed, recreate it only when continuing the user's workspace
task, rather than repeatedly reopening something the user just closed.

The target set is persisted, but is not an enforced access boundary. Use explicit
tab IDs for page actions, preserve the user's requested site/task scope, and
account for manual tab changes. A user-requested task on another existing tab
does not authorize moving their tab into Aegis automatically.

## Create and populate

All examples use `scripts/browser.py <command> --params '<JSON>'`. Replace example
IDs with observed values.

1. Create a dedicated tab using `newTab {url:"https://example.com",active:true}`
   or the actual authorized task URL. Use a supported HTTP/S start page so the
   extension's internal-page block does not prevent later commands.
2. Request `createTabGroup {tabIds:[123],title:"Aegis",color:"blue",tabId:123}`.
   Record its returned `groupId` and whether `native:true`. A logical fallback
   is not a visible native group; report that distinction.
3. Request `target.set {tabs:[123],activeTabId:123,groupId:456,tabId:123}`.
   Verify with `listTabGroups` and `target.get`. `focusTabGroup {groupId:456}`
   focuses the workspace when appropriate.

## New task tabs

From extension 1.1.2, `newTab` joins the persisted group automatically and creates
it in that group's window. An explicit `groupId` chooses another known group.
A stale native group fails before tab creation; rediscover the workspace before
retrying. Verify the returned `groupId`, `getTabInfo`, and `target.get`.
With older versions, call `addTabToGroup` immediately after creating the tab.

Use `removeTabFromGroup {tabId:ID}` only when requested or undoing your own
incidental change; it ungroups rather than closes the tab. `closeTab` closes it.
Do not close the entire workspace or the user's unrelated tabs as cleanup.

Relevant commands: `listTabGroups`, `createTabGroup`, `addTabToGroup`,
`removeTabFromGroup`, `focusTabGroup`, `target.get`, `target.set`, `getTabInfo`.
All still follow the extension's local policy and the active environment's rules.
