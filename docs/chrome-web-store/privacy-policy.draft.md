# Aegis Browser Connector privacy policy — draft

Not ready to publish: publisher legal identity, contact, effective date, hosted URL,
and downstream processing practices require confirmation.

The connector links a browser extension with a separately installed local Aegis
companion and automation controller. Depending on authorized commands it can read
page content, URLs and titles, form values, cookies, browser storage, screenshots,
console/network diagnostics, frame information, download metadata, and selected
file content. Actions can use your existing authenticated website sessions.

The extension sends commands and results over a loopback WebSocket to the local
companion. The reviewed extension does not contain a vendor analytics endpoint.
A connected controller or AI agent may transmit results to its configured service;
its data practices must be reviewed separately. This draft does not assert that
no personal, financial, health, authentication, or browsing data can be processed.

Configuration, manually entered bridge authentication tokens, policies, workspace
identifiers, saved workflows, recordings, schedules, and bounded audit/run histories
are stored in browser extension local storage. Native-host credentials are kept in
memory; the bridge's discovery token is also stored in its owner-only runtime file.
Downloads, CLI output and controller logs may persist on disk separately.
Secret redaction is best effort; do not record confidential workflows until the
secret handling review is complete.

Removing the extension removes its extension storage. It does not delete downloaded
files, controller output, native-host registration/binaries, or data already sent
to another service. Before publication, provide tested instructions to inspect and
delete each category and state retention periods for downstream systems.

Publisher contact, user rights process, sale/sharing statements, security practices,
and any legally required regional terms must be finalized from verified facts.
