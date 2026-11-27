# Aegis Documentation

This documentation describes Aegis as it exists after the v3 audit: a Go-native,
single-target authenticated web crawler and vulnerability triage scanner.

## Start here

1. `PRD.md` — product intent, scope, success metrics, and false-positive gates
2. `SPEC.md` — component-level technical specification and quality gates
3. `TESTING.md` — how to run local/CI test gates
4. `architecture/overview.md` — current architecture and data flow
5. `api-reference/index.md` — current REST API, not a hypothetical coordinator API
6. `plans/2026-06-02-go-native-hardening-remediation.md` — plan to close remaining gaps

## Important scope statement

Aegis is not currently a Burp Suite/Caido replacement, not a general fuzzer, and not
a multi-target recon platform. The current workstream is to make all existing Go-native
functionality solid and deterministic before adding broader platform features.

## Quality policy

Every detector must have:

- positive test: known-bad input produces findings
- negative test: realistic safe input produces no findings
- edge-case test: empty/large/unicode/binary/truncated inputs do not panic or false-positive

Every orchestrator must be deterministic where possible: same config and same mock
server should produce the same crawl page set.
