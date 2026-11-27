# Implementation Plan

This file is retained as a root-level pointer for older references.

## Current verification status

**Not fully to spec.** See [the evidence-backed conformance matrix](docs/plans/2026-11-27-plan-conformance.md)
for current gaps, confirmed fixes, and release gates. Historical execution logs
are not a current completion checklist.

## Active Plans (in priority order)

1. **`docs/plans/2026-07-12-v4-comprehensive-remediation.md`** — CURRENT ACTIVE PLAN
   - Based on v4 audit (2026-07-12): 115 findings across 29 files
   - 8 phases: HTTP hardening → resource leaks → race conditions → stubs → safety defaults → deduplication → docs → verification
   - Branch: `audit/v4-comprehensive-remediation-2026-07-12`

2. **`docs/plans/2026-06-02-go-native-hardening-remediation.md`** — PARTIALLY EXECUTED (PR #1 merged)
   - Batches 1-8 cover detector FP gates, crawl determinism, session contracts, API contracts, recon, OWASP quality, backlog, and final audit
   - Some batches may be superseded by v4 plan; cross-reference before executing

3. **`docs/plans/2026-11-15-connector-feasible-features-plan.md`** — PARTIALLY IMPLEMENTED
   - Browser connector phases 0–7; use the current conformance matrix for status.
   - Store packaging/security records do not establish full feature-plan completion.

## Historical / Reference

Do not use older strategic-pivot drafts or stale multi-analyzer drafts.
Those are out of scope for current Aegis.