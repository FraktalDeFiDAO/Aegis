# Separation of Concerns

## Principle

Aegis separates acquisition, validation, analysis, orchestration, and reporting so
that each subsystem can be tested independently and hardened without changing the
whole pipeline.

## Boundaries

### CLI (`cmd/aegis`)

Responsible for command parsing, flags, and invoking internal packages. It should
not contain detector logic, crawler logic, or persistence policy beyond wiring.

### Validation (`internal/validator`, `internal/scope`)

Responsible for URL, host, path, and scope policy. Any component that accepts a
user-controlled URL must call the validator before network access or filesystem
write.

### Acquisition (`internal/browser`, `internal/crawler`, `internal/content`, `internal/scrape`)

Responsible for fetching/rendering pages and persisting crawl artifacts. It should
not decide vulnerability severity. It produces normalized artifacts for scanners.

### Analysis (`internal/scanner`, `internal/owasp25`, `internal/xss`, `internal/waf`, `internal/platform`)

Responsible for findings. Every detector must satisfy the PRD/SPEC false-positive
contract: positive, negative, and edge-case tests.

### Orchestration (`internal/runner`, `internal/workflow`, `internal/api`)

Responsible for running workflows and API jobs. It must be bounded, authenticated
where externally reachable, and deterministic in tests.

### Persistence (`internal/session`, crawler DB, filesystem dumps)

Responsible for encrypted sessions, SQLite crawl state, and local artifacts. Writes
must be bounded and safe: owner-only permissions for secrets, quota enforcement for
API dumps, and atomic writes for session files once SPEC backlog B-5 is implemented.

## Out of scope

This document does not describe Web3 analyzers, Android analyzers, desktop binary
analysis, Python/Rust/Java analyzers, or a coordinator service. Those were stale
pre-v3 concepts and are not part of current Aegis.
