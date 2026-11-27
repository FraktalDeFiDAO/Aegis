# Developer Checklist

Use this checklist before marking any Aegis change complete.

## Scope

- [ ] Change is Go-native; no Rust/FFI/language bridge introduced
- [ ] Build-vs-buy decision is clear: `[LIB: name]` or `[CUSTOM]` in `docs/SPEC.md` if it adds or changes a component
- [ ] No stale Web3/Android/Desktop/coordinator-service assumptions added to docs
- [ ] Private/loopback scanning remains opt-in

## Tests

- [ ] Unit tests added/updated for changed public symbols
- [ ] Detector changes include positive, negative, and edge-case tests
- [ ] API changes include `httptest` contract tests
- [ ] Crawler changes include deterministic mock-server tests where possible
- [ ] Network-dependent tests skip cleanly offline

## Security

- [ ] New HTTP clients have a timeout
- [ ] TLS verification defaults to enabled
- [ ] Error responses are sanitized
- [ ] Session or secret files use owner-only permissions
- [ ] Filesystem writes are sanitized and bounded

## Gates

```bash
gofmt -l cmd internal
go vet ./...
go build ./...
go test -count=1 ./...
```

Release gate:

```bash
go test -count=1 -race ./...
golangci-lint run
gosec ./...
```

Run via `scripts/go-run.sh` or the documented Podman command.

## Docs

- [ ] `docs/SPEC.md` updated if behavior/status changed
- [ ] `docs/PRD.md` updated if scope/success metrics changed
- [ ] `docs/api-reference/index.md` updated if API behavior changed
- [ ] `README.md` and `docs/README.md` remain consistent with current scope
