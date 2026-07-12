# API Reference

Aegis exposes a small REST API for starting crawls and checking health. The API is
not a general coordinator service and does not expose Web3/Android/Desktop analyzer
endpoints.

## Authentication

All endpoints except process startup require authentication unless the server is
started with `AEGIS_API_ALLOW_UNAUTH=true` for development.

Accepted credentials:

- `Authorization: Bearer <token>`
- `X-API-Key: <AEGIS_API_TOKEN>`

Server refuses to start without `AEGIS_API_TOKEN` unless `AEGIS_API_ALLOW_UNAUTH=true`.

## Rate limiting

Per-client token-bucket rate limit:

- `AEGIS_API_RATE_PER_MIN` default `60`
- `AEGIS_API_RATE_BURST` default `10`
- `AEGIS_API_BUCKET_TTL_SEC` default `600`
- `AEGIS_API_MAX_BUCKETS` default `10000`
- `AEGIS_API_SWEEP_EVERY_SEC` default `60`

Bucket storage is bounded by TTL and max-bucket eviction.

## Dump quota

API crawls write to `api_dump/<timestamp>` by default.

- `AEGIS_API_DUMP_ROOT` default `api_dump`
- `AEGIS_API_DUMP_MAX_DIRS` default `16`

Oldest directories are pruned when the quota is exceeded.

## GET /health

Health check.

### Response

```http
HTTP/1.1 200 OK
Content-Type: application/json
```

```json
{"ok":true}
```

## POST /crawl

Start an asynchronous crawl.

### Request

```http
POST /crawl HTTP/1.1
Authorization: Bearer <token>
Content-Type: application/json
```

```json
{
  "target": "https://example.local",
  "maxDepth": 3,
  "userAgent": "AegisBot/1.0"
}
```

The exact config maps to the crawler config accepted by the Go API. Invalid JSON
returns `400`. Missing/invalid auth returns `401`. Rate-limit exceed returns `429`.

### Response

```http
HTTP/1.1 202 Accepted
Content-Type: application/json
```

```json
{
  "status": "accepted"
}
```

The crawl runs asynchronously and writes artifacts to the configured API dump root.

## Error responses

Errors are sanitized. The API must not leak internal stack traces or raw filesystem
paths in response bodies.

```json
{"error":"unauthorized"}
```

## Contract tests

The API behavior contract is defined in `docs/SPEC.md` §7.4.4 and should be encoded
in `internal/api/api_spec_test.go`.
