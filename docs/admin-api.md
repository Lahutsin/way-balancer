# Admin API

## Scope

The admin surface is exposed by `lb-dataplane serve --config ...` and is intended for privileged operational control, not public application traffic.

In the current workspace mode, the admin listener exposes health, status, validation, audit, reload, and cache-control endpoints over HTTP/1.

## Endpoint Matrix

| Endpoint | Method | Permission | Typical result | Purpose |
| --- | --- | --- | --- | --- |
| `/healthz` | `GET` | `read` | `200 OK` | Cheap readiness probe for the admin surface. |
| `/status` | `GET` | `read` | `200 OK` | Runtime counters, listener state, replacement lifecycle, and recent overload events. |
| `/validate` | `GET` | `read` | `200 OK` or `400 Bad Request` | Dry-run current config file and preview active vs candidate snapshots, warnings, and apply strategy. |
| `/audit` | `GET` | `audit` | `200 OK` | Recent admin-plane activity with actor, outcome, and detail. |
| `/reload` | `POST` | `write` | `200 OK` or `500 Internal Server Error` | Apply the current config file using rollback-safe reload logic. |
| `/cache/purge` | `POST` | `write` | `200 OK` or `400 Bad Request` | Purge cache entries by exact key or path prefix. |
| `/cache/invalidate` | `POST` | `write` | `200 OK` or `400 Bad Request` | Apply a replay-safe invalidation event, usually for multi-node convergence. |

## Auth Modes

The admin listener supports two explicit auth models:

- `bearer`: shared bearer secret, typically from `LB_CTL_ADMIN_SECRET`
- `signed_headers`: per-operator signing with permissions, replay protection, and clock-skew checks

For production exposure, prefer `signed_headers`. The bearer mode is practical for localhost-only or isolated bootstrap flows.

## Bearer Example

```sh
export LB_CTL_ADMIN_SECRET=<admin-bearer-token>
curl -H "Authorization: Bearer $LB_CTL_ADMIN_SECRET" http://127.0.0.1:9900/status
curl -H "Authorization: Bearer $LB_CTL_ADMIN_SECRET" http://127.0.0.1:9900/validate
curl -H "Authorization: Bearer $LB_CTL_ADMIN_SECRET" http://127.0.0.1:9900/audit
curl -X POST -H "Authorization: Bearer $LB_CTL_ADMIN_SECRET" http://127.0.0.1:9900/reload
```

## Signed Header Contract

When `listeners[].admin.auth.mode = "signed_headers"`, each request must include:

- `x-lb-admin-actor`
- `x-lb-admin-timestamp`
- `x-lb-admin-nonce`
- `x-lb-admin-signature`

The runtime signs and verifies the exact payload:

```text
actor
method
target
timestamp
nonce
```

The signature path enforces:

- operator existence
- permission for the requested action
- timestamp skew bounds
- nonce replay rejection
- secret presence and validity

The detailed security posture and rollout guidance live in [Admin Plane Hardening](runbooks/admin-plane-hardening.md).

## What `GET /status` Returns

`GET /status` is the main runtime-state endpoint. The response includes:

- service mode and config path
- uptime and proxied request or connection counters
- admin request and reload counters
- `last_reload_result`
- per-listener status records
- `recent_overload_events`

Each listener record includes:

- `state` and `overload_state`
- accepted, active, completed, and shed connection counters
- `brownout_features`
- replacement lifecycle state under `replacement`

The replacement object is especially important during reloads. It shows whether the listener is stable, draining, or preserving a failed replacement start.

## What `GET /validate` Returns

`GET /validate` is the preflight endpoint for config mutation. It returns:

- the active compiled snapshot, if one is running
- the candidate compiled snapshot from disk
- a diff preview between active and candidate
- warnings for meaningful but syntactically valid changes
- apply strategy and rollback-safety summary
- compatibility metadata

Use it before every `POST /reload`.

## What `GET /audit` Returns

The audit endpoint returns a bounded in-memory list of recent admin actions, including:

- request identifier
- listener name
- actor
- auth mode
- action
- source
- outcome
- detail

This is the fastest way to understand whether a denied or failed admin action was caused by auth, permissions, rate limits, replay rejection, or a runtime apply failure.

## Reload Semantics

`POST /reload` applies the current config from disk only after it compiles successfully.

Important behavior:

- successful reloads return `configuration applied`
- failed reloads preserve the active runtime and return `500 Internal Server Error`
- overlap-and-drain listener replacement is used when a safe staged swap is possible
- started reloads are recorded in audit before the apply finishes

Operational rule: run `GET /validate` first, then `POST /reload`, then confirm with `GET /status` and `GET /audit`.

## Cache Control Endpoints

### `POST /cache/purge`

This endpoint is the normal operator-facing cache action. It accepts a listener or route cache scope plus a target.

Example path-prefix purge:

```json
{
  "scope": "public",
  "target": {
    "type": "path_prefix",
    "path_prefix": "/catalog"
  },
  "requested_by": "admin-a",
  "reason": "invalidate catalog"
}
```

The response reports local purge effect and fan-out status, including:

- `action`
- `result`
- `scope`
- `purged_entries`
- `fanout_delivery_success_count`
- `fanout_delivery_failure_count`
- `fanout_failed_targets`
- `degraded`
- `invalidation_event_id`

### `POST /cache/invalidate`

This endpoint applies a replay-safe invalidation event directly. It is most useful for internal or peer-delivery workflows, not for a human operator’s first-line purge path.

Example event body:

```json
{
  "event_id": "node-a-1",
  "scope": "public",
  "issuer": "node-a",
  "target": {
    "PathPrefix": "/catalog"
  },
  "occurred_at_unix_ms": 1700000000000
}
```

The response indicates whether the event was newly applied or detected as a duplicate.

## Common Status Codes

| Status | Typical meaning |
| --- | --- |
| `401 Unauthorized` | Missing or invalid admin authentication. |
| `403 Forbidden` | Source allow-list or permission policy blocked the request. |
| `404 Not Found` | Unknown admin endpoint. |
| `409 Conflict` | Signed-header nonce replay was rejected. |
| `429 Too Many Requests` | The authenticated admin identity exceeded configured rate limits. |
| `500 Internal Server Error` | Reload attempted but the apply failed. |
| `503 Service Unavailable` | Required admin signing secret was missing or another fail-closed prerequisite was not met. |

## Recommended Operator Sequence

1. Call `/healthz` to confirm the admin plane is reachable.
2. Call `/validate` before mutating config.
3. Call `/reload` only after a clean preview.
4. Call `/status` to inspect listener replacement or overload state.
5. Call `/audit` after denied or failed actions to capture the exact reason.

## Next Step

Open [HTTP Cache](cache.md) for cache behavior and invalidation guidance, or open [Troubleshooting](troubleshooting.md) for failure-oriented workflows.