# Admin API

## Scope

The admin surface is exposed by `lb-dataplane serve --config ...` and is intended for privileged operational control, not public application traffic.

In the current workspace mode, the admin listener exposes liveness, serving-readiness, status, validation, audit, reload, and cache-control endpoints over HTTP/1.

The legacy unversioned endpoints remain available for backward compatibility. The stable machine-readable contract is exposed additively under `/v1/...` and returns `X-LB-Admin-Api-Version: v1` on every response.

## Endpoint Matrix

| Endpoint | Method | Permission | Typical result | Purpose |
| --- | --- | --- | --- | --- |
| `/healthz` | `GET` | `read` | `200 OK` | Liveness probe for the admin surface. |
| `/readyz` | `GET` | `read` | `200 OK` or `503 Service Unavailable` | Serving-readiness probe for the dataplane instance. |
| `/status` | `GET` | `read` | `200 OK` | Runtime counters, listener state, replacement lifecycle, and recent overload events. |
| `/validate` | `GET` | `read` | `200 OK` or `400 Bad Request` | Dry-run current config file and preview active vs candidate snapshots, warnings, and apply strategy. |
| `/audit` | `GET` | `audit` | `200 OK` | Recent admin-plane activity with actor, code, outcome, and detail. |
| `/reload` | `POST` | `write` | `200 OK` or `500 Internal Server Error` | Apply the current config file using rollback-safe reload logic. |
| `/cache/purge` | `POST` | `write` | `200 OK` or `400 Bad Request` | Purge cache entries by exact key or path prefix. |
| `/cache/invalidate` | `POST` | `write` | `200 OK` or `400 Bad Request` | Apply a replay-safe invalidation event, usually for multi-node convergence. |

Each listed endpoint also has a stable versioned form under `/v1`, such as `/v1/status`, `/v1/readyz`, and `/v1/reload`.

## Versioned Contract

`/v1/*` responses use a stable envelope:

```json
{
  "api_version": "v1",
  "status": "ok",
  "data": { ... }
}
```

Errors use:

```json
{
  "api_version": "v1",
  "status": "error",
  "error": {
    "code": "unsupported_api_version",
    "message": "requested admin API version is not supported"
  }
}
```

Current stable error codes include:

- `unauthorized`
- `forbidden`
- `replay_rejected`
- `rate_limited`
- `validation_failed`
- `reload_failed`
- `unsupported_mutation`
- `not_found`
- `unsupported_api_version`
- `misconfigured`
- `internal`

## Auth Modes

The admin listener supports two explicit auth models:

- `bearer`: shared bearer secret, typically from `LB_CTL_ADMIN_SECRET` or `LB_CTL_ADMIN_SECRET_FILE`
- `signed_headers`: per-operator signing with permissions, replay protection, and clock-skew checks

For production exposure, prefer `signed_headers`. The bearer mode is practical for localhost-only or isolated bootstrap flows.

When `<SECRET_ENV>_FILE` is set, the runtime reads the secret material directly from that file on each admin request. That is the supported zero-downtime rotation path for file-projected Kubernetes secrets and similar external secret delivery mechanisms.

## Bearer Example

```sh
export LB_CTL_ADMIN_SECRET=<admin-bearer-token>
curl -H "Authorization: Bearer $LB_CTL_ADMIN_SECRET" http://127.0.0.1:9900/status
curl -H "Authorization: Bearer $LB_CTL_ADMIN_SECRET" http://127.0.0.1:9900/readyz
curl -H "Authorization: Bearer $LB_CTL_ADMIN_SECRET" http://127.0.0.1:9900/validate
curl -H "Authorization: Bearer $LB_CTL_ADMIN_SECRET" http://127.0.0.1:9900/audit
curl -X POST -H "Authorization: Bearer $LB_CTL_ADMIN_SECRET" http://127.0.0.1:9900/reload
```

Use probe endpoints with this split:

- `GET /healthz`: confirms the process is alive and the admin listener can answer.
- `GET /readyz`: confirms whether the instance should receive new traffic.

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
sha256_hex(request_body)
```

For empty-body requests, the final line is the SHA-256 of the empty payload. Any body mutation after signing invalidates the request.

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
- `reload_health`
- `last_reload_outcome_code`
- reload duration metrics: `reload_total_duration_ms`, `reload_max_duration_ms`, `reload_last_duration_ms`, `reload_last_success_duration_ms`, `reload_last_failure_duration_ms`
- `last_reload_result`
- `control_plane_journal`
- rolled-up `readiness`
- per-listener status records
- `recent_overload_events`

Each listener record includes:

- `state` and `overload_state`
- accepted, active, completed, and shed connection counters
- `brownout_features`
- replacement lifecycle state under `replacement`

For HTTPS listeners, `listener.tls` also exposes:

- TLS health state and stable reason codes
- minimum TLS version and ALPN policy
- session resumption mode
- certificate metadata for the default certificate and any SNI certificates, including fingerprint, SANs, validity bounds, and expiry-warning status

The replacement object is especially important during reloads. It shows whether the listener is stable, draining, preserving a failed replacement start, or reporting that an old listener exceeded its configured drain timeout while the replacement stayed active.

The status surface also publishes `last_reload_outcome_code` so automation can distinguish `reload_applied_in_place`, `reload_applied_overlap_drain`, `reload_failed_rollback_preserved`, and `reload_failed_blocked_change` without parsing free-form text. It also includes bounded reload duration metrics so operators can reason about recent, worst-case, and cumulative apply latency without scraping free-form audit text.

At the top level, `admin_auth.secret_sources` reports the configured admin secret sources without leaking secret values. Each entry includes the listener name, auth mode, actor, source kind (`env` or `file`), source reference, current health, and whether that source supports rotation without a process reload.

The `control_plane_journal` object exposes the local durable journal path plus the currently restored desired and applied snapshot identity. Its nested `recovery` object tells operators whether the process restored prior durable state cleanly or detected an unfinished in-flight reload that now needs operator attention.

When unfinished recovery is present, `control_plane_journal.recovery.in_flight_operation` also carries the persisted lifecycle code, human-readable detail, and any affected listener names. For overlap-and-drain recovery, that lets automation distinguish a plain in-place reload from a replacement-aware reload that was interrupted mid-flight.

After startup reconciliation, `control_plane_journal.recovery.reconciled_listeners` reports the current live `listener_state` and `replacement_state` for each affected listener name plus a machine-readable `reconciliation_verdict`. Current verdicts distinguish at least `settled`, `replacement_still_draining`, `replacement_failed_preserved`, `replacement_drain_timeout`, `missing`, and fallback `needs_review`.

The same recovery block also publishes `reconciliation_summary`, which rolls those listener-level verdicts into an `overall_verdict` plus per-bucket counts. That is the fastest surface for automation to decide whether recovered replacement work is settled, still draining, or still needs review.

`reconciliation_summary` also includes `recommended_action`, a machine-readable next-step hint. Current values distinguish at least `observe_only`, `wait_for_drain_completion`, `validate_and_retry_reload`, `investigate_drain_timeout`, and `investigate_and_validate_reload`.

At the top level, `control_plane_journal.recovery.operator_guidance` turns the full recovery state into an operator-facing recommendation even when there are no affected listeners to reconcile. It currently exposes a machine-readable `recommended_action`, `urgency`, `operation_age_ms`, `expected_completion_within_ms`, and `exceeded_expected_completion`, so plain unfinished reload recovery can still report `validate_and_retry_reload` with `action_required`, while interrupted overlap-and-drain recovery can escalate to `investigate_stalled_drain` once the persisted operation age exceeds the expected drain window.

When startup successfully bootstraps the current config after crash recovery, `reload_health` and `last_reload_outcome_code` may move forward to the new startup apply result. In that case, use `control_plane_journal.recovery` and the recovery audit event code `reload_recovered_unfinished` to decide whether prior unfinished work still needs operator review.

After an operator performs a subsequent successful `POST /reload`, the recovery block should move from `needs_operator_action` to `resolved`. That transition is the machine-readable signal that the unfinished recovered reload has been reviewed and superseded by a new completed apply.

The journal currently retains a bounded recent admin audit slice rather than unbounded history. In serve mode, that bounded slice follows the active admin audit capacity so restart recovery preserves the most recent operator-relevant events without turning the local journal into an unbounded log.

## What `GET /readyz` Returns

`GET /readyz` is the serving-readiness endpoint. It returns machine-readable JSON plus:

- `200 OK` when the instance should receive new traffic
- `503 Service Unavailable` when the instance should be removed from new traffic

The current readiness contract rolls up public listeners when public listeners exist. It becomes not ready when:

- there are no serving listeners in the evaluated scope
- a relevant listener is `draining` or otherwise not `running`
- a relevant listener enters unsafe overload states such as `shedding` or `brownout`
- the last reload attempt is still marked failed

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
- code
- source
- outcome
- detail

This is the fastest way to understand whether a denied or failed admin action was caused by auth, permissions, rate limits, replay rejection, or a runtime apply failure.

For snapshot publication workflows, the same `detail` field should also be treated as rollout context. When a newly published snapshot changes route destination weights, the publish audit entry now includes the previous published version plus a compact diff summary such as which route changed and how its destination weights moved.

Reload audit entries publish machine-readable lifecycle codes such as `reload_started_in_place`, `reload_started_overlap_drain`, `reload_started_blocked_candidate`, `reload_applied_in_place`, `reload_applied_overlap_drain`, `reload_applied_overlap_drain_timeout`, `reload_failed_apply`, `reload_failed_rollback_preserved`, and `reload_failed_blocked_change`.

## Fleet Rollout Coordination

The current multi-node contract is exposed through the `lb-admin-api` library surface rather than a built-in `/fleet/*` HTTP endpoint in `lb-dataplane`.

Use `FleetRolloutCoordinator` when one control-plane workflow needs to coordinate rollout or rollback across multiple dataplane nodes while preserving explicit consistency tradeoffs.

Key fleet surfaces:

- `FleetRolloutRequest` and `FleetRollbackRequest`
- `FleetRolloutStrategy`: `immediate`, `sequential`, or `canary`
- `FleetConvergenceReport` with `converged`, `progressing`, `degraded`, and `diverged` states
- per-node `desired_version`, `active_version`, and convergence detail

The contract is `bounded_eventual`: the fleet is only considered converged when every targeted node reports the desired version and digest within the configured divergence budget.

### Staged Waves and Health Gates

Feature 05 extends the library contract with staged rollout planning and wave-level health gates.

Key staged planning surfaces:

- `FleetStagedRolloutRequest` and `FleetStagedRolloutPlan`
- `FleetRolloutWaveDefinition`
- `FleetHealthGatePolicy` (`required` and `best_effort` modes)
- `plan_staged_rollout(...)` validation for full node coverage and wave consistency

Key wave gate ingestion and evaluation surfaces:

- `FleetNodeBackend::fetch_health_signals(node_id, window_ms)`
- `collect_wave_health_signals(...)`
- `evaluate_wave_gate(...)` / `evaluate_wave_gate_with_policy(...)`
- `FleetWaveGateVerdict`: `passed`, `pending`, `failed`

### Abort and Automatic Rollback Semantics

Wave gate outcomes can now drive explicit abort and automatic rollback decisions:

- `FleetRolloutCoordinator::decide_wave_abort_and_rollback(...)`
- `FleetRolloutCoordinator::execute_auto_rollback_if_needed(...)`
- `FleetAbortRollbackDecision`
- `FleetAutoRollbackOutcome`

Current abort reasons are machine-readable:

- `wave_gate_failed`
- `wave_gate_timed_out`

When automatic rollback is enabled for a failed decision, rollback targets the shared last-known-good fleet version (`target_version: None` path in `FleetRollbackRequest`) and reports whether rollback converged.

### Rich Staged Status Surfaces

Feature 05 also adds dedicated status rendering for staged rollouts:

- `render_staged_status_surface(...)`
- `FleetStagedStatusSurface`
- `FleetWaveStatusSurface`
- `FleetNodeStatusSurface`

Wave status is machine-readable (`pending`, `in_progress`, `passed`, `failed`, `aborted`, `blocked`) and includes gate counters (`evaluated_nodes`, `failing_nodes`, `missing_nodes`) plus `degraded` and `timed_out` flags.

Fleet staged status includes high-level rollout state (`progressing`, `aborted`, `rolled_back`, `converged`, `degraded`) and rollback projection fields (`rollback_target_version`, `rollback_succeeded`).

Per-node status includes convergence state, mapped wave identity, and ingested gate signal when available.

### HTTP Surface Note

These staged fleet semantics are currently exposed as stable `lb-admin-api` library surfaces. A built-in `/fleet/*` endpoint in `lb-dataplane` is still additive future work.

## Reload Semantics

`POST /reload` applies the current config from disk only after it compiles successfully.

Important behavior:

- successful reloads return `configuration applied`
- failed reloads preserve the active runtime and return `500 Internal Server Error`
- overlap-and-drain listener replacement is used when a safe staged swap is possible
- if a replacement becomes active but an old listener exceeds its configured drain timeout, the reload still succeeds but surfaces a distinct drain-timeout outcome code and detail
- started reloads are recorded in audit before the apply finishes
- only one reload apply path executes at a time; later reload requests wait behind the active apply instead of interleaving listener mutation

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

When the HTTP peer transport is used, the transport also keeps a machine-readable last fan-out report with per-peer attempts, duplicate outcomes, and partition detection. That is the recommended control-plane surface for retry policy tuning and follow-up automation.

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

For the stable `/v1/*` contract, prefer the machine-readable `error.code` field over raw HTTP status text for automation.

## Recommended Operator Sequence

1. Call `/healthz` to confirm the admin plane is reachable.
2. Call `/readyz` to confirm the instance should receive new traffic.
3. Call `/validate` before mutating config.
4. Call `/reload` only after a clean preview.
5. Call `/status` to inspect listener replacement, reload, or overload state.
6. Call `/audit` after denied or failed actions to capture the exact reason.

## Next Step

Open [HTTP Cache](cache.md) for cache behavior and invalidation guidance, or open [Troubleshooting](troubleshooting.md) for failure-oriented workflows.