# Troubleshooting

## Scope

This page is the shortest path from a symptom to the right diagnostic endpoint or runbook. It focuses on the most likely operator problems in the current workspace mode.

## First Checks

When something feels wrong, start with these in order:

```sh
curl -H "Authorization: Bearer $LB_CTL_ADMIN_SECRET" http://127.0.0.1:9900/healthz
curl -H "Authorization: Bearer $LB_CTL_ADMIN_SECRET" http://127.0.0.1:9900/readyz
curl -H "Authorization: Bearer $LB_CTL_ADMIN_SECRET" http://127.0.0.1:9900/status
curl -H "Authorization: Bearer $LB_CTL_ADMIN_SECRET" http://127.0.0.1:9900/validate
curl -H "Authorization: Bearer $LB_CTL_ADMIN_SECRET" http://127.0.0.1:9900/audit
```

Those endpoints usually tell you whether the issue is liveness, serving readiness, auth, config, listener lifecycle, or runtime pressure.

Use them with this split:

- `GET /healthz`: the process is alive and serving the admin socket.
- `GET /readyz`: this instance should receive new traffic right now.
- `GET /status`: detailed listener, reload, and overload state.
- `GET /validate`: config preview before reload.
- `GET /audit`: recent admin-plane activity.

## Admin API Failures

| Symptom | Likely cause | What to check next |
| --- | --- | --- |
| `401 Unauthorized` | Missing or invalid bearer token, or bad signed request | Verify auth mode and credentials. |
| `403 Forbidden` | Source allow-list or permission policy blocked the action | Inspect `GET /audit` for the denied action and reason. |
| `409 Conflict` | Reused signed nonce | Check replay protection on the client side. |
| `429 Too Many Requests` | Admin rate limit exceeded | Reduce retry loops or adjust admin rate limits carefully. |
| `503 Service Unavailable` | Required signing secret missing or fail-closed prerequisite not met | Verify configured operator secrets and auth environment. |

Use [Admin API](admin-api.md) and [Admin Plane Hardening](runbooks/admin-plane-hardening.md) when you need the full contract.

## Validate Is Clean, But Reload Failed

If `GET /validate` succeeds and `POST /reload` still fails:

1. inspect `GET /audit` for the started and failed reload entries
2. inspect `GET /status` for `last_reload_result`
3. look at each listener’s `replacement` object

The most useful `replacement.state` values are:

- `stable`: no staged replacement in progress
- `replacement_draining`: the desired listener is active while an old one drains
- `failed_start_preserved`: the replacement start failed and the prior listener stayed active
- `drain_timeout_expired`: the replacement became active, but an old listener exceeded its configured drain timeout before finishing cleanly

If crash recovery is in play, also inspect `control_plane_journal.recovery.reconciled_listeners[*].reconciliation_verdict` in `GET /status`:

- `settled`: the affected listener is back to `running` plus `stable`
- `replacement_still_draining`: the listener is serving but replacement drain work is still visible
- `replacement_failed_preserved`: the active listener was preserved after replacement start failure
- `replacement_drain_timeout`: replacement stayed active but prior drain exceeded timeout
- `missing`: the recovered affected listener name is not present after restart and needs review
- `needs_review`: the post-restart state does not match any safer known bucket yet

If you need the fast aggregate answer first, check `control_plane_journal.recovery.reconciliation_summary.overall_verdict`:

- `settled`: every affected listener reconciled cleanly
- `replacement_still_draining`: only transitional drain work remains visible
- `replacement_failed_preserved` or `replacement_drain_timeout`: recovery found a bounded but non-clean replacement outcome
- `needs_review`: at least one affected listener is missing or otherwise outside the safer known buckets

Then use `control_plane_journal.recovery.reconciliation_summary.recommended_action` as the default next step:

- `observe_only`: no immediate remediation is suggested
- `wait_for_drain_completion`: keep watching until replacement drain work clears
- `validate_and_retry_reload`: re-run validation and a clean follow-up reload
- `investigate_drain_timeout`: inspect why the old listener failed to drain in time
- `investigate_stalled_drain`: the recovered overlap-and-drain operation is still draining after its expected completion window and should be investigated
- `investigate_and_validate_reload`: investigate the mismatch first, then validate and reload once the intent is clear

If you want the single operator-facing answer that also works for plain interrupted reloads, use `control_plane_journal.recovery.operator_guidance`:

- `recommended_action`: the current default next step across the whole recovery block
- `urgency`: `none`, `watch`, `action_required`, or `urgent`
- `operation_age_ms`: how long the recovered in-flight operation has been open according to the persisted start timestamp
- `expected_completion_within_ms`: the persisted expected completion window for overlap-and-drain recovery when one is known
- `exceeded_expected_completion`: `true` when the recovered operation age is already beyond that expected completion window

This is the safer field for automation that should not special-case whether `affected_listeners` existed in the recovered in-flight operation.

This is a rollback-safe behavior, not silent partial mutation.

## Cache Is Not Hitting Or Purge Did Not Work

### Low Cache Hit Rate

Check for:

- requests carrying `Authorization` or `Cookie`
- high-cardinality `vary_headers` or cache-key headers
- missing validators from the origin
- overly small TTL windows

### Purge Succeeded Locally But Not Everywhere

Check the purge response for:

- `degraded = true`
- non-zero `fanout_delivery_failure_count`
- non-empty `fanout_failed_targets`

That means the local node purged, but distributed convergence did not complete.

If the control plane keeps a `HttpCachePeerTransport` handle, inspect its last fan-out report as well:

- peers with `attempts > 1` indicate retry pressure
- peers with `result = failed` after retries indicate real degraded convergence
- `partition_detected = true` means you should treat the event as a partial-cluster issue, not a single local miss

## Fleet Rollout Is Mixed Across Nodes

Check whether the control plane fleet report says:

- `state = progressing`: the rollout is still within the bounded divergence budget
- `state = degraded`: at least one node failed or became unreachable
- `state = diverged`: the fleet stayed mixed beyond the configured divergence budget

Then inspect per-node `desired_version`, `active_version`, and convergence detail. The safe remediation path is usually to retry failed nodes or roll back the whole fleet to a shared known-good version.

### Cache Growth Or Churn Looks Wrong

Check whether:

- `max_entries` is too low
- `max_bytes` is too low
- `max_object_bytes` is too high for the workload

The deeper operational guidance lives in [HTTP Cache](cache.md), [Cache Operations](runbooks/cache-operations.md), and [Cache Performance](runbooks/cache-performance.md).

## Affinity Does Not Look Sticky

Check these questions in order:

1. Is the route actually using an upstream cluster with `traffic_policy.affinity` configured?
2. Is the expected header or cookie present on every request?
3. Is the preferred backend healthy, or is fallback correctly re-entering healthy selection?
4. Is the key distribution too skewed, making one backend look overloaded?

Common causes:

- missing cookie or header values
- expecting affinity on traffic that does not carry the configured key
- backend health changes causing healthy fallback
- using affinity for traffic that is not truly stateful

See [Affinity](affinity.md) for deployment guidance and trade-offs.

## Requests Are Being Rejected Or Shed

If public traffic is being rejected or looks degraded under load:

1. inspect `GET /status`
2. look at `recent_overload_events`
3. inspect each listener’s `overload_state`, `shed_connections`, and `brownout_features`

Typical causes:

- concurrency or rate-limit saturation
- overload protection transitioning state
- source or protocol protection rejecting malformed or suspicious traffic
- listener admission pressure during spikes

This is one of the strongest signals that you should inspect telemetry and the observability runbook, not just retry the request path blindly.

## Use The Right Runbook

| Topic | Best next document |
| --- | --- |
| admin auth, replay, source policy | [Admin Plane Hardening](runbooks/admin-plane-hardening.md) |
| config preview and reload safety | [Config Safety Workflow](runbooks/config-safety-workflow.md) |
| cache policy and purge behavior | [Cache Operations](runbooks/cache-operations.md) |
| distributed invalidation | [Cache Invalidation](runbooks/cache-invalidation.md) |
| active-active fleet rollout | [Multi-Node Topology](runbooks/multi-node-topology.md) |
| listener replacement and rollback | [Upgrade And Rollback Policy](runbooks/upgrade-rollback-policy.md) |
| soak, chaos, and failure visibility | [Soak And Chaos Failure Injection](runbooks/soak-chaos-failure-injection.md) |
| observability stack and diagnostics | [Observability Stack](runbooks/observability-stack.md) |

## Escalation Path

When the fast checks are not enough:

1. capture `GET /status` and `GET /audit`
2. capture the relevant config and `GET /validate` output
3. capture overload and cache diagnostics from telemetry or support bundles
4. then move into the deeper runbook for the affected subsystem