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

## Route Matching Does Not Behave As Expected

## WebSocket Upgrade Fails

If a WebSocket client gets a local `400 Bad Request` before the request reaches upstream, check these first:

- the matched route or listener explicitly allows `upgrade.protocols: ["websocket"]`
- the request uses HTTP/1.1, not HTTP/2
- the request includes both `Connection: Upgrade` and `Upgrade: websocket`
- the request is a `GET` without an HTTP request body

Current support boundary is narrow by design:

- supported: HTTP/1.1 WebSocket upgrade on `public` `http1` listeners
- supported: HTTP/1.1 WebSocket upgrade on `public` `https` listeners when ALPN negotiates HTTP/1.1
- not supported: admin listeners
- not supported: non-WebSocket upgrade protocols
- not supported: HTTP/2 extended CONNECT or RFC 8441-style WebSocket bootstrapping

If the route is allowed but the upstream still refuses the handshake, reproduce with a minimal request and verify the upstream returns `101 Switching Protocols` with both `Connection: Upgrade` and `Upgrade: websocket`.

If a request seems to land on the wrong route or gets a local `403` unexpectedly, check the matcher layers in this order:

1. path prefix
2. hostname
3. method
4. header matchers
5. query-parameter matchers
6. content-type
7. effective client IP against `source_cidrs`

If the route itself is correct but a canary or blue-green split does not seem to follow the expected destination weights, inspect both rollout-time and runtime-time visibility:

1. inspect snapshot publication diff or publish audit detail to confirm the intended weight shift actually landed
2. reproduce one request through the runtime harness and inspect `Http1ConnectionReport.route_selection_metrics` or `Http2ConnectionReport.route_selection_metrics`
3. confirm `route_destination_selection_counts` and `route_destination_fallback_count` match the intended behavior

Use the fallback count to distinguish two different problems quickly:

- `route_destination_fallback_count = 0`: the route destination policy is being applied without route-level failover
- `route_destination_fallback_count > 0`: the runtime is bypassing a higher-priority destination because that destination pool had no eligible backend

Common causes:

- request host does not match the normalized `Host` or `:authority` value you expected
- method filter is declared, but the client uses a different verb
- header exact matcher fails because the value differs after trimming
- query matcher fails because the parameter is missing or percent-encoding differs from what you assumed
- content-type matcher is checking the media type only, but the request sends a different media type than expected
- route-level source CIDRs are matching against the raw peer address because trusted forwarding was not configured

### Effective Client IP Looks Wrong

If source-based routing or blocking behaves incorrectly:

1. verify whether `security.trusted_client_ip.enabled` is set
2. confirm which address is acting as the immediate peer for trust evaluation: raw socket peer without Proxy Protocol, or Proxy Protocol source when `listeners[].proxy_protocol` is enabled
3. confirm the forwarded chain is syntactically valid
4. confirm the route `source_cidrs` include the effective client IP you actually want to match

If the peer is not trusted, forwarded headers are ignored or rejected by design. In that case, route-level source matching evaluates the direct socket source.

Header precedence is deterministic:

1. direct socket peer, unless Proxy Protocol is enabled
2. Proxy Protocol source, when the listener requires `v1` or `v2`
3. trusted `Forwarded`
4. trusted `X-Forwarded-For` when `Forwarded` is absent

That same effective source is also what public-listener `hostile_edge_protection.source_quota` uses. If source quota looks like it is throttling every request as one shared proxy IP, check Proxy Protocol configuration first.

On dual-stack listeners, IPv4 clients can arrive on the IPv6 socket as IPv4-mapped IPv6 addresses such as `::ffff:198.51.100.7`. The runtime now canonicalizes those back to plain IPv4 before:

- trusted proxy CIDR checks
- route `source_cidrs` matching
- anonymous-source CIDR checks
- hostile-edge and enumeration source aggregation such as `ipv4_subnet_24`

If source policy still looks wrong on a dual-stack listener, compare the configured CIDRs against the canonical IPv4 client address, not the mapped `::ffff:` presentation.

If the listener sits behind an L4 load balancer, also confirm that `listeners[].proxy_protocol` matches what the fronting hop actually sends. A listener configured for `v1` or `v2` will fail closed before HTTP parsing if the preface is absent or malformed.

Quick check for a v1-enabled HTTP/1 listener:

```sh
printf 'PROXY TCP4 198.51.100.7 203.0.113.10 45678 8080\r\nGET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n' | nc 127.0.0.1 8080
```

### Route Specificity Rules

Current precedence is:

1. longest path prefix wins first
2. for equal prefixes, a route with hostname filters wins over one without
3. for equal prefixes and hostname specificity, a route with method filters wins over one without
4. for equal earlier dimensions, routes with more header, query, content-type, and source constraints win over less specific routes

Keep overlapping routes intentionally ordered by specificity rather than relying on declaration order.

### Fast Reproduction Tip

When debugging one route in isolation, send the request with every declared matcher visible in the curl command. For example:

```sh
curl \
	-H 'Host: example.com' \
	-H 'X-Tenant: beta' \
	-H 'Content-Type: application/json; charset=utf-8' \
	-H 'X-Forwarded-For: 198.51.100.7' \
	'http://127.0.0.1:8080/api?auth=user'
```

If source matching is involved, remember that `X-Forwarded-For` only affects routing when the direct peer is configured as trusted.

### Transformed Headers Or Rewrites Look Wrong

Check the effective ordering before assuming the matcher or upstream is broken:

1. route matching happens on the original downstream request
2. request transforms run only after a route has already been selected
3. cache lookup uses the transformed request shape
4. response transforms change the downstream response headers, but the HTTP/1 cache stores the normalized origin headers and reapplies the effective response transform on cache hit

Common causes:

- expecting a path rewrite to influence which route wins
- mutating a request header and then checking the upstream with the pre-transform value
- expecting a cached response entry to preserve the already transformed header set from an earlier route or listener
- trying to mutate restricted framing or hop-by-hop headers that validation rejects by design

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
| route matching and request classification | [Configuration](configuration.md) |
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