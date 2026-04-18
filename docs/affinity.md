# Affinity

## Scope

way-balancer supports deterministic upstream affinity for stateful workloads through `upstream_clusters[].traffic_policy.affinity`.

The current surface is intentionally narrow:

- `header_hash`
- `cookie_hash`
- explicit fallback through `balance_healthy`

This is enough to support sticky-session-style workloads without pretending affinity is always the right answer.

## Example

The checked-in `sticky-sessions-cookie.json` example uses cookie-based affinity:

```json
{
  "name": "session-app",
  "traffic_policy": {
    "algorithm": "round_robin",
    "locality": "disabled",
    "no_healthy_fallback": "fail",
    "affinity": {
      "type": "cookie_hash",
      "cookie_name": "session_id",
      "fallback": "balance_healthy"
    }
  }
}
```

## Supported Modes

### `header_hash`

Use when an upstream identity is already carried in a stable request header such as a tenant key or authenticated user identifier.

### `cookie_hash`

Use when the application already owns a stable session cookie and you want deterministic backend stickiness for that cookie value.

## Selection Semantics

The runtime behavior is intentionally conservative:

1. If there is no configured affinity policy, normal selection runs.
2. If the configured header or cookie is missing, normal selection still runs.
3. If a deterministic preferred endpoint is available and healthy, the request stays pinned there.
4. If the preferred endpoint is unhealthy or ejected, `fallback: balance_healthy` re-enters healthy selection rather than pinning to a dead backend.

The healthy fallback rule is important. It means affinity is advisory only while the preferred target remains viable.

## Interaction With Other Selection Logic

Affinity does not replace the rest of upstream selection. It sits alongside:

- endpoint health
- locality preference
- the underlying balancing algorithm
- no-healthy fallback behavior

The runtime first narrows viable candidates, then applies deterministic affinity selection, then falls back when necessary.

## When Affinity Helps

Affinity is a good fit when:

- the application keeps state in-memory or in process-local caches
- session churn is moderate and key distribution is reasonably even
- occasional healthy fallback is acceptable during failures

## When Affinity Hurts

Affinity can make the system worse when:

- one tenant or session dominates traffic
- workloads are not actually stateful
- the chosen key has extremely high skew
- you expect affinity to override health or overload protection

The main risk is hot-spot amplification. Sticky behavior does not create capacity; it only biases where requests land.

## Practical Guidance

### Choose Stable Keys

Good keys:

- session identifiers
- tenant identifiers
- authenticated user IDs with sane distribution

Bad keys:

- timestamps
- request IDs
- ad-hoc headers that are frequently absent

### Roll Out Conservatively

Start with one stateful route, verify behavior, then expand. Do not enable affinity across unrelated traffic classes by default.

### Expect Fallback During Failures

A request that used to land on one backend may move during failures or ejection events. That is the intended safety behavior.

## Validation And Testing

The repository already includes focused coverage for:

- deterministic selection in the upstream balancer
- unhealthy fallback behavior
- HTTP/1 cookie-based extraction
- HTTP/2 header-based extraction

The checked-in example config is validated by `cargo test -p lb-test-support --test example_configs`.

## Related Pages

- [Configuration](configuration.md) for the typed config surface
- [Troubleshooting](troubleshooting.md) for affinity-not-sticky diagnostics
- [Stability Contract](runbooks/stability-contract.md) for current maturity and boundary expectations