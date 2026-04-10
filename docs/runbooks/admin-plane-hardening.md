# Admin Plane Hardening

## Purpose

This runbook defines the operator-facing security model for the privileged admin listener used by `lb-dataplane serve --config ...`.

## Supported Admin Auth Models

The admin listener supports two explicit auth modes:

- `bearer`: legacy shared bearer secret resolved from an environment variable such as `LB_CTL_ADMIN_SECRET`
- `signed_headers`: stronger per-operator request signing with explicit permissions and replay resistance

For production exposure, prefer `signed_headers`. The bearer mode remains useful for localhost-only or tightly isolated bootstrap environments, but it does not give per-operator attribution.

## Signed Header Contract

When `listeners[].admin.auth.mode = "signed_headers"`, each request must include:

- `x-lb-admin-actor`
- `x-lb-admin-timestamp`
- `x-lb-admin-nonce`
- `x-lb-admin-signature`

The signature is computed over this exact payload shape:

```text
actor
method
target
timestamp
nonce
```

The runtime validates:

- the operator identity exists in config
- the operator has the required permission for the requested action
- the timestamp is within the configured clock-skew allowance
- the nonce has not already been used inside the configured replay window
- the request signature matches the operator secret
- the referenced operator secret is configured; missing secrets fail closed with `503 Service Unavailable` rather than silently falling back to an empty key

`GET /status`, `GET /validate`, and `GET /healthz` require `read` permission. `GET /audit` requires `audit` permission. `POST /reload` requires `write` permission.

## Source Policy And Rate Limiting

Each admin listener can additionally enforce:

- `allowed_source_cidrs`: source-address allow-list before auth is evaluated
- `rate_limit.requests_per_minute`
- `rate_limit.burst`

The source allow-list runs before auth is evaluated. Rate limiting is then applied after successful auth and keyed by authenticated identity plus source address, so anonymous failures do not consume the same bucket as a valid operator sharing that egress IP. Rejected sources return `403 Forbidden`. Rate-limited operators return `429 Too Many Requests`.

## Audit Visibility

Sensitive and rejected admin actions are retained in an in-memory bounded audit log configured by `admin.audit.max_retained_events`.

For the default bearer-auth localhost flow, use:

```sh
curl -H "Authorization: Bearer $LB_CTL_ADMIN_SECRET" http://127.0.0.1:9900/audit
```

or the signed equivalent to inspect recent admin actions. Audit entries include:

- request identifier
- listener name
- actor
- auth mode
- action
- source address
- outcome
- detail

This gives operators direct visibility into successful reloads, denied writes, replay rejections, rate limiting, and source-policy denials.

## Recommended Production Posture

Use this baseline unless you have a narrower local-only deployment:

1. Bind the admin listener to a non-public or localhost-only address.
2. Prefer `signed_headers` with separate read, audit, and write operators.
3. Restrict admin access further with `allowed_source_cidrs`.
4. Keep audit retention large enough to preserve recent operator activity during incident review.
5. Treat bearer mode as transitional or local-only unless compensating controls are strong.

## Validation Coverage

Focused admin-plane regression coverage currently includes:

- signed read-versus-write authorization boundaries
- dedicated audit-permission enforcement for `GET /audit`
- nonce replay rejection
- fail-closed handling when an operator secret is missing
- source allow-list enforcement
- post-auth identity-based rate limiting enforcement
- audit log retrieval for denied privileged actions

Run the targeted suite with:

```sh
cargo test -p lb-dataplane workspace_serve -- --nocapture
```