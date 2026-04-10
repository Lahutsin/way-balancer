# Config Safety Workflow

## Purpose

This runbook defines the safe operator workflow for validating, previewing, applying, and rolling back workspace config changes.

## Validate Before Apply

For `lb-dataplane serve --config ...`, use the admin listener before `POST /reload`:

```sh
curl -H "Authorization: Bearer $LB_CTL_ADMIN_SECRET" http://127.0.0.1:9900/validate
```

`GET /validate` performs a dry-run against the current config file on disk and returns:

- the active compiled snapshot, when one is already running
- the candidate compiled snapshot preview
- the snapshot diff between active and candidate configs
- semantic warnings for risky listener, route, upstream, or security posture changes
- apply behavior preview, including blocked same-bind protocol or class swaps

This endpoint is the primary preflight for operators editing a config in place.

For the checked-in localhost and Docker Compose bearer-auth examples, the same admin listener also exposes `GET /status`, `GET /healthz`, and `GET /audit`. Use `GET /audit` after a rejected reload or denied action to confirm who attempted the operation and why it was blocked.

## Warning Semantics

Warnings are not hard failures. They are rollout advisories for changes that are syntactically valid but operationally meaningful.

Current warning classes include:

- listener topology changes
- route table changes
- upstream cluster changes
- security posture changes
- blocked same-bind protocol or class swaps that reload will reject

Treat warnings as a required review gate, not a best-effort hint.

## Apply Behavior

Use reload only after a clean validate preview:

```sh
curl -X POST -H "Authorization: Bearer $LB_CTL_ADMIN_SECRET" http://127.0.0.1:9900/reload
```

The current serve-mode apply path is rollback-safe in these ways:

- the candidate config is fully parsed, validated, and compiled before apply
- new listeners are started before old listeners are retired
- if reload fails before the swap completes, the active runtime stays unchanged
- same-bind protocol or listener-class swaps are rejected instead of risking a partial in-place rebind

This means a failed reload should be treated as a rejected candidate, not as a partially applied rollout.

If a reload is rejected because of authz, source policy, replay detection, or rate limiting, inspect `GET /audit` before retrying. That gives you the exact admin-plane outcome instead of inferring it only from the HTTP status code.

## Rollback Workflow

If a validated candidate still proves undesirable after apply:

1. Restore the previously known-good config file.
2. Run `GET /validate` again and confirm the preview matches the expected rollback snapshot.
3. Run `POST /reload` to return the process to the prior state.
4. Confirm with `GET /status` and live probes.

Because the active snapshot metadata includes the current digest and API version, operators can compare the rollback candidate against the running state before applying it.

## Version And Compatibility Strategy

Config compatibility is anchored on snapshot metadata:

- `api_version` must be supported by the current binary
- snapshot compilation must succeed against the current snapshot format version
- unsupported version jumps fail during validate or compile preview rather than during listener mutation

The current migration strategy is strict compatibility, not live auto-migration. Upgrade or rollback between versions should therefore follow this order:

1. Deploy the binary that understands the target config schema.
2. Run `GET /validate` against the candidate config.
3. Apply with `POST /reload` only after the preview is clean.
4. For rollback, restore the prior config and repeat the same validate then reload sequence.

## Operational Notes

- `GET /status` remains the runtime state endpoint.
- `GET /validate` is the preflight and diff endpoint.
- `GET /audit` is the recent admin activity endpoint and is especially useful after denied reload attempts.
- `POST /reload` is the only state-mutating config action.
- A successful validate preview does not replace post-apply smoke checks; it only reduces rollout risk before mutation.