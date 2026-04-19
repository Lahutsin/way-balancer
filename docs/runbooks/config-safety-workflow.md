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

For the checked-in localhost and Docker Compose bearer-auth examples, the same admin listener also exposes `GET /healthz`, `GET /readyz`, `GET /status`, and `GET /audit`. Use `GET /audit` after a rejected reload or denied action to confirm who attempted the operation and why it was blocked.

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

## Reload Targets

The current operator target is:

- treat in-place reload and overlap-and-drain replacement as rollback-safe by default
- treat zero-drop for already accepted connections as the target outcome during normal replacement, not a promise under every disruptive or stalled-drain case
- use `reload_last_duration_ms`, `reload_last_success_duration_ms`, `reload_last_failure_duration_ms`, and `reload_max_duration_ms` as the primary live signals for whether reload latency is staying within your environment budget
- investigate any `reload_applied_overlap_drain_timeout` outcome as degraded success, even if the replacement stayed active

This repository does not yet publish a hard global millisecond SLO for every environment. The current contract is that reload latency and degraded-success cases are surfaced explicitly so operators can set environment-specific alert thresholds without inferring from free-form text.

The current serve-mode apply path is rollback-safe in these ways:

- the candidate config is fully parsed, validated, and compiled before apply
- new listeners are started before old listeners are retired
- supported bind or protocol changes are staged through overlap-and-drain replacement when the new listener can bind on a fresh socket first
- if reload fails before the swap completes, the active runtime stays unchanged
- same-bind protocol or listener-class swaps are rejected instead of risking a partial in-place rebind

This means a failed reload should be treated as a rejected candidate, not as a partially applied rollout.

If a reload is rejected because of authz, source policy, replay detection, or rate limiting, inspect `GET /audit` before retrying. That gives you the exact admin-plane outcome instead of inferring it only from the HTTP status code.
If a reload is accepted and needs overlap-and-drain replacement, `GET /audit` records a `started` entry before apply completes, and `GET /status` shows which listener is desired, which prior listener is draining, whether a failed replacement start was preserved, and whether an old listener exceeded its configured drain timeout.
If that drain timeout expires after the replacement is already active, treat the reload as a degraded success rather than a rollback failure: `GET /status` and `GET /audit` surface a dedicated drain-timeout outcome code instead of the clean overlap-and-drain success code.
If operators submit repeated reloads while one apply is still running, the runtime serializes them through a single reload guard. Later requests wait behind the active apply rather than interleaving listener mutation.
If a reload fails, `GET /readyz` becomes the fast serving-readiness signal that the instance should stop receiving new traffic until the operator either restores a known-good config and reloads successfully or otherwise clears the failed state.
After a later successful reload, the runtime clears that prior failed readiness/reload state and replaces it with the new success outcome. Operators should therefore always trust the latest `last_reload_outcome_code`, `last_reload_result`, and `GET /readyz` response rather than caching an older failure.

## Rollback Workflow

If a validated candidate still proves undesirable after apply:

1. Restore the previously known-good config file.
2. Run `GET /validate` again and confirm the preview matches the expected rollback snapshot.
3. Run `POST /reload` to return the process to the prior state.
4. Confirm with `GET /status` that listener `replacement.state` has returned to `stable` and that no unexpected `draining` entries remain.
5. Confirm with live probes.

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
- `GET /healthz` is liveness only.
- `GET /readyz` is the serving-readiness endpoint.
- `GET /status` now includes per-listener replacement lifecycle data under `replacement`, including `state`, `desired`, `draining`, recent retired identities, and any preserved failed-start detail.
- `GET /status` now also includes rolled-up `readiness`, `reload_health`, `last_reload_outcome_code`, and reload duration metrics (`reload_total_duration_ms`, `reload_max_duration_ms`, `reload_last_duration_ms`, `reload_last_success_duration_ms`, `reload_last_failure_duration_ms`).
- `GET /validate` is the preflight and diff endpoint.
- `GET /audit` is the recent admin activity endpoint and is especially useful after denied reload attempts or while a replacement-capable reload is still in progress. Reload entries now include machine-readable `code` values for blocked candidate changes, overlap-and-drain success, rollback-preserved failure, and generic apply failure.
- `POST /reload` is the only state-mutating config action.
- A successful validate preview does not replace post-apply smoke checks; it only reduces rollout risk before mutation.