# TLS Operations

## Scope

This runbook describes the HTTPS listener TLS controls currently supported by `lb-dataplane serve`.

## Supported Listener TLS Policy

For `protocol: "https"`, the `tls_termination` block supports:

- `certificate_source`: default certificate and private key loaded from files.
- `certificate_source.ocsp_path`: optional stapled OCSP response loaded from a DER file.
- `sni_certificates`: additional file-backed certificates selected by SNI host name.
- `minimum_version`: `tls12` or `tls13`.
- `alpn_protocols`: ordered ALPN advertisement policy, currently `http2` and `http11`.
- `session_resumption.mode`: `disabled`, `stateful`, `tickets`, or `hybrid`.
- `session_resumption.session_cache_size`: in-memory cache size for modes that use stateful resumption.
- `session_resumption.tls13_ticket_count`: number of TLS 1.3 tickets issued for modes that use tickets.

## Certificate Rotation

Certificate rotation is handled by config reload on stable listeners.

1. Write the new certificate, key, and optional OCSP response files to disk.
2. Update the workspace config paths if the rotated material uses new file names.
3. Call the admin reload endpoint.
4. Confirm listener status remains healthy and run an HTTPS probe against the intended SNI host names.

Because HTTPS listeners rebuild their `rustls` config on reload, default certificates, SNI certificates, ALPN policy, and session resumption policy all move to the new configuration atomically for that listener.

## SNI Operations

Use `sni_certificates` when one HTTPS bind address must terminate certificates for multiple host names.

1. Keep `certificate_source` populated with a valid default fallback certificate.
2. Add one `sni_certificates` entry per certificate bundle.
3. List all covered host names under `server_names`.
4. Reload the config and probe each host name with SNI enabled.

Duplicate or syntactically invalid SNI names are rejected during config validation.

## Session Resumption Guidance

- Use `disabled` if the edge should avoid all resumption state.
- Use `stateful` if resumption must remain local to process memory.
- Use `tickets` if stateless resumption is preferred and ticket issuance is acceptable.
- Use `hybrid` for the broadest compatibility and best hit-rate.

`stateful` and `hybrid` require a non-zero `session_cache_size`.
`tickets` and `hybrid` require a non-zero `tls13_ticket_count`.

## OCSP Stapling Guidance

If `ocsp_path` is configured, the listener reads the DER response during config load and staples it with the associated certificate.

1. Refresh the OCSP response file before it expires.
2. Keep the response file colocated with the matching certificate material.
3. Reload the config after updating the OCSP file.

An empty `ocsp_path` is rejected during config validation.