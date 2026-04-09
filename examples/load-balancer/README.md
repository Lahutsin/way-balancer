# Load Balancer Configuration Examples

These examples target the typed JSON configuration accepted by `lb_config_model::WorkspaceConfig`.

## Files

- `basic-http.json`: minimal HTTP/1.1 edge listener with a single upstream cluster and a conservative public-cache policy
- `http-cache-public.json`: public HTTP example with a named shared-cache policy and route-level cache binding
- `docker-compose-public-admin.json`: container-friendly public plus admin listeners for `docker compose up` with cache enabled on the public route
- `grpc-retries.json`: HTTP/2 or gRPC-style listener with retry-budget policy wiring
- `https-termination.json`: HTTPS listener with file-backed TLS termination material and a conservative public-cache policy
- `public-admin.json`: public application listener plus a separate admin TCP listener, with cache enabled on the public route
- `local-dev-insecure.json`: development-only example showing explicit insecure override gating

## Important Note

These files model the configuration document only. Snapshot publication metadata such as artifact attestation is part of the control-plane publish flow and is not embedded inside the config JSON itself.

The `security.artifact_verification.trusted_signers` arrays are left empty on purpose in the checked-in examples. Production control-plane workflows should populate them with Ed25519 public keys for the signer identities allowed to publish snapshots.

Examples that keep `security.artifact_verification.mode` set to `enforced` are intentionally not self-sufficient artifacts. They validate as configuration documents, but real publication and rollout still require signer injection from the control plane or operator workflow.

The HTTPS example uses file paths for PEM certificate and key material. Those files are operator-provided deployment inputs rather than repository fixtures.

The Docker Compose example binds `0.0.0.0` explicitly and points at a fixed backend IP on the compose network so the current `SocketAddr`-based upstream model can resolve the demo backend without extra service discovery. The admin listener is intended to be used only with `LB_CTL_ADMIN_SECRET` bearer authorization, and the compose file publishes port `9900` on `127.0.0.1` only.

The cache example is intentionally conservative for a shared cache: it limits methods to `GET` and `HEAD`, keeps `allow_set_cookie_storage` disabled, enables validator-based revalidation, and uses bounded in-memory storage. Cookie-bearing requests still bypass the shared cache at runtime even if the config itself does not mention cookies.

## Validation

The repository validates these examples with:

```sh
cargo test -p lb-test-support --test example_configs
```