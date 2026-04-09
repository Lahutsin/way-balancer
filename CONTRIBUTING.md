# Contributing

## Development Baseline

Before opening a change, run:

```sh
./scripts/quality.sh
```

If the required developer tools are missing, install them explicitly and rerun the command.

## Change Scope

- Keep changes aligned to one feature document at a time.
- Do not mix unrelated infrastructure and product logic changes.
- Do not introduce `unsafe` code without an RFC and explicit review.
- Prefer bounded state and explicit failure handling over convenience abstractions.

## Required Gates

Every change should preserve:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `./scripts/check-coverage.sh` with at least 80% line coverage for every Rust source file under `crates/*/src` and `binaries/*/src`
- `cargo doc --workspace --no-deps`
- dependency and secret scanning where the necessary tools are available

## Repository Conventions

- Shared logic belongs in `crates/`.
- Thin entrypoints belong in `binaries/`.
- Integration tests belong in crate-local `tests/` directories.
- Long-running or release-oriented commands belong in `scripts/`.
- Security and release evidence should be reproducible from repository state.
