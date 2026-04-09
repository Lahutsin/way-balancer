#!/usr/bin/env sh
set -eu

if command -v gitleaks >/dev/null 2>&1; then
  gitleaks detect --config .gitleaks.toml --no-banner --redact
else
  echo "gitleaks not installed; skipping secret scan" >&2
fi
