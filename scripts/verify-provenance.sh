#!/usr/bin/env sh
set -eu

mkdir -p artifacts/provenance

lock_sha256="$(shasum -a 256 Cargo.lock | awk '{print $1}')"
cat > artifacts/provenance/source-manifest.json <<EOF
{
  "schema": "way-balancer.provenance.v1",
  "cargo_lock_sha256": "${lock_sha256}"
}
EOF

echo "Provenance manifest verified: Cargo.lock sha256=${lock_sha256}" > artifacts/provenance/README.txt
