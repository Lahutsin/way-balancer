#!/usr/bin/env sh
set -eu

compatibility_doc="docs/runbooks/compatibility-matrix.md"
upgrade_doc="docs/runbooks/upgrade-rollback-policy.md"
dr_doc="docs/runbooks/disaster-recovery.md"
evidence_doc="docs/runbooks/release-evidence-checklist.md"
ga_template="docs/runbooks/ga-readiness-review-template.md"
inventory_doc="artifacts/release-evidence-inventory.md"
sbom_doc="artifacts/sbom/README.md"
provenance_doc="artifacts/provenance/README.md"

test -f "$compatibility_doc"
test -f "$upgrade_doc"
test -f "$dr_doc"
test -f "$evidence_doc"
test -f "$ga_template"
test -f "$inventory_doc"
test -f "$sbom_doc"
test -f "$provenance_doc"

grep -q '^# Compatibility Matrix$' "$compatibility_doc"
grep -q '^## Skew Policy$' "$compatibility_doc"
grep -q 'Security Patch Process' "$compatibility_doc"
grep -q 'check-release-artifacts.sh' "$compatibility_doc"

grep -q '^# Upgrade and Rollback Policy$' "$upgrade_doc"
grep -q '^## Upgrade Flow$' "$upgrade_doc"
grep -q '^## Rollback Flow$' "$upgrade_doc"
grep -q 'upgrade_rollback_smoke' "$upgrade_doc"
grep -q 'insecure_dev_mode' "$upgrade_doc"

grep -q '^# Disaster Recovery and Restore Validation$' "$dr_doc"
grep -q '^## Backup Flow$' "$dr_doc"
grep -q '^## Restore Flow$' "$dr_doc"
grep -q '^## Restore Validation Checklist$' "$dr_doc"
grep -q 'credential' "$dr_doc"
grep -q 'snapshot_restore_smoke' "$dr_doc"

grep -q '^# Release Evidence Checklist$' "$evidence_doc"
grep -q '^## Required Evidence$' "$evidence_doc"
grep -q '^## Release Candidate Sign-Off Checklist$' "$evidence_doc"
grep -q 'EVID-008' "$evidence_doc"

grep -q '^# GA Readiness Review Template$' "$ga_template"
grep -q '^## Evidence Inventory$' "$ga_template"
grep -q 'go_with_exceptions' "$ga_template"
grep -q 'EVID-008' "$ga_template"

grep -q '^# Release Evidence Inventory$' "$inventory_doc"
grep -q 'EVID-001' "$inventory_doc"
grep -q 'EVID-008' "$inventory_doc"
grep -q 'ga-readiness-review-template.md' "$inventory_doc"

for evid in EVID-001 EVID-002 EVID-003 EVID-004 EVID-005 EVID-006 EVID-007 EVID-008; do
	grep -q "$evid" "$evidence_doc"
	grep -q "$evid" "$ga_template"
	grep -q "$evid" "$inventory_doc"
done