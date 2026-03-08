# Drivechain Staged Rollout Plan

This plan defines rollout phases for production-grade Drivechain activation.

## Phase 0: Pre-Release Gate

Entry criteria:
- Drivechain production gates in `PRODUCTION_READINESS.md` are complete.
- CI green on build + drivechain functional tests.
- Release checksums and SBOM generated.
- Public signet bootstrap configuration is published (`challenge`, canonical seed
  nodes, bootstrap instructions).

Exit criteria:
- Candidate build signed and archived.

## Phase 1: Private Canary

Scope:
- Small operator set, isolated infrastructure, limited economic exposure.

Checks:
- Startup/restart behavior across upgrades.
- Reorg handling and state snapshot fallback.
- RPC rejection reason stability.

Duration:
- Minimum 7 days continuous operation.

Exit criteria:
- No unresolved SEV-1/SEV-2 issues.

## Phase 2: Public Testnet/Signet Burn-In

Scope:
- Public nodes and miners, broader adversarial surface.

Checks:
- Commit/vote/execute flow under real network conditions.
- Mempool conflict and replacement behavior.
- Monitoring/alerting coverage and paging path.
- Seed-node and miner diversity remain healthy across independent operators.

Duration:
- Minimum 14 days continuous operation.

Exit criteria:
- No unresolved consensus or escrow-safety defects.
- External review feedback triaged and resolved.
- Burn-in evidence is archived in `doc/drivechain/PUBLIC_SIGNET_RUNBOOK.md`.

## Phase 3: Mainnet Guarded Launch

Scope:
- Progressive enablement by operator cohort.

Controls:
- Canary-first miner participation.
- Explicit go/no-go checkpoint every 24 hours for first week.
- Fast rollback readiness with pre-validated backups.

Exit criteria:
- Stable operation through initial vote window period.
- Incident response drill completed successfully.

## Phase 4: General Availability

Requirements:
- Publish post-launch report with:
  - issues found,
  - mitigations shipped,
  - remaining risks and owner.
