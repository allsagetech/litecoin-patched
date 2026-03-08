# Drivechain Production Readiness Gates

This document defines the required production gates for Drivechain deployments
from this repository.

Status model:
- `ENFORCED`: Checked by CI or static policy in-repo.
- `MANUAL`: Requires release-manager sign-off and evidence links.

## Gate Matrix

1. Spec freeze
- Requirement: Drivechain spec status is `Final`, and implemented tags/flows are
  documented.
- Status: `ENFORCED`
- Evidence: `doc/drivechain/LIP-drivechain.md`

2. Consensus + mempool test coverage
- Requirement: Drivechain unit + functional test suite passes in CI.
- Status: `ENFORCED`
- Evidence: `.github/workflows/build-release.yaml`

3. Reorg/restart safety coverage
- Requirement: Activation boundary, reorg deactivation, rollback, restart-state tests pass.
- Status: `ENFORCED`
- Evidence: `drivechain_softfork_*`, `drivechain_reorg_*`, `drivechain_restart_*`

4. Ownership/registration conflict coverage
- Requirement: Register auth, duplicate ID, mempool conflict, and confirmation ordering tests pass.
- Status: `ENFORCED`
- Evidence: `drivechain_register_*`, `drivechain_owner_auth_*`

5. Fuzz harness availability
- Requirement: Drivechain script parser/builders are fuzzed.
- Status: `ENFORCED`
- Evidence: `src/test/fuzz/drivechain_script.cpp`

6. Sanitizer matrix availability
- Requirement: TSan, MSan, ASan/UBSan, and fuzz sanitizer jobs exist in CI configuration.
- Status: `ENFORCED`
- Evidence: `.cirrus.yml`

7. Release integrity artifacts
- Requirement: Release artifacts include checksums and SBOM.
- Status: `ENFORCED`
- Evidence: `.github/workflows/build-release.yaml`, `contrib/devtools/generate_spdx_sbom.py`

8. Signed release checksums
- Requirement: `SHA256SUMS.asc` is produced when a release signing key is configured.
- Status: `ENFORCED`
- Evidence: `.github/workflows/build-release.yaml`

9. Incident + rollback runbooks
- Requirement: Chain split, rollback, and owner key compromise procedures are documented.
- Status: `ENFORCED`
- Evidence: `doc/drivechain/INCIDENT_RESPONSE_RUNBOOK.md`

10. Staged rollout plan
- Requirement: Testnet/canary/mainnet phased rollout plan is documented.
- Status: `ENFORCED`
- Evidence: `doc/drivechain/STAGED_ROLLOUT_PLAN.md`

11. Public signet burn-in
- Requirement: Drivechain commit/vote/execute flow is validated on the designated
  public signet with published bootstrap configuration and independent seed/miner
  operators.
- Status: `MANUAL`
- Evidence: `doc/drivechain/PUBLIC_SIGNET_RUNBOOK.md`

12. External security review sign-off
- Requirement: Independent review and unresolved findings log.
- Status: `MANUAL`
- Evidence template: `doc/drivechain/EXTERNAL_SECURITY_SIGNOFF.md`

13. Security response program / bounty
- Requirement: Public reporting path and bounty policy are declared.
- Status: `MANUAL`
- Evidence template: `doc/drivechain/EXTERNAL_SECURITY_SIGNOFF.md`

## Release Manager Completion Rule

A production release is considered ready when:
- All `ENFORCED` gates pass in CI.
- All `MANUAL` gates are completed and signed in
  `doc/drivechain/EXTERNAL_SECURITY_SIGNOFF.md`.
