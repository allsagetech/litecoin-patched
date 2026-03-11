# Drivechain Security Review Checklist

Use this checklist before public testnet/mainnet deployment.

## Consensus Correctness

- Verify `CheckDrivechainBlock` and `DrivechainState::ConnectBlock` reject/accept identically for:
  - DEPOSIT / BUNDLE_COMMIT / VOTE / EXECUTE
  - REGISTER policy-hash binding
  - Reorg edge cases and same-block ordering edge cases
- Verify activation boundary behavior on both forward activation and reorg deactivation.
- Verify vote window, approval threshold, and expiration schedule invariants.
- Verify deposit and execute cap failures match between mempool policy and block validation.

## Ownership / Authorization

- Confirm REGISTER policy hash covers threshold, owner key hashes, and both cap values.
- Confirm REGISTER signature verification cannot be bypassed.
- Confirm duplicate registration of an existing sidechain ID is rejected.
- Confirm owner-auth sidechains require valid distinct owner signatures on bundle commits.
- Confirm duplicate signatures do not satisfy `auth_threshold`.
- Confirm malformed/partial compact signatures are rejected consistently (mempool + block).

## Escrow / Execute Safety

- Confirm deposits cannot raise escrow above `max_escrow_amount`.
- Confirm execute withdrawal sum cannot exceed effective escrow.
- Confirm execute withdrawal sum cannot exceed `max_bundle_withdrawal`.
- Confirm execute bundle hash must match exact withdrawal set and ordering.
- Confirm no drivechain outputs are allowed inside EXECUTE withdrawal windows.

## Reorg / Persistence

- Validate state snapshot persistence and fallback recompute behavior.
- Validate restart safety with pending bundles, approved bundles, and orphaned branches.
- Validate mempool eviction/revalidation for stale BMM requests and execute transactions.

## RPC / UX Safety

- Confirm `getdrivechaininfo` exposes unambiguous policy fields (`policy_hash`,
  `owner_key_hashes`, payload-order companions, threshold, and caps).
- Confirm wallet RPCs fail with clear errors on invalid sidechain IDs and malformed inputs.
- Confirm wallet RPCs fail with clear errors on insufficient or unauthorized owner address sets.
- Confirm auto-selected sidechain IDs from `senddrivechainregister` are deterministic and documented.

## Adversarial Testing

- Long reorg fuzz scenario (multi-sidechain, overlapping bundle windows).
- Mempool-vs-block divergence tests for crafted mixed drivechain outputs.
- Duplicate/replace transaction races around bundle commits and registrations.

## Deployment / Process

- Independent reviewer sign-off on consensus diffs in:
  - `src/validation.cpp`
  - `src/drivechain/state.cpp`
  - `src/drivechain/script.cpp`
- Functional + unit + fuzz corpus review complete.
- Incident rollback and key-compromise runbooks prepared.
- Staged rollout plan approved (`doc/drivechain/STAGED_ROLLOUT_PLAN.md`).
- External sign-off completed (`doc/drivechain/EXTERNAL_SECURITY_SIGNOFF.md`).
