# Implementation Status: Validity-Enforced Sidechains

This document is the branch-status companion to:

- `doc/validity-sidechains/LIP-validity-sidechains.md`
- `doc/validity-sidechains/MIGRATION_MAP.md`
- `doc/validity-sidechains/ACTIVATION_REQUIREMENTS.md`

Use this file first when starting a new chat about the validity-sidechain work.
It describes what the current branch actually implements, what is still
scaffold-only, and what should happen next.

## 1. Current Branch State

As of the current `litecoin-validity-sidechains` branch tip:

- the repo contains a separate `src/validitysidechain/` module
- the new protocol has distinct parsing, state, validation, mempool, and RPC
  scaffolding
- the branch is still `scaffolding`, not `trustless`, not `activation
  candidate`, and not `production-ready`
- the legacy drivechain consensus path still exists and remains active

The authoritative read-only status RPC is:

- `getvaliditysidechaininfo`

That RPC currently reports:

- `implementation_status = "scaffolding"`
- `trustless_enforced = false`
- `activation_candidate = false`
- `legacy_drivechain_withdrawal_path_active = true`
- `batch_validation_mode = "scaffold_queue_prefix_commitment_v1"`
- `verified_withdrawal_execution_mode = "merkle_inclusion_scaffold"`
- `escape_exit_mode = "merkle_inclusion_scaffold"`

## 2. What Is Implemented

The following validity-sidechain transaction families are implemented in parser,
validation, mempool, and chainstate form:

- `REGISTER_VALIDITY_SIDECHAIN`
- `DEPOSIT_TO_VALIDITY_SIDECHAIN`
- `RECLAIM_STALE_DEPOSIT`
- `REQUEST_FORCE_EXIT`
- `COMMIT_VALIDITY_BATCH`
- `EXECUTE_VERIFIED_WITHDRAWALS`
- `EXECUTE_ESCAPE_EXIT`

The following core behaviors exist on this branch:

- sidechain registration against a fixed supported config registry
- validity-sidechain state persistence at the tip
- L1 message queue tracking with queue root and head index
- deposit insertion into the queue
- stale-deposit reclaim with escrow rollback and tombstoning
- force-exit request insertion and maturity tracking
- deterministic queue-prefix consumption by accepted batches
- mandatory consumption of matured force-exit requests in the reachable prefix
- accepted-batch indexing by sidechain and batch number
- executed-withdrawal replay protection
- executed escape-exit replay protection
- read-only RPC reporting for validity-sidechain state
- wallet send-path RPCs for registration, deposit, force-exit request,
  stale-deposit reclaim, and scaffold batch submission

## 3. What Is Still Scaffold-Only

The current implementation is not yet the final trustless design.

### Batch verification

`COMMIT_VALIDITY_BATCH` currently uses a scaffold verifier profile:

- supported profile name: `scaffold_onchain_da_v1`
- registry flag: `scaffolding_only = true`
- verifier mode: `scaffold_queue_prefix_commitment_v1`

This means:

- proof bytes are not a real zk proof yet
- the branch requires a deterministic scaffold proof envelope
- that envelope binds the batch commitment and current chainstate roots
- queue-prefix consumption is enforced
- state-root, withdrawal-root, and data-root updates are still restricted to
  scaffold behavior

There is not yet a real zk verifier backend in the repository.

### Withdrawal execution

`EXECUTE_VERIFIED_WITHDRAWALS` now uses deterministic Merkle-style proof
objects, but this is still scaffolded because:

- the accepted batch path is not yet backed by a real zk proof
- the withdrawal root is not yet produced by a final circuit/verifier path

### Escape exits

`EXECUTE_ESCAPE_EXIT` now also uses deterministic Merkle-style proof objects,
but this is still scaffolded because:

- the escape-exit tree is still a staging proof format
- the proofs are not yet tied to the final user-state circuit

## 4. Legacy Drivechain Status

Legacy drivechain has not been removed yet.

Current legacy status:

- the drivechain consensus path is still compiled and active
- `getdrivechaininfo` still exists, but is marked deprecated
- `senddrivechainbundle` still exists, but is marked deprecated
- `senddrivechainexecute` still exists, but is marked deprecated

This deprecation is intentional. The branch has not yet reached the point where
legacy consensus behavior can be deleted safely.

## 5. Wallet and RPC Gaps

The new protocol now has a partial operator RPC surface.

Currently available wallet/RPC send-paths:

- `sendvaliditysidechainregister`
- `sendvaliditydeposit`
- `sendvaliditybatch`
- `sendforceexitrequest`
- `sendstaledepositreclaim`

Still missing wallet/RPC work:

- `sendverifiedwithdrawals`
- `sendescapeexit`

So far, the new path can exercise registration, queue insertion, scaffold batch
submission, and stale-deposit recovery from the wallet, but proof-execution
ergonomics are still incomplete.

## 6. Testing Status

The branch has unit coverage for the new parsing/state layers, including:

- config registry
- deposit queue and reclaim
- batch scaffold acceptance
- withdrawal proof execution
- escape-exit proof execution

It also now has functional wallet/RPC coverage for:

- validity-sidechain registration
- deposit submission
- force-exit request submission
- scaffold batch submission with auto-built scaffold proof bytes
- stale-deposit reclaim

What is still missing or incomplete:

- full functional coverage for the new validity-sidechain transaction families
- real verifier test vectors
- DA failure-mode tests against a non-scaffold batch path
- broad reorg coverage for the complete validity-sidechain flow

## 7. Next Recommended Steps

If continuing this branch in another chat, the recommended order is:

1. Add a real zk verifier backend and at least one non-scaffold supported
   profile.
2. Make `COMMIT_VALIDITY_BATCH` accept real state-root, withdrawal-root, and
   data-root transitions under proof verification.
3. Replace the escape-exit staging tree with final user-state proof semantics.
4. Add the remaining proof-execution wallet RPCs
   (`sendverifiedwithdrawals` and `sendescapeexit`) and finish the operator
   send-path.
5. Add functional tests for the full validity-sidechain path.
6. Only then convert the deprecated legacy drivechain RPCs into hard failures
   and begin removing the legacy consensus path.

## 8. How To Use The Docs Together

For a future chat:

1. Start with this file for current branch truth.
2. Use `LIP-validity-sidechains.md` for the target protocol semantics.
3. Use `MIGRATION_MAP.md` for the codebase transition plan.
4. Use `ACTIVATION_REQUIREMENTS.md` to avoid overstating readiness or
   trustlessness.

If any of those documents disagree, treat this file as the implementation
status for the current branch and update the others accordingly.
