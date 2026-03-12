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
- accepted-batch RPC reporting with publication tx/proof/DA metadata derived
  from the active chain
- executed-withdrawal replay protection
- executed escape-exit replay protection
- persisted validity-sidechain snapshots by tip hash for restart and reorg rollback
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
- empty proof bytes, missing non-zero DA payloads, empty DA chunks, oversized
  payloads, and mismatched `data_root` commitments are rejected
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

## 5. Wallet and RPC Surface

The new protocol now has a full operator RPC send-path for the currently
implemented scaffold semantics.

Currently available wallet/RPC send-paths:

- `sendvaliditysidechainregister`
- `sendvaliditydeposit`
- `sendvaliditybatch`
- `sendverifiedwithdrawals`
- `sendforceexitrequest`
- `sendstaledepositreclaim`
- `sendescapeexit`

So far, the new path can exercise registration, queue insertion, scaffold batch
submission, verified-withdrawal execution, stale-deposit recovery, and
escape-exit execution from the wallet.

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
- malformed batch DA rejection for missing chunks, oversized payloads, oversized
  proof bytes, and bad `data_root`
- forced-inclusion recovery by requiring matured force-exit requests to be
  consumed by the accepted queue prefix
- verified withdrawal execution
- escape-exit execution
- stale-deposit reclaim
- restart persistence and snapshot-backed rollback across invalidated tips and
  competing-fork rollback of accepted batches, verified withdrawals, and
  escape-exit/nullifier state
- competing-fork rollback of stale-deposit reclaim state so reclaimable
  deposits reappear deterministically after losing-fork rollback

What is still missing or incomplete:

- full functional coverage for the new validity-sidechain transaction families
- real verifier test vectors
- DA failure-mode tests against a non-scaffold batch path
- broad reorg coverage for the complete validity-sidechain flow

## 7. Trustless And Activation Roadmap

This section is the repo-specific implementation order for the current branch.
It is an engineering sequence, not a relaxation of the naming discipline in
`ACTIVATION_REQUIREMENTS.md`. Until the formal gates there are satisfied, the
branch should still be described as scaffolding rather than trustless or
activation-ready.

### Must Before Trustless

The biggest remaining blockers before the design can even approach trustless
semantics are:

- ship a real zk verifier backend and at least one non-scaffold supported
  profile in `src/validitysidechain/verifier.*` and
  `src/validitysidechain/registry.*`
- make `COMMIT_VALIDITY_BATCH` verify real `new_state_root`,
  `withdrawal_root`, `data_root`, and public-input transitions under proof
  verification instead of the current scaffold no-op root rules in
  `src/validitysidechain/verifier.cpp` and `src/validitysidechain/state.cpp`
- enforce onchain data availability for every accepted non-scaffold batch,
  including deterministic rejection of missing chunks, malformed chunk
  ordering, oversized payloads, and mismatched `data_root` commitments in
  `src/validitysidechain/verifier.cpp` and `src/validation.cpp`
- finish proof-backed L1 queue consumption so deposits and matured force-exit
  requests are enforced by the proven batch transition, not only by the current
  scaffold queue-prefix checks in `src/validitysidechain/state.cpp`
- replace scaffold withdrawal and escape-exit execution semantics with final
  proof-backed roots and user-state proofs in `src/validitysidechain/state.cpp`,
  `src/validitysidechain/script.cpp`, and `src/validation.cpp`
- keep deposit recovery, withdrawal replay protection, and escape-exit replay
  protection deterministic under consensus so stale deposits remain reclaimable
  and exits remain single-execution under restart and reorg conditions

### Must Before Activation

After the core trustless blockers above, the remaining activation blockers are:

- keep the wallet/operator RPC surface aligned with the final proof semantics
  and capability reporting as verifier profiles evolve
- harden reorg safety for accepted batches, queue state, escrow balances, and
  nullifier sets across `src/validation.cpp` and `src/validitysidechain/state.*`
- add the full required test matrix called out in
  `doc/validity-sidechains/ACTIVATION_REQUIREMENTS.md`
- benchmark verifier and DA-validation costs to safe node-validation limits and
  get external review of verifier integration and public-input binding
- remove legacy withdrawal authorization from the migration path so miner
  voting and owner signatures are no longer part of peg-out authorization

### After Activation Candidate

Only after the new path is the sole supported withdrawal model should the branch:

- delete deprecated legacy drivechain withdrawal RPCs and consensus logic in
  `src/rpc/blockchain.cpp`, `src/wallet/rpcwallet.cpp`, `src/validation.cpp`,
  `src/drivechain/state.*`, `src/miner.cpp`, and `src/txmempool.*`
- expand ergonomics, tooling, and broader operator convenience beyond the trust
  and activation gates

### Milestone 1: Replace The Scaffold Verifier

Goal: make `COMMIT_VALIDITY_BATCH` capable of real proof verification.

Primary files:

- `src/validitysidechain/verifier.h`
- `src/validitysidechain/verifier.cpp`
- `src/validitysidechain/registry.h`
- `src/validitysidechain/registry.cpp`

Work:

- extend the verifier mode enum beyond `SCAFFOLD_QUEUE_PREFIX_ONLY`
- add at least one supported non-scaffold proof profile to the fixed registry
- define exactly which public inputs are bound by consensus and what resource
  limits apply to them

Exit criteria:

- accepted batches may change `new_state_root`, `withdrawal_root`, and
  `data_root`
- proof verification is consensus-enforced
- scaffold-only is no longer the only usable profile

### Milestone 2: Make Batch Acceptance Actually Trustless

Goal: remove the remaining scaffold assumptions from batch processing.

Primary files:

- `src/validitysidechain/state.cpp`
- `src/validation.cpp`
- `src/validitysidechain/script.cpp`

Work:

- update `ValiditySidechainState::AcceptBatch` so accepted batches reflect real
  proof-backed state transitions rather than scaffold no-op roots
- tighten block and mempool validation around batch metadata, root transitions,
  and queue consumption
- keep script encoding and decoding aligned with the final batch format and
  public-input commitments

Exit criteria:

- batch acceptance no longer depends on no-op state-root rules
- queue-prefix consumption is enforced as part of the proven transition
- matured force-exit inclusion is backed by proof semantics rather than only
  scaffold checks

### Milestone 3: Enforce Real Onchain DA

Goal: batches are invalid unless their DA payload is present and committed
correctly.

Primary files:

- `src/validitysidechain/verifier.cpp`
- `src/validation.cpp`
- `src/validitysidechain/registry.cpp`

Work:

- finish DA checks for non-scaffold batches
- add rejection paths for missing chunks, malformed ordering, oversized
  payloads, and bad `data_root` commitments
- confirm that the supported profile limits are realistic for node validation

Exit criteria:

- DA is mandatory for accepted non-scaffold batches
- invalid or incomplete DA payloads are rejected deterministically

### Milestone 4: Finalize The Exit Model

Goal: make withdrawals and escape exits depend on final proof semantics.

Primary files:

- `src/validitysidechain/state.cpp`
- `src/validitysidechain/script.cpp`
- `src/validation.cpp`

Work:

- finish the `EXECUTE_VERIFIED_WITHDRAWALS` path against real accepted-batch
  roots
- replace the current escape-exit staging tree with final user-state proof
  semantics against the latest finalized state root
- preserve replay protection and exact payout matching

Exit criteria:

- trustless withdrawal execution works from real proof-backed roots
- escape exits are no longer staging proofs

### Milestone 5: Finish The Wallet Surface

Goal: keep the operator path aligned with the consensus features already
exposed by the new protocol.

Primary files:

- `src/wallet/rpcwallet.cpp`
- `src/rpc/blockchain.cpp`

Work:

- keep `sendverifiedwithdrawals` aligned with the accepted-batch and withdrawal
  proof semantics
- keep `sendescapeexit` aligned with the escape-exit proof semantics
- keep `getvaliditysidechaininfo` aligned with the real capability set and any
  proof-profile changes

Exit criteria:

- the full operator flow exists through wallet RPCs
- operators no longer need hand-built raw transactions for the main
  validity-sidechain actions

### Milestone 6: Reorg And Persistence Hardening

Goal: make the new state machine survive adversarial chain movement and restart.

Primary files:

- `src/validation.cpp`
- `src/validitysidechain/state.cpp`
- `src/validitysidechain/state.h`

Work:

- harden connect, disconnect, restore, and replay behavior for
  validity-sidechain state
- verify snapshot and replay behavior for accepted batches, queue head/root,
  escrow state, and executed-nullifier sets
- add targeted reorg coverage for batches, reclaims, withdrawals, and
  escape exits

Exit criteria:

- accepted batches, queue state, escrow balances, and nullifier sets are
  reorg-safe
- the implementation has no hidden dependence on forward-only chain movement

### Milestone 7: Test Gates

Goal: satisfy the activation requirements, not just the happy path.

Primary files:

- `src/test/validitysidechain_state_tests.cpp`
- `src/test/validitysidechain_script_tests.cpp`
- `test/functional/feature_validitysidechain_wallet.py`

Work:

- expand unit coverage for parsing, config validation, queue hashing,
  nullifiers, and state-transition invariants
- add functional and adversarial coverage for proof vectors, DA failures, queue
  edge cases, censorship recovery, reorgs, and DoS/resource-bound cases

Exit criteria:

- the test matrix matches `doc/validity-sidechains/ACTIVATION_REQUIREMENTS.md`

### Milestone 8: Activation Readiness And Legacy Removal

Goal: move from trustless implemented to activation candidate.

Primary files:

- `src/rpc/blockchain.cpp`
- `src/wallet/rpcwallet.cpp`
- `src/validation.cpp`
- `src/drivechain/state.*`
- `src/miner.cpp`
- `src/txmempool.*`
- `doc/validity-sidechains/*.md`

Work:

- benchmark verifier and DA validation costs
- get external review of verifier integration and public-input binding
- remove or hard-fail legacy withdrawal RPCs and then remove the legacy
  consensus path
- update docs so they stop describing the new path as scaffolding once the
  formal gates are actually cleared

Exit criteria:

- the no-go conditions in `doc/validity-sidechains/ACTIVATION_REQUIREMENTS.md`
  are cleared
- legacy miner-vote and owner-auth withdrawal authorization are gone

### Practical Priority

If the goal is the shortest path from the current branch state, the practical
implementation order is:

1. Milestone 1
2. Milestone 2
3. Milestone 3
4. Milestone 4
5. Milestone 6
6. Milestone 7
7. Milestone 5
8. Milestone 8

That order keeps wallet ergonomics behind the real trustlessness bottlenecks:
verifier integration, batch semantics, data availability, exits, and reorg
hardening.

## 8. How To Use The Docs Together

For a future chat:

1. Start with this file for current branch truth.
2. Use `LIP-validity-sidechains.md` for the target protocol semantics.
3. Use `MIGRATION_MAP.md` for the codebase transition plan.
4. Use `ACTIVATION_REQUIREMENTS.md` to avoid overstating readiness or
   trustlessness.

If any of those documents disagree, treat this file as the implementation
status for the current branch and update the others accordingly.
