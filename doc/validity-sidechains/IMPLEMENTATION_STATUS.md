# Implementation Status: Validity-Enforced Sidechains

This document is the branch-status companion to:

- `doc/validity-sidechains/LIP-validity-sidechains.md`
- `doc/validity-sidechains/MIGRATION_MAP.md`
- `doc/validity-sidechains/ACTIVATION_REQUIREMENTS.md`
- `doc/validity-sidechains/PROPOSED_ZK_SYSTEM.md`

Use this file first when starting a new chat about the validity-sidechain work.
It describes what the current branch actually implements, what is still
scaffolded or experimental, and what should happen next.

The selected native pairing backend for the intended real verifier path is
documented in `doc/validity-sidechains/NATIVE_VERIFIER_BACKEND.md`.

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
- `force_exit_request_mode = "profile_specific"`
- `batch_validation_mode = "profile_specific"`
- `batch_queue_binding_mode = "profile_specific"`
- `batch_withdrawal_binding_mode = "profile_specific"`
- `max_batch_data_chunks_limit = 256`
- `max_batch_queue_consumption_limit = 1024`
- `verified_withdrawal_execution_mode = "profile_specific"`
- `max_execution_fanout_limit = 128`
- `escape_exit_mode = "profile_specific"`

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
- fixed consensus/resource bounds for batch DA chunk count, consumed queue
  messages, and withdrawal / escape-exit execution fanout
- wallet send-path RPCs for registration, deposit, force-exit request, batch
  submission, verified withdrawals, stale-deposit reclaim, and escape exits

## 3. What Is Still Scaffolded Or Experimental

The current implementation is not yet the final trustless design.

### Batch verification

`COMMIT_VALIDITY_BATCH` currently uses two scaffold verifier profiles, two
experimental toy Groth16 profiles, and one proposed native real profile slot:

- supported profile names:
  - `scaffold_onchain_da_v1`
  - `scaffold_transition_da_v1`
  - `gnark_groth16_toy_batch_transition_v1`
  - `native_blst_groth16_toy_batch_transition_v1`
  - `groth16_bls12_381_poseidon_v1`
  - `groth16_bls12_381_poseidon_v2`
- verifier modes:
  - `scaffold_queue_prefix_commitment_v1`
  - `scaffold_transition_commitment_v1`
  - `gnark_groth16_toy_batch_transition_v1`
  - `native_blst_groth16_toy_batch_transition_v1`
  - `groth16_bls12_381_poseidon_v1`
  - `groth16_bls12_381_poseidon_v2`

This means:

- the scaffold profiles still require a deterministic scaffold proof envelope
  - that envelope binds the batch commitment and current chainstate roots
- empty proof bytes, missing non-zero DA payloads, empty DA chunks, oversized
  payloads, oversized DA chunk counts, and mismatched `data_root`
  commitments are rejected
- queue-prefix consumption is enforced, and batch metadata now carries a
  deterministic `queue_prefix_commitment` checked against the exact consumed
  pending prefix
- the prefix-only scaffold profile still requires no-op state-root,
  withdrawal-root, and data-root updates with empty DA
- the transition scaffold profile now allows deterministic root and DA updates,
  but they are still not backed by a real zk proof
- the experimental toy Groth16 profile now has a real proving key, verifying
  key, proof vectors, and end-to-end external prover/verifier command path
  through `contrib/validitysidechain-zk-demo`, but it proves only a toy
  arithmetic relation and does not satisfy the intended trustless sidechain
  semantics
- the native toy Groth16 profile now has committed converted proof vectors and
  a native binary verifying-key blob under `artifacts/validitysidechain/`,
  and the node can replay those committed vectors through the in-process
  `blst` verifier, but it still proves only the same toy arithmetic relation
  rather than the intended sidechain circuit
- verifier-asset status still reports whether valid and invalid proof vectors
  are present, but runtime verifier readiness now depends on the manifest and
  verifying key rather than on bundled proof-vector fixtures
- the repo now vendors `blst` under `external/blst/` as the selected native
  BLS12-381 pairing backend, and the node now compiles a portable in-process
  `blst` library plus a backend self-test wrapper for the proposed real profile
- the proposed real profile now also has a native binary parser layer for
  Groth16 proof bytes and verifying-key blobs, including `blst`-validated
  compressed-point checks and supported public-input-count enforcement
- the native backend now also evaluates the Groth16 pairing equation in-process
  against that parsed proof / VK format, with synthetic algebraic unit
  coverage
- the proposed real profile now also has an experimental committed artifact
  bundle with a real proving key, native verifying key, valid/invalid proof
  vectors, and an external auto-prover path that emits native `VSGP` proof
  bytes consumed by the in-process verifier
- the committed real-profile vectors now bind a non-empty published DA payload,
  and the external auto-prover request path now carries `data_chunks_hex` so
  the prover validates `data_root` and `data_size` against the same chunk list
  the wallet publishes onchain
- the committed real-profile vectors now also consume one deterministic deposit
  queue entry and carry a non-zero `queue_prefix_commitment`, with the deposit
  nonce chosen so the queue hashes fit the current one-scalar-per-input native
  verifier format
- the experimental real-profile prover request now also carries
  `consumed_queue_entries`, and the current experimental circuit now
  constrains one consumed queue witness internally, even though the
  surrounding node state machine still enforces the reachable queue-prefix
  rules locally
- the experimental real-profile vectors now also bind one deterministic
  withdrawal leaf through the actual Litecoin withdrawal-root hashing path, so
  the committed valid vector can still drive `EXECUTE_VERIFIED_WITHDRAWALS`
  against a proof-backed accepted batch, and `withdrawal_root` is now bound
  directly into the experimental Poseidon transition commitment while the
  experimental circuit now also constrains that single withdrawal witness
- the functional real auto-prover coverage now also rejects mismatched
  `withdrawal_leaves` witness metadata before proof generation, so the wallet
  no longer treats that experimental witness as best-effort input
- the wallet `sendvaliditybatch` RPC now applies the same experimental
  real-profile shape limits even when callers supply manual `proof_bytes`,
  rejecting `consumed_queue_messages > 1` and more than one
  `withdrawal_leaves` witness up front instead of falling through to later
  consensus or ignored-metadata behavior
- the Go `verify-batch` helper now also understands the committed native real
  `groth16_bls12_381_poseidon_v1` bundle, giving the branch an external
  verifier-tool cross-check in addition to the in-process native verifier
- the committed real-profile invalid vectors now cover corrupted proofs,
  `new_state_root` mismatch, `queue_prefix_commitment` mismatch, and
  `withdrawal_root` mismatch against the same accepted public-input tuple
- the experimental real-profile proving key is now generator-produced but not
  committed in-tree; committed artifacts remain verifier-side only, while
  local real-profile auto-prover runs require regenerating that proving key
  out of tree, and the validity-sidechain CI job now does that materialization
  transiently on the runner before functional tests
- external-profile asset status now validates manifest name, consensus tuple,
  declared public-input layout, backend/key layout, and listed valid/invalid
  proof-vector files instead of treating file presence alone as sufficient
- the proposed Groth16 profile now has a fixed consensus tuple, expected
  verifier-asset layout, committed experimental proof material, and a native
  verifier core, but batch validation still cannot become trustless until the
  final intended sidechain circuit replaces the current deterministic
  experimental transition semantics with the final sidechain state machine;
  `groth16_bls12_381_poseidon_v1` still keeps host-validated single-entry /
  single-leaf fixtures, while the decomposed `v2` profile now proves a bounded
  in-circuit queue/withdrawal witness relation instead of leaving those roots
  entirely host-validated
- consensus now hard-rejects `groth16_bls12_381_poseidon_v1` batches with
  `consumed_queue_messages > 1`, matching the current experimental
  single-entry queue-fixture coverage instead of silently accepting broader
  queue consumption semantics than that profile actually models
- consensus, wallet RPCs, and top-level profile reporting now also pin that
  same experimental batch queue mode to consumed deposit entries only, exposed
  as `local_prefix_consensus_single_deposit_entry_experimental`, so the node
  no longer implies current proof coverage for consumed force-exit queue
  entries on that profile
- the same experimental real profile now also disables new
  `REQUEST_FORCE_EXIT` submission entirely, reported as
  `force_exit_request_mode = "disabled_pending_real_queue_entry_proof"`,
  because the current proof path cannot yet cover consumed force-exit queue
  entries for that profile
- consensus and wallet RPCs now also hard-reject more than one executed
  withdrawal leaf for `groth16_bls12_381_poseidon_v1`, matching the current
  single-leaf experimental withdrawal binding instead of pretending broader
  withdrawal execution coverage exists
- RPC status now reports that same profile as
  `withdrawal_root_single_leaf_experimental` rather than the generic
  `withdrawal_root_merkle_inclusion` mode, so node observability no longer
  overstates the current withdrawal execution capability
- the top-level `getvaliditysidechaininfo` RPC now also reports
  `force_exit_request_mode = "profile_specific"`,
  `batch_queue_binding_mode = "profile_specific"` and
  `batch_withdrawal_binding_mode = "profile_specific"` alongside the existing
  profile-specific batch and withdrawal execution mode summaries
- the auto-prover path now also fails early on unsupported experimental real
  witness shapes, rejecting more than one consumed queue entry or more than
  one withdrawal witness leaf before invoking the external prover command
- consensus now also requires the executed withdrawal proof itself to be a
  literal single-leaf proof for `groth16_bls12_381_poseidon_v1`, so a
  hand-crafted Merkle proof for one leaf out of a larger withdrawal tree no
  longer slips past the current experimental single-leaf semantics
- the current native verifier path interprets each batch public input as a
  single BLS12-381 scalar, so the final real profile must either keep those
  roots / commitments field-sized or move to a decomposed public-input layout
- the branch now also has a committed `groth16_bls12_381_poseidon_v2` bundle
  for that decomposed successor layout, splitting
  `l1_message_root_before`, `l1_message_root_after`,
  `queue_prefix_commitment`, `withdrawal_root`, and `data_root` into
  128-bit public-input limbs while keeping the current native-verifier-safe
  experimental transition shape, leaving the current committed
  `groth16_bls12_381_poseidon_v1` bundle unchanged
- the external prover helper now treats `groth16_bls12_381_poseidon_v2`
  according to that decomposed runtime surface instead of reusing the old
  single-entry/single-leaf witness checks: it derives and validates generic
  consumed queue prefixes and generic withdrawal Merkle roots for `v2`, but
  those generic witness relations are still host-validated by the auto-prover
  helper and Litecoin consensus checks rather than proven in-circuit, while
  `groth16_bls12_381_poseidon_v1` remains explicitly single-entry and
  single-leaf
- `getvaliditysidechaininfo` now reports that same decomposed `v2` profile as
  `batch_queue_binding_mode = "local_prefix_consensus_committed_public_inputs_experimental"`
  and
  `batch_withdrawal_binding_mode = "accepted_root_generic_public_input_experimental"`
  so node observability no longer implies the reverted bounded-witness `v2`
  experiment is still the active path
- the decomposed `groth16_bls12_381_poseidon_v2` runtime path now also has
  direct reclaim coverage in both state-unit and functional tests, proving a
  matured deposit can be reclaimed and persisted across restart while keeping
  the profile's full-width initial withdrawal root intact
- that same decomposed reclaim path now also has dedicated reorg coverage,
  proving an orphaned reclaim cleanly rolls back to the matured-deposit state
  and can be restored or resubmitted after restart without losing the
  full-width withdrawal-root state
- real-profile registration now enforces that `initial_state_root` already
  fits the BLS12-381 scalar field for both Poseidon profiles, while
  `initial_withdrawal_root` is still scalar-sized only for
  `groth16_bls12_381_poseidon_v1`; the decomposed `v2` bundle now accepts a
  full-width withdrawal root because that value has a committed limb-split
  public-input slot and matching native Groth16 verifier assets
- the experimental real profile now also rejects a second pending deposit
  queue entry, and deposit admission checks the append, single-entry consume,
  and prefix-commitment queue hashes against that same scalar field, while
  stale-deposit reclaim still separately checks the tombstone queue hash, so
  the node no longer accepts pending deposit states the current 11-input
  native verifier layout cannot represent
- the wallet `sendvaliditydeposit` RPC now mirrors that profile limit too:
  it reports `deposit_admission_mode = "single_pending_entry_scalar_field_experimental"`
  and auto-picks a compatible nonce when callers omit one, instead of leaving
  operators to trial-and-error random nonces against mempool rejection
- the remaining trustless blocker is no longer the generic pairing equation;
  it is the absence of the final sidechain proof semantics for the intended
  profile

There is now a native in-process Groth16 verifier core in the repository, but
the intended sidechain circuit semantics are still experimental rather than the
final trustless state machine.

### Withdrawal execution

`EXECUTE_VERIFIED_WITHDRAWALS` now uses deterministic Merkle-style proof
objects, but this is still scaffolded because:

- the accepted batch path is not yet backed by a real zk proof
- the withdrawal root is not yet produced by a final circuit/verifier path

### Escape exits

`EXECUTE_ESCAPE_EXIT` now also uses deterministic Merkle-style proof objects,
but this is still experimental rather than final because:

- consensus still decodes the staging escape-exit proof objects directly and
  verifies them against `current_state_root`
- the dormant account/balance witness format is not yet wired into block or
  mempool validation

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

So far, the new path can exercise registration, queue insertion, batch
submission, verified-withdrawal execution, force-exit request submission,
stale-deposit recovery, and escape-exit execution from the wallet.
`sendverifiedwithdrawals` now accepts either the legacy ordered withdrawal
list or explicit Merkle proof objects, and `sendescapeexit` now accepts either
legacy exit leaves or explicit account/balance state-proof objects.
`sendvaliditybatch` now also auto-derives `prior_state_root`,
`l1_message_root_before`, `l1_message_root_after`, and
`queue_prefix_commitment` from the active chainstate when callers omit them,
and it can now also derive profile-appropriate `withdrawal_root`, `data_root`,
and `data_size` values from withdrawal witnesses or DA chunks where the current
wallet surface has enough information. It also rejects mismatched queue-prefix
or withdrawal-witness metadata before proof construction instead of falling
through to later generic verifier errors.
The wallet now also locally prevalidates stale-deposit reclaim,
verified-withdrawal execution, and escape-exit execution against the active
chainstate before transaction construction, so obvious delay/replay/root-state
failures are rejected immediately instead of falling through to later mempool
rejection.
Non-scaffold profiles now also expose an experimental `current_state_root`
Merkle mode for `EXECUTE_ESCAPE_EXIT`, but that path still stops short of the
final user-state proof semantics.

## 6. Testing Status

The branch has unit coverage for the new parsing/state layers, including:

- config registry
- deposit queue and reclaim
- batch scaffold acceptance
- commit-script DA chunk framing and malformed chunk-order/count rejection
- resource-bound rejection for DA chunk count, consumed queue count, and
  withdrawal / escape-exit execution fanout
- withdrawal proof execution
- escape-exit proof execution

It also now has functional wallet/RPC coverage for:

- validity-sidechain registration
- deposit submission
- force-exit request submission
- scaffold batch submission with auto-built scaffold proof bytes
- committed valid/invalid toy proof-vector replay through the experimental
  external verifier path
- committed valid/invalid native toy proof-vector replay through the
  in-process `blst` verifier path
- committed valid/invalid real-profile proof-vector replay through the
  in-process `blst` verifier path
- auto-built proof generation for the experimental real profile through the
  configured external prover command path, with native in-process verification
- malformed external verifier manifests for tuple/public-input mismatches
- malformed batch DA rejection for missing chunks, malformed chunk ordering,
  oversized payloads, oversized proof bytes, oversized DA chunk counts, and
  bad `data_root`
- wallet-side rejection for oversized verified-withdrawal and escape-exit
  execution fanout before transaction construction
- forced-inclusion recovery by requiring matured force-exit requests to be
  consumed by the full reachable queue prefix, including restart persistence
  before and after the consuming batch and the case where an earlier pending
  deposit must be consumed first
- explicit censorship-recovery coverage showing that a live sequencer cannot
  bypass a matured force-exit request and that a halted sequencer still leaves
  users with an escape-exit path
- exact-bound functional coverage for the maximum queue-consumption limit, the
  maximum DA payload plus chunk-count limits, and the maximum verified-
  withdrawal execution fanout limit
- verified withdrawal execution
- escape-exit execution
- stale-deposit reclaim
- mempool duplicate rejection for registration, deposit, reclaim, force-exit,
  batch, verified-withdrawal, and escape-exit transaction families
- restart persistence and snapshot-backed rollback across invalidated tips and
  multi-batch invalidated history plus competing-fork rollback of accepted
  batches, verified withdrawals, and
  escape-exit/nullifier state
- competing-fork rollback of pending and matured force-exit request state so
  losing-fork censorship recovery data does not survive reorg
- competing-fork rollback of accepted force-exit consumption batches so a
  losing-fork batch does not hide a still-matured request and the same batch
  can be restored or resubmitted after restart
- competing-fork rollback of stale-deposit reclaim state so reclaimable
  deposits reappear deterministically after losing-fork rollback
- orphaned reclaim transactions staying out of mempool when a competing fork
  consumes the same deposit in an accepted batch
- orphaned verified-withdrawal transactions staying out of mempool when the
  winning fork already executed the same withdrawal ids, including explicit
  Merkle-proof RPC submissions
- orphaned escape-exit transactions staying out of mempool when the winning
  fork already executed the same legacy exit ids or current-state-root
  state-proof claim keys, including same-claim submissions with different
  deterministic `exit_id` values
- competing-fork rollback of state-proof escape-exit claim-key replay state so
  losing-fork current-state-root exits can be restored or resubmitted after
  restart without keeping stale nullifiers alive
- competing-fork rollback of longer losing-fork accepted-batch history plus
  executed withdrawals, including restart with an empty mempool and manual
  replay of the same batch sequence afterward
- competing-fork rollback of losing-fork registration and deposit state so
  orphaned sidechains disappear and the same sidechain id can be reused

What is still missing or incomplete:

- full functional coverage for the new validity-sidechain transaction families
- final non-toy sidechain verifier test vectors for the production semantics
- additional adversarial and long-range reorg coverage beyond the current
  registration, deposit, force-exit, batch, withdrawal, reclaim, and
  escape-exit rollback scenarios

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
