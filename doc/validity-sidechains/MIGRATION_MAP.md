# Migration Map: Drivechain to Validity-Enforced Sidechains

This document maps the current drivechain implementation in this repository onto
the target architecture defined in
`doc/validity-sidechains/LIP-validity-sidechains.md`.

For the current branch status and recommended next steps, start with
`doc/validity-sidechains/IMPLEMENTATION_STATUS.md`.

The short version is:

- keep Litecoin escrow accounting
- remove miner-voted withdrawals
- remove owner-auth withdrawal control
- add proof-verified batch finalization
- add data availability, queue-driven deposits, forced inclusion, deposit
  reclaim, and escape exits

## 1. Design Delta

| Current drivechain design | Target validity-sidechain design |
|---------------------------|----------------------------------|
| REGISTER binds owner policy | REGISTER binds supported proof configuration |
| BUNDLE_COMMIT publishes a withdrawal bundle hash | COMMIT_VALIDITY_BATCH publishes state/public inputs plus zk proof |
| miners vote yes/no on bundles | no miner withdrawal vote path |
| optional owner signatures gate commits | no owner withdrawal authorization |
| peg-ins are opaque deposits into escrow | peg-ins become queue messages with a reclaim path if unconsumed |
| EXECUTE allowed after approval/finalization delay | EXECUTE allowed after proof-backed batch acceptance and inclusion proof |
| escrow safety enforced, withdrawal correctness socially judged | escrow safety and withdrawal correctness both enforced by consensus |
| no censorship-resistant exit path | forced inclusion plus escape exits |

## 2. Consensus Components to Remove

These concepts should leave the withdrawal authorization path entirely:

- owner-auth registration and threshold signature policy
- miner yes/no vote outputs
- vote windows and approval thresholds
- finalization delay tied to miner votes
- approved bundle tracking
- bundle replacement rules based on miner-approved pending bundles

Relevant current files:

- `src/drivechain/script.cpp`
- `src/drivechain/script.h`
- `src/drivechain/state.cpp`
- `src/drivechain/state.h`
- `src/validation.cpp`
- `src/wallet/rpcwallet.cpp`
- `doc/drivechain/LIP-drivechain.md`

## 3. Consensus Components to Add

The new protocol requires the following major additions:

- verifier registry or built-in verifier implementations
- validity-sidechain registration config parser and hash
- batch proof verification path
- data-availability payload verification
- L1 message queue root and queue-prefix consumption rules
- pending deposit record and stale-deposit reclaim path
- accepted batch / withdrawal-root index
- executed withdrawal nullifier set
- escape-exit state tracking

None of these are optional if the stated goal is trustless peg-outs.

## 4. File-by-File Migration Plan

### `src/drivechain/script.cpp` and `src/drivechain/script.h`

Current role:

- parse drivechain tags
- owner-auth policy hashing and signature recovery
- bundle auth and register auth verification

Target role:

- either replace these files entirely with
  `src/validitysidechain/script.*`
- or keep the files temporarily and replace the tag set with:
  - `REGISTER_VALIDITY_SIDECHAIN`
  - `DEPOSIT_TO_VALIDITY_SIDECHAIN`
  - `COMMIT_VALIDITY_BATCH`
  - `EXECUTE_VERIFIED_WITHDRAWALS`
  - `REQUEST_FORCE_EXIT`
  - `RECLAIM_STALE_DEPOSIT`
  - `EXECUTE_ESCAPE_EXIT`

Phase 1 scaffold note:

- the new script layer should keep a non-overlapping temporary tag range while
  the legacy drivechain parser is still compiled
- a parser/builder module at `src/validitysidechain/script.*` can land before
  any consensus activation as long as it does not claim trustless enforcement

Delete:

- `DrivechainSidechainPolicy`
- owner-key hash encoding/decoding
- `VerifyDrivechainBundleAuthSigs`
- `VerifyDrivechainRegisterAuthSigs`

Add:

- sidechain config hashing
- batch public-input hashing
- deposit message hashing
- DA chunk commitment parsing
- withdrawal inclusion proof parsing
- escape-exit proof parsing

### `src/drivechain/state.cpp` and `src/drivechain/state.h`

Current role:

- sidechain registration
- escrow balance tracking
- bundle tracking
- vote tallying
- approval/finalization scheduling
- execute processing

Target role:

- retain escrow balance tracking
- retain sidechain registration concept, but registration stores proof config
- replace `Bundle` with `AcceptedBatch`
- replace vote counts with:
  - batch number
  - withdrawal root
  - data root
  - accepted height
- add:
  - L1 message queue root
  - L1 message queue head index
  - pending deposit records
  - last accepted batch height
  - executed nullifier index
  - escape-exit nullifier index

Delete:

- `Bundle.yes_votes`
- `Bundle.no_votes`
- `Bundle.approved`
- `ComputeDrivechainBundleSchedule`
- all vote-window logic

Add:

- `AcceptedBatch`
- `DepositRequest`
- `ForceExitRequest`
- `EscapeExitRecord`

### `src/validation.cpp`

Current role:

- pre-validate register/bundle/vote/execute
- enforce vote windows and approval state
- check mempool/block alignment

Target role:

- verify registration config matches supported verifier set
- verify batch proof public inputs and consensus constraints
- verify DA payload is present and correctly committed
- verify deposit insertion and stale-deposit reclaim rules
- verify L1 message queue root/head transitions
- verify withdrawal inclusion proofs against accepted roots
- verify escape exits against the latest finalized state root

Delete:

- `CheckDrivechainBlock` vote-specific logic
- `CheckDrivechainMempoolTx` vote-specific logic
- bundle approval and finalization delay rules
- owner-auth validation

Add:

- `CheckValiditySidechainDeposit`
- `CheckValiditySidechainBatch`
- `CheckValiditySidechainDA`
- `CheckVerifiedWithdrawals`
- `CheckForceExitRequest`
- `CheckStaleDepositReclaim`
- `CheckEscapeExit`

### `src/wallet/rpcwallet.cpp`

Current role:

- register sidechain owner policy
- sign bundle commits with owner keys
- create deposit, BMM request, and execute transactions

Target role:

- create deposit requests that join the L1 message queue
- register supported proof configurations
- submit batch commitments with proof and DA payload
- submit verified withdrawal executions
- submit force-exit requests
- submit stale-deposit reclaims
- optionally submit escape exits

Delete or deprecate:

- `senddrivechainregister`
- `senddrivechainbundle`
- owner-address handling for withdrawal auth

Add or rename:

- `sendvaliditydeposit`
- `sendvaliditysidechainregister`
- `sendvaliditybatch`
- `sendverifiedwithdrawals`
- `sendforceexitrequest`
- `sendstaledepositreclaim`
- `sendescapeexit`

Current branch status:

- `sendvaliditysidechainregister`, `sendvaliditydeposit`,
  `sendvaliditybatch`, `sendforceexitrequest`, and
  `sendstaledepositreclaim` now exist for the scaffold path
- `sendverifiedwithdrawals` now executes against accepted batch
  `withdrawal_root` values across the current profiles
- `sendescapeexit` remains scaffold-only today, and non-scaffold profiles
  hard-fail pending real state-root proof semantics

### `src/rpc/blockchain.cpp`

Current role:

- report sidechain owner-auth data and bundle vote state

Target role:

- report:
  - proof configuration
  - latest finalized state root
  - latest batch number
  - accepted withdrawal roots
  - last accepted batch height
  - L1 message queue state
  - pending deposit count
  - executed nullifier counts
  - escrow balance

Rename target:

- `getdrivechaininfo` -> `getvaliditysidechaininfo`

Phase 1 scaffold note:

- a read-only `getvaliditysidechaininfo` RPC can ship before any consensus
  migration so downstream tools can integrate against the new state shape
  without pretending that trustless validation is already active

### `src/interfaces/chain.*`

Current role:

- expose drivechain owner-auth policy information

Target role:

- expose validity-sidechain registration config and latest finalized state

### `test/functional/*drivechain*`

Current role:

- test owner auth, vote windows, bundle approval, bundle execution

Target replacement test families:

- registration rejects unsupported proof configs
- deposits enter the L1 message queue and can be reclaimed if unconsumed
- batch proof acceptance/rejection
- DA payload presence and hashing
- forced inclusion of L1 exit requests
- verified withdrawal inclusion checks
- escape-exit path on sequencer halt
- reorg handling for accepted batches and executed nullifiers

The existing drivechain vote and owner-auth tests should be retired once the new
protocol is the only supported withdrawal model.

## 5. BMM Decision

The current codebase mixes two different concerns:

- sidechain block production and blind merged mining
- withdrawal authorization
- L1 queue consumption for deposits and exits

For validity-enforced sidechains these should be split.

Recommended rule:

- remove BMM from the trust model entirely
- preserve BMM only as an optional sidechain block-production feature if there
  is product value in it
- do not let BMM signals affect peg-out authorization

This means the `BMM_REQUEST` and `BMM_ACCEPT` code may either:

- remain as an optional, independent feature
- or be deleted to keep the rollout focused on proof-verified peg-outs

## 6. Suggested Implementation Phases

### Phase 0: Rename and Spec Freeze

- add the validity-sidechain draft spec
- stop describing the target protocol as drivechain in new docs
- define the supported proof-system shortlist

### Phase 1: New State Model Behind Feature Flag

- add new state structs for registration config, accepted batches, queue
  messages, and nullifiers
- add placeholder verifier interface and DA parser
- keep old drivechain path intact while the new path is compiled but inactive

### Phase 2: Proof-Verified Batch Acceptance

- implement registration validation against a fixed verifier registry
- implement deposit queue insertion and queue-root tracking
- implement `COMMIT_VALIDITY_BATCH`
- start with a scaffold-only verifier mode that is explicit about not being
  trustless, then add an experimental real-profile backend before the final
  native verifier path
- persist accepted batches and withdrawal roots

### Phase 3: Withdrawal Execution

- implement `EXECUTE_VERIFIED_WITHDRAWALS`
- implement `RECLAIM_STALE_DEPOSIT`
- add nullifier protection
- remove bundle approval and miner-vote requirements from the new path

### Phase 4: Trustless Exit Guarantees

- implement `REQUEST_FORCE_EXIT`
- implement queue-consumption checks in batch proofs
- implement `EXECUTE_ESCAPE_EXIT`

This phase is required before the system should be described as fully trustless.

### Phase 5: Remove Legacy Drivechain Withdrawal Path

- delete vote-window logic
- delete owner-auth withdrawal logic
- delete miner-voted bundle state
- keep only optional BMM pieces if they still serve an independent purpose

## 7. Immediate Next Coding Tasks

If implementation starts from the current branch, the highest-signal sequence is:

1. Add new docs and naming in parallel with the old code.
2. Introduce a new `validitysidechain` module instead of overloading the
   existing `drivechain` module indefinitely.
3. Define the exact binary encoding for:
   - queue head / tombstone handling
   - DA chunk commitments
   - withdrawal leaves
   - escape-exit leaves
4. Add a verifier abstraction with a single supported proof family first.
5. Write unit tests for parsing and state transitions before touching wallet RPCs.

Current branch status:

- fixed proof-config registry now exists in `src/validitysidechain/registry.*`,
  including scaffold modes, an experimental real toy profile, and the planned
  native Groth16 profile slot
- external-profile verifier asset status now validates manifest naming,
  consensus tuple, declared public-input layout, backend labeling, key layout,
  and listed proof-vector files before reporting the bundle as ready
- registration config encoding exists in `src/validitysidechain/script.*`
- deposit queue message encoding exists in `src/validitysidechain/script.*`
- batch public-input encoding exists in `src/validitysidechain/script.*`
- batch metadata decoding now explicitly separates public inputs, proof bytes,
  and DA chunks in `src/validitysidechain/script.*`
- force-exit request encoding exists in `src/validitysidechain/script.*`
- registration config prevalidation exists for supported profile tuples and
  resource bounds
- `REGISTER_VALIDITY_SIDECHAIN` is now recognized by script classification,
  mempool admission, block prevalidation, and chainstate application
- deposit queue insertion, stale-deposit reclaim metadata, and reclaim-path
  escrow accounting now exist in `src/validitysidechain/state.*` and
  `src/validation.cpp`
- `REQUEST_FORCE_EXIT` now has fixed request encoding, queue insertion,
  maturity tracking, and mempool duplicate protection
- accepted-batch state tracking, batch-number monotonicity, queue-prefix
  transition plumbing, and mempool duplicate tracking now exist for
  `COMMIT_VALIDITY_BATCH`
- batch public-input encoding now also carries `queue_prefix_commitment`, so
  accepted batches commit to the exact consumed pending L1 prefix instead of
  only the before/after queue roots
- the current branch exposes two scaffold verifier modes, one experimental
  native toy Groth16 mode, and one experimental real Groth16 profile:
  `scaffold_queue_prefix_commitment_v1` for no-op-root batches,
  `scaffold_transition_commitment_v1` for deterministic root/DA transitions,
  `native_blst_groth16_toy_batch_transition_v1` for committed in-process toy
  proof-vector replay through the native `blst` verifier,
  and `groth16_bls12_381_poseidon_v1` as a fixed non-scaffold tuple with
  committed experimental assets, non-empty DA proof vectors, external
  auto-prover support that now carries `data_chunks_hex` and
  `consumed_queue_entries`, one deterministic consumed deposit queue-entry
  fixture with a non-zero `queue_prefix_commitment`, one deterministic
  withdrawal-leaf fixture through the actual Litecoin withdrawal-root hashing
  path, and native in-process verification for the current experimental
  queue/withdrawal fixture relation, which now binds `withdrawal_root` into
  the transition commitment while keeping the single consumed queue witness
  plus single withdrawal witness host-validated outside the proof, along with
  consensus rejection of `consumed_queue_messages > 1` for that profile so
  the node no longer accepts broader queue-consumption semantics than the
  current experimental bundle covers, plus consensus and wallet rejection of
  more than one executed withdrawal leaf for that profile so withdrawal
  execution does not overstate the current experimental semantics, along with
  committed invalid vectors for mismatched `new_state_root`,
  `queue_prefix_commitment`, and `withdrawal_root`, plus functional rejection
  of mismatched `withdrawal_leaves` witness data before auto-prover proof
  generation; the proving key still has to be regenerated locally, so the
  committed repo bundle remains verifier-side only and still stops short of
  final trustless semantics even though the validity-sidechain CI job now
  materializes that proving key transiently on the runner for auto-prover
  coverage
- `EXECUTE_VERIFIED_WITHDRAWALS` now has fixed withdrawal-leaf encoding,
  accepted-batch lookup, escrow decrement, executed-withdrawal replay
  protection, and mempool duplicate tracking
- `EXECUTE_VERIFIED_WITHDRAWALS` now uses deterministic Merkle-style
  inclusion proofs instead of the temporary full-list withdrawal mode
- `EXECUTE_ESCAPE_EXIT` now has fixed escape-exit leaf encoding, inactivity
  gating, escrow decrement, executed-exit replay protection, and mempool
  duplicate tracking
- `EXECUTE_ESCAPE_EXIT` now uses deterministic Merkle-style proof objects
  against `current_state_root`, but it is still scaffold-only because those
  proofs are not yet backed by the final user-state circuit
- `getvaliditysidechaininfo` exposes the scaffold proof-config registry and
  registration, force-exit, batch-validation, withdrawal, and escape-exit
  plumbing availability
- `getvaliditysidechaininfo` now also reconstructs accepted-batch publication
  metadata from the active chain, including proof size, DA chunk count, and
  the publishing transaction id
- wallet send-path RPCs now exist for validity-sidechain registration,
  deposits, scaffold batches, force-exit requests, and stale-deposit reclaim
- the legacy `getdrivechaininfo`, `senddrivechainbundle`, and
  `senddrivechainexecute` RPC surfaces are now explicitly marked deprecated,
  while the underlying legacy consensus path remains active during migration
- validity-sidechain tip snapshots now persist across connect/load/disconnect,
  and ancestor snapshot replay now uses persisted by-hash validity-sidechain
  snapshots during rollback/restart recovery, with competing-fork rollback
  coverage for accepted batches, verified withdrawals, and escape exits
- trustless proof verification, DA-carrying batches, proof-backed queue
  consumption, full force-inclusion enforcement, and final per-proof
  escape-exit semantics are still outstanding

## 8. Bottom Line

The current drivechain code can be a useful escrow-accounting starting point, but
it is not a small patch away from a trustless design. The trustless target is a
new protocol family with a different authorization model, different state
machine, different RPC surface, and stricter data-availability requirements.
