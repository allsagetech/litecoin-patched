# Activation Requirements: Validity-Enforced Sidechains

This document defines the minimum conditions under which the protocol described
in `doc/validity-sidechains/LIP-validity-sidechains.md` may be described as
trustless or considered for activation planning.

If any item in this document is unmet, the project should describe the design as
an incomplete draft rather than a trustless sidechain system.

## 1. Consensus Completeness Gates

The following consensus features are mandatory:

- A fixed, Litecoin-reviewed verifier set. Arbitrary user-supplied verifier code
  or verifying keys are not acceptable for V1.
- Explicit resource bounds on proof bytes, public inputs, queue processing, DA
  payload size, and withdrawal execution fanout.
- Onchain-enforced data availability for every accepted batch.
- An L1 message queue for deposits and forced exits, with deterministic queue
  root and head tracking.
- A trustless deposit path in which peg-ins either become finalized sidechain
  state or become reclaimable on Litecoin.
- `RECLAIM_STALE_DEPOSIT` or an equivalent recovery path for unconsumed deposits.
- `REQUEST_FORCE_EXIT` or equivalent forced inclusion for censored users.
- `EXECUTE_ESCAPE_EXIT` or equivalent halt recovery against the latest finalized
  state root.
- Replay protection for all executed withdrawals and escape exits.
- Reorg-safe state transitions for accepted batches, queue state, escrow
  balances, and nullifier sets.

## 2. Testing Gates

The following test categories are mandatory:

- Unit tests for transaction parsing, config hashing, queue hashing, nullifier
  handling, and state-transition invariants.
- Verifier tests using valid and invalid proof vectors for every supported proof
  family.
- DA tests covering missing chunks, malformed chunk ordering, oversized payloads,
  and mismatched `data_root` commitments.
- Queue-consumption tests covering deposits, forced exits, stale-deposit
  reclaim, and queue ordering edge cases.
- Reorg tests for accepted batches, executed withdrawals, stale-deposit reclaim,
  and escape exits.
- Functional tests proving that a censored user can still recover through
  forced inclusion or escape exits.
- Denial-of-service tests for worst-case proof size, maximum DA payload,
  withdrawal fanout, and queue growth.

## 3. Review Gates

The following reviews are mandatory before any activation decision:

- External review of verifier integration and consensus resource accounting.
- External review of the supported circuit family and public-input binding.
- Review of the DA design proving that users can reconstruct state and exit
  data without trusted operators.
- Review of the deposit recovery path proving that peg-ins cannot be trapped in
  escrow indefinitely.
- Review of the forced inclusion and escape-exit model under censorship and
  sequencer halt.

## 4. No-Go Conditions

Activation should be blocked if any of the following remain true:

- DA depends on a trusted committee, operator-hosted blobs, or social promises.
- Deposits can be locked on Litecoin without a deterministic reclaim path.
- Forced exits exist only on paper and are not consensus-enforced.
- Escape exits are absent or depend on a trusted coordinator.
- The protocol still relies on miner voting or owner signatures to authorize
  peg-outs.
- The verifier/circuit path has not been benchmarked to safe node-validation
  costs.

## 5. Naming Discipline

The project should not describe the design as:

- `trustless`
- `production-ready`
- `activation candidate`

until every requirement above is satisfied.

Before that point, the correct description is:

- `draft validity-sidechain design`
- `incomplete trustless sidechain redesign`
- `pre-activation research and implementation work`
