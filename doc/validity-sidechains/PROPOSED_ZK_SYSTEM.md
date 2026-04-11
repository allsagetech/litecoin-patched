# Proposed ZK System: Validity Batch Proof V2

This file defines the canonical zk target for the validity-sidechain design in
this branch.

It is a proposal, not an implemented verifier backend.

## 1. Goal

Replace the current scaffold batch verifier with a real proof system that lets
Litecoin consensus verify:

- a proven state transition from `prior_state_root` to `new_state_root`
- a proven ordered withdrawal set committed by `withdrawal_root`
- binding of the accepted DA payload via `data_root` and `data_size`
- binding of the batch transition to the exact L1 queue prefix consumed by the
  batch

This proposal keeps:

- onchain data availability on Litecoin
- L1-controlled queue head / maturity / reclaim logic
- L1 execution of verified withdrawals and escape exits

## 2. Chosen Shape

### Proof system

- proving system: `Groth16`
- curve: `BLS12-381`
- verifier library in node: small embedded Groth16 verifier backed by a
  BLS12-381 pairing library
- circuit implementation: Rust prover/circuit crate

Why this choice:

- proof size is small and fixed
- verifier cost is low enough for full-node validation
- public-input handling is simple
- the branch only needs one fast batch proof path first, not a universal proof
  system

This does require a circuit-specific trusted setup per circuit version.

## 3. Canonical Profile Tuple

The canonical end-state profile should be a fixed registry entry:

- `profile_name = "groth16_bls12_381_poseidon_v2"`
- `scaffolding_only = false`
- `version = 1`
- `proof_system_id = 2`
- `circuit_family_id = 1`
- `verifier_id = 1`
- `public_input_version = 5`
- `state_root_format = 2`
- `deposit_message_format = 1`
- `withdrawal_leaf_format = 2`
- `balance_leaf_format = 2`
- `data_availability_mode = 1`

The exact numeric ids are less important than fixing one tuple and treating it
as consensus.

The current branch still carries `groth16_bls12_381_poseidon_v1` as a
scalar-limited migration profile for committed vectors and compatibility work.
That profile should be treated as transitional only. The intended final shape
uses `v2` so full-width queue, withdrawal, and DA roots are decomposed into
128-bit limbs as part of the public-input contract.

## 4. State Commitments

### State tree

Use a Poseidon-based Merkle tree over account leaves.

Account leaf:

```text
Poseidon(
  account_id,
  spend_key_commitment,
  balance_root,
  account_nonce,
  last_forced_exit_nonce
)
```

Balance leaf:

```text
Poseidon(asset_id, balance)
```

`current_state_root` and `new_state_root` are the Poseidon Merkle roots of this
tree, encoded into 32 bytes.

### Withdrawal tree

Use an ordered Poseidon Merkle tree:

```text
Poseidon(withdrawal_id, amount, destination_commitment)
```

This root is published as `withdrawal_root` and later used by Litecoin to
verify `EXECUTE_VERIFIED_WITHDRAWALS`.

### Queue prefix commitment

Do not force the circuit to emulate the Litecoin queue-root accumulator.

Instead, add one extra public input:

- `queue_prefix_commitment`

This is a Poseidon Merkle root over the exact ordered consumed queue messages.

Queue message leaf:

- deposit:

```text
Poseidon(
  kind = 1,
  deposit_id,
  amount,
  destination_commitment,
  refund_script_commitment,
  nonce
)
```

- force exit:

```text
Poseidon(
  kind = 2,
  request_hash,
  account_id,
  exit_asset_id,
  max_exit_amount,
  destination_commitment,
  nonce
)
```

Litecoin computes this commitment from the actual queue prefix it consumes.
The circuit computes the same commitment from the private witness and proves it
used exactly that message sequence.

This avoids redesigning the Litecoin queue root while still binding the proof
to the exact consumed L1 messages.

## 5. Public Inputs

The first real proof profile should bind these public inputs:

1. `sidechain_id`
2. `batch_number`
3. `prior_state_root`
4. `new_state_root`
5. `l1_message_root_before`
6. `l1_message_root_after`
7. `consumed_queue_messages`
8. `queue_prefix_commitment`
9. `withdrawal_root`
10. `data_root`
11. `data_size`

Notes:

- `l1_message_root_before` and `l1_message_root_after` remain Litecoin-side
  consensus checks
- `queue_prefix_commitment` is what binds the proof to the actual consumed
  messages
- `data_root` and `data_size` bind the proof to the DA payload accepted on L1

## 6. Private Witness

The prover witness contains:

- the pre-state account tree witnesses for all touched accounts
- the post-state updates for those accounts
- the exact ordered consumed queue messages
- the ordered batch transaction list / batch execution trace
- the ordered withdrawal leaf list

The witness does not need to include the full DA payload inside the circuit.
Litecoin already validates the DA payload onchain and binds it through
`data_root`.

## 7. Circuit Rules

The `ValidityBatchCircuitV1` proves:

- `prior_state_root` matches the witnessed pre-state
- the circuit applied exactly the queue messages committed by
  `queue_prefix_commitment`
- deposit messages increase the correct account balance
- force-exit messages either:
  - create the required exit effect in state, or
  - reduce the account to an exited / nullified state according to protocol
- the ordered withdrawal list produced by the transition hashes to
  `withdrawal_root`
- the resulting state hashes to `new_state_root`
- `batch_number`, `sidechain_id`, `data_root`, and `data_size` are bound into
  the proof
- total balance conservation holds except for withdrawals emitted by the batch

The circuit does not need to prove Litecoin block height or deposit reclaim
windows. Those remain L1 consensus checks over queue state.

## 8. Litecoin Consensus Checks Outside The Proof

Even with the zk proof, Litecoin still performs deterministic consensus checks:

- verify the Groth16 proof against the pinned verifying key
- reject oversized proof bytes
- reject missing chunks, malformed chunk ordering, oversized payloads, and bad
  `data_root`
- verify `prior_state_root` equals the current finalized root
- verify batch number monotonicity
- verify `l1_message_root_before` equals the current queue root
- compute the exact contiguous consumed prefix from queue state
- compute `l1_message_root_after` from that prefix and compare it to the public
  input
- compute `queue_prefix_commitment` from that same prefix and compare it to the
  public input
- enforce matured force-exit inclusion in the consumed prefix
- update queue head and pending-record state

That split is intentional: Litecoin stays authoritative for L1 queue semantics,
while the proof becomes authoritative for how those consumed messages changed
sidechain state.

## 9. Withdrawals And Escape Exits

### Verified withdrawals

Keep the current model:

- batch proof outputs `withdrawal_root`
- Litecoin later verifies ordered Merkle proofs against that accepted root
- each withdrawal id remains single-execution on Litecoin

### Escape exits

Do not add a second zk proof family first.

Instead, make `EXECUTE_ESCAPE_EXIT` verify a Poseidon Merkle proof against the
accepted account state root:

```text
Poseidon(account_id, spend_key_commitment, balance_root, account_nonce, last_forced_exit_nonce)
```

The escape-exit leaf or account leaf must carry enough balance / nonce data for
Litecoin to verify:

- account inclusion in the accepted state root
- exit amount does not exceed the committed balance
- exit nullifier / nonce has not already been executed

This keeps escape exits trustless without needing a second recursive circuit.

## 10. Verifier Assets This Design Needs

For this design, the repo needs concrete assets:

- `batch_vk.bin`
  - pinned Groth16 verifying key for `ValidityBatchCircuitV1`
- `profile.json`
  - the exact fixed tuple and limits for the supported profile
- `valid/`
  - valid proof vectors with public inputs, proof bytes, DA chunks, and
    expected acceptance
- `invalid/`
  - malformed proof vectors: wrong public inputs, wrong queue prefix
    commitment, wrong `data_root`, wrong withdrawal root, corrupted proof, and
    wrong verifier key

Suggested repo layout:

```text
artifacts/
  validitysidechain/
    groth16_bls12_381_poseidon_v1/
      profile.json
      batch_vk.bin
      valid/
      invalid/
```

## 11. Why This Is A Good Fit For This Repo

It matches the current branch shape:

- accepted batches already carry `new_state_root`, `withdrawal_root`, and
  `data_root`
- Litecoin already tracks queue state and can deterministically compute the
  consumed prefix
- Litecoin already has withdrawal and escape-exit execution paths that work off
  accepted roots

So the real delta is concentrated in:

- a verifier backend in `src/validitysidechain/verifier.*`
- one real registry profile in `src/validitysidechain/registry.*`
- proof-vector tests
- converting escape exits from scaffold staging proofs to state-root proofs

## 12. Non-Goals For V1

This proposal does not try to do all of the following at once:

- recursive proofs
- universal proof systems
- proof aggregation across batches
- proof-carrying DA
- replacing Litecoin-controlled queue maturity / reclaim logic

V1 should optimize for one thing: a small, fast, consensus-safe batch verifier
that makes the branch honestly trustless.
