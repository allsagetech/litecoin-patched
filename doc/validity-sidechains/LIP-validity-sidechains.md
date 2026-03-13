LIP: DRAFT
Title: Litecoin Validity-Enforced Sidechains
Author: AllSageTech, LLC / support@allsagetech.com
Status: Draft
Type: Standards Track - Consensus
Created: 2026-03-11
License: MIT

Companion implementation-status doc:
`doc/validity-sidechains/IMPLEMENTATION_STATUS.md`

---

# Abstract

This draft defines a trustless sidechain model for Litecoin in which peg-outs are
authorized by Litecoin consensus verification of zk-validity proofs, not by miner
votes, owner signatures, or federated custody. LTC is locked in a sidechain
escrow on Litecoin, sidechain batches are finalized only when Litecoin validates
their proofs and data-availability commitments, and withdrawals are released only
when Litecoin verifies inclusion against an accepted withdrawal root.

This protocol is not classic drivechain. The miner-voted withdrawal model is
replaced by proof-verified batch commitments, permissionless withdrawal
execution, forced inclusion of L1 exit requests, and an escape hatch for
sequencer halt.

---

# Motivation

The current drivechain-style model is trust-minimized, but not trustless:

- miners decide whether a withdrawal bundle is valid
- operators can be given owner-auth powers over bundle commits
- Litecoin does not verify the sidechain's state-transition correctness

If the design goal is trustless technology, that authorization model is not
sufficient. Litecoin itself must reject invalid peg-outs even if every miner and
every operator wants the withdrawal to succeed.

This draft therefore changes the security boundary:

- invalid withdrawals fail because the proof or inclusion data is invalid
- valid withdrawals do not require miner or owner discretion
- users retain an exit path if the sequencer censors or halts, provided data
  availability and force-exit rules are satisfied

---

# Goals

- Make peg-out correctness depend on Litecoin consensus verification, not social
  trust.
- Remove miner voting from withdrawal authorization.
- Remove owner-auth from withdrawal authorization.
- Allow only sidechains whose proof system and circuit family are explicitly
  supported by Litecoin consensus.
- Require data availability sufficient for safe exits.
- Provide censorship resistance through forced inclusion and halt recovery.

# Non-Goals

- Supporting arbitrary user-defined verifier code on Litecoin.
- Supporting arbitrary sidechain state models with no standard exit format.
- Preserving BIP300/BIP301 semantics under the new protocol name.
- Using off-chain operator promises as the safety model for peg-outs.

---

# Terminology

- `Validity sidechain`: A sidechain whose batches are accepted only when Litecoin
  verifies a supported zk-validity proof.
- `Sequencer`: The party or parties ordering sidechain transactions and producing
  batches.
- `Batch`: A finalized sidechain state-transition carrying a new state root,
  withdrawal root, and data-availability commitment.
- `L1 message queue`: The ordered queue of Litecoin-originating deposits and
  forced-exit requests that batches must consume.
- `Withdrawal root`: Commitment to the set of L1 withdrawals authorized by a
  finalized batch.
- `Deposit request`: An L1 peg-in message waiting to be consumed by a finalized
  batch or reclaimed on Litecoin.
- `Force-exit request`: An L1 message requiring the sidechain to include a user
  exit within a bounded delay.
- `Escape exit`: An L1 withdrawal path directly against the latest finalized
  state root, used if the sequencer halts.

---

# Security Model

The trustless claim of this protocol depends on all of the following:

1. Litecoin verifies the zk-validity proof for each finalized batch.
2. Litecoin enforces data-availability publication for every finalized batch.
3. Litecoin records enough state to prevent double execution of withdrawals.
4. Users can force inclusion of exits while the sequencer is live.
5. Users can escape against the latest finalized state if the sequencer halts.
6. Users can reclaim deposits that the sequencer refuses to consume.

If any of these are missing, the system is not fully trustless.

---

# Supported Sidechain Class

Only sidechains matching a Litecoin-supported proof configuration may register.

Each supported configuration is defined in Litecoin consensus by:

- `proof_system_id`
- `circuit_family_id`
- `verifier_id`
- `public_input_version`
- `state_root_format`
- `deposit_message_format`
- `withdrawal_leaf_format`
- `balance_leaf_format`
- `data_availability_mode`
- `max_batch_data_bytes`

V1 of this protocol SHOULD support only a small, fixed set of verifier/circuit
combinations compiled into consensus code. Arbitrary user-supplied verifying
keys are out of scope for the initial rollout because they dramatically expand
the consensus attack surface and denial-of-service risk.

---

# Consensus Resource Limits

The protocol must bound consensus verification cost explicitly.

Chain-defined limits must cap at least:

- `max_proof_bytes`
- `max_batch_data_bytes`
- `max_public_inputs_bytes`
- `max_withdrawals_per_execute`
- `max_l1_messages_consumed_per_batch`

Transactions exceeding these limits are invalid even if the cryptographic proof
itself would verify. The trustless design is not acceptable if it exposes
Litecoin nodes to unbounded verifier or data-availability denial-of-service
costs.

---

# L1 Message Queue

Each registered validity sidechain has an ordered L1 message queue maintained by
Litecoin consensus.

The queue contains standardized Litecoin-originating messages:

- deposit requests
- force-exit requests

Each accepted batch must prove a valid transition from
`l1_message_root_before` to `l1_message_root_after`, consuming a contiguous
prefix of pending messages. Messages may leave the queue only by:

- being consumed by an accepted batch, or
- being explicitly tombstoned by an L1 recovery path such as stale-deposit
  reclaim

This queue is required so deposits and forced exits cannot be silently ignored
by the sequencer.

The implementation should also track a queue head index or equivalent compact
state so contiguous-prefix consumption is unambiguous under reorgs and does not
require replaying the entire queue history.

---

# Transaction Families

This draft assumes the implementation may temporarily reuse the existing
`OP_DRIVECHAIN (0xb4)` transport opcode while the codebase is migrated away from
drivechain naming. The normative protocol names below describe the target
semantics, not the temporary wire label.

All validity-sidechain outputs have the form:

```text
OP_RETURN
OP_DRIVECHAIN
<1-byte: sidechain_id>
<32-byte: payload>
<1-byte: tag>
```

## Tags

| Tag  | Meaning |
|------|---------|
| 0x06 | REGISTER_VALIDITY_SIDECHAIN |
| 0x07 | DEPOSIT_TO_VALIDITY_SIDECHAIN |
| 0x08 | COMMIT_VALIDITY_BATCH |
| 0x09 | EXECUTE_VERIFIED_WITHDRAWALS |
| 0x0A | REQUEST_FORCE_EXIT |
| 0x0B | RECLAIM_STALE_DEPOSIT |
| 0x0C | EXECUTE_ESCAPE_EXIT |

The temporary tag range begins at `0x06` so the staged migration does not
collide with the legacy drivechain `REGISTER` tag `0x05` while both parsers
still exist in the codebase.

---

# REGISTER_VALIDITY_SIDECHAIN

`REGISTER_VALIDITY_SIDECHAIN` binds a Litecoin sidechain ID to a supported proof
configuration and an initial state.

The `payload` is:

```text
sidechain_config_hash
```

The next pushed data item after the tag encodes:

- protocol version
- proof_system_id
- circuit_family_id
- verifier_id
- public_input_version
- state_root_format
- deposit_message_format
- withdrawal_leaf_format
- balance_leaf_format
- data_availability_mode
- max_batch_data_bytes
- max_proof_bytes
- force_inclusion_delay
- deposit_reclaim_delay
- escape_hatch_delay
- initial_state_root
- initial_withdrawal_root

Consensus rules:

- the encoded configuration must hash to `sidechain_config_hash`
- the `(proof_system_id, circuit_family_id, verifier_id, public_input_version)`
  tuple must be present in Litecoin consensus parameters
- `data_availability_mode` must be one of the Litecoin-supported trustless DA
  modes
- `max_batch_data_bytes`, `force_inclusion_delay`, `deposit_reclaim_delay`, and
  `escape_hatch_delay` must be within chain-defined bounds

Registration does not carry owner-auth state. The protocol deliberately removes
owner keys from withdrawal authorization.

---

# DEPOSIT_TO_VALIDITY_SIDECHAIN

`DEPOSIT_TO_VALIDITY_SIDECHAIN` locks LTC into sidechain escrow and inserts a
deposit request into the sidechain's L1 message queue.

The `payload` is:

```text
deposit_message_hash
```

The encoded deposit metadata binds:

- `sidechain_id`
- `deposit_id`
- `amount`
- `destination_commitment`
- `refund_script_commitment`
- `nonce`

`deposit_id` must uniquely bind the deposit transaction, output position, and
nonce so the same escrowed output cannot be reclaimed or consumed twice under a
different identifier.

Consensus rules:

- the sidechain must already be registered
- the encoded deposit message must hash to `deposit_message_hash`
- `amount` must be within Litecoin money range and greater than zero
- the transaction must lock exactly `amount` into the sidechain escrow
- the `(deposit_id, amount, destination_commitment, refund_script_commitment,
  nonce)` tuple must be appended to the sidechain's L1 message queue

State updates on success:

- increment sidechain escrow by `amount`
- record the pending deposit request and its queue position
- update the Litecoin-maintained `l1_message_queue_root`

If the sequencer never consumes this deposit into a finalized batch, the user
must be able to recover it through `RECLAIM_STALE_DEPOSIT`.

---

# COMMIT_VALIDITY_BATCH

`COMMIT_VALIDITY_BATCH` finalizes a new sidechain batch.

The `payload` is:

```text
batch_commitment_hash
```

The transaction carries the following public inputs, either as pushed metadata or
via a dedicated witness encoding:

- `batch_number`
- `prior_state_root`
- `new_state_root`
- `l1_message_root_before`
- `l1_message_root_after`
- `consumed_queue_messages`
- `withdrawal_root`
- `data_root`
- `data_size`

The transaction also carries:

- `proof_bytes`
- zero or more DA chunks whose ordered hash commitment must equal `data_root`

Consensus rules:

- the sidechain must already be registered
- `prior_state_root` must equal the sidechain's current finalized state root
- `batch_number` must be strictly monotonic
- `proof_bytes` must not exceed `max_proof_bytes`
- the `(prior_state_root, new_state_root, withdrawal_root, data_root,
  l1_message_root_before, l1_message_root_after, consumed_queue_messages,
  batch_number, sidechain_id)` tuple must be bound into the proof's public
  inputs
- the proof must verify under the registered verifier configuration
- `l1_message_root_before` must equal the current Litecoin-maintained queue root
- the batch must consume exactly `consumed_queue_messages` messages from the
  current contiguous pending queue prefix and produce
  `l1_message_root_after`
- all matured L1 force-exit requests must be included in the consumed prefix
- any pending deposit request left unconsumed past `deposit_reclaim_delay`
  becomes reclaimable on Litecoin and must not remain permanently stuck
- the batch's DA payload must be published in the same transaction and must hash
  to `data_root`
- `data_size` must not exceed `max_batch_data_bytes`

State updates on success:

- `current_state_root = new_state_root`
- `l1_message_queue_root = l1_message_root_after`
- advance the queue head / mark the consumed queue prefix as processed
- record `(batch_number, withdrawal_root, data_root, accepted_height)`
- append published DA metadata needed for forced exits and auditability

Current scaffold implementation note:

- the current branch only enables `scaffolding_only` batch validation
- both scaffold modes require `proof_bytes` to be a deterministic scaffold
  envelope binding the batch commitment and the current chainstate roots
- `scaffold_queue_prefix_commitment_v1` only accepts no-op batches:
  - no DA chunks are present
  - `new_state_root`, `withdrawal_root`, and `data_root` remain unchanged
- `scaffold_transition_commitment_v1` accepts deterministic root and DA
  transitions, but still without a real zk proof backend
- queue-prefix consumption is still allowed in scaffold mode, and all matured
  force-exit requests in the reachable prefix must be consumed
- this is plumbing for the future verifier path, not trustless batch
  finalization

Miner approval is not part of batch finalization.

---

# Data Availability

zk-validity alone is not enough. A sidechain is only safe to use if users can
obtain the data needed to reconstruct the state, detect censorship, and form an
exit.

V1 rules:

- every accepted batch must publish its DA payload on Litecoin in the same
  transaction that commits the batch
- `data_root` commits to an ordered list of batch data chunks
- the full set of chunks must be available to full nodes at validation time
- batches lacking DA payload are invalid

If Litecoin cannot economically carry the required DA payload, the protocol is
not ready for activation. Off-chain DA committees or operator-hosted blobs do
not satisfy the trustless requirement of this draft.

---

# EXECUTE_VERIFIED_WITHDRAWALS

`EXECUTE_VERIFIED_WITHDRAWALS` pays one or more mainchain withdrawal outputs from
an already accepted `withdrawal_root`.

The marker output `payload` is:

```text
accepted_batch_id
```

`accepted_batch_id` must uniquely bind at least:

- `sidechain_id`
- `batch_number`
- `withdrawal_root`

The transaction contains:

- one marker output
- `n` mainchain payout outputs immediately after the marker
- witness metadata describing each withdrawal leaf
- inclusion proofs from each leaf to the accepted `withdrawal_root`
- withdrawal nullifiers or unique leaf identifiers

Consensus rules:

- the referenced batch must exist and must have an accepted `withdrawal_root`
- every withdrawal leaf must be included in that `withdrawal_root`
- no withdrawal nullifier or leaf identifier may have been executed before
- each payout output must exactly match the corresponding withdrawal leaf
- the sidechain escrow must cover the total payout amount

State updates on success:

- decrement sidechain escrow by the executed total
- mark all referenced nullifiers or leaf IDs as spent

Anyone may submit this transaction. No owner signature and no miner vote is
required.

Current scaffold implementation note:

- the current branch now implements deterministic Merkle-style withdrawal
  inclusion proofs for `EXECUTE_VERIFIED_WITHDRAWALS`
- the transaction carries one proof object per executed withdrawal leaf
- Litecoin verifies each proof against the accepted batch `withdrawal_root`
- per-withdrawal replay protection is enforced by executed withdrawal IDs
- this is still execution plumbing because the accepted batch itself is not yet
  proven by a real zk verifier

---

# REQUEST_FORCE_EXIT

`REQUEST_FORCE_EXIT` lets a user post an L1 withdrawal intent directly to
Litecoin when the sequencer is censoring them.

The request binds:

- sidechain id
- user key or account identifier
- exit asset id
- maximum exit amount
- destination script or address commitment
- nonce

Consensus behavior:

- the request is inserted into an L1 force-message queue for that sidechain
- the Litecoin-maintained `l1_message_queue_root` is updated accordingly
- after `force_inclusion_delay`, any valid batch must show the request as
  consumed or converted into a withdrawal authorization path

This rule gives users a censorship-resistant path while the sequencer continues
to post batches.

Current scaffold implementation note:

- the current branch now validates and stores `REQUEST_FORCE_EXIT` messages on
  the Litecoin side
- pending and matured force-exit request counts are tracked in chainstate and
  exposed by RPC
- duplicate force-exit request hashes are rejected in mempool and block
  validation
- scaffold `COMMIT_VALIDITY_BATCH` now supports deterministic queue-prefix
  consumption with no proof bytes and no state-root / withdrawal-root changes
- matured force-exit requests in the currently reachable pending queue prefix
  must be consumed by an accepted scaffold batch
- full trustless force-inclusion still requires real proof verification of the
  sidechain transition, not just deterministic L1 queue accounting

---

# RECLAIM_STALE_DEPOSIT

`RECLAIM_STALE_DEPOSIT` returns a deposit to its original Litecoin owner if the
deposit request remains pending on the L1 message queue past
`deposit_reclaim_delay`.

The marker output `payload` is:

```text
deposit_id
```

The transaction contains:

- one marker output
- a refund payout output matching the registered `refund_script_commitment`
- metadata proving the referenced deposit request

Consensus rules:

- the referenced deposit request must still be pending in the L1 message queue
- the deposit request must not have been consumed by any accepted batch
- the current height must be at least `deposit_height + deposit_reclaim_delay`
- the refund output amount must exactly equal the locked deposit amount

State updates on success:

- decrement sidechain escrow by the reclaimed amount
- tombstone the deposit request in the L1 message queue so later batches cannot
  consume it
- update the Litecoin-maintained `l1_message_queue_root`

This rule prevents deposits from being trapped indefinitely if the sequencer
refuses to include them.

---

# EXECUTE_ESCAPE_EXIT

`EXECUTE_ESCAPE_EXIT` is the halt-recovery path. It allows a user to withdraw
directly from the latest finalized sidechain state if no valid batch has been
posted for `escape_hatch_delay`.

The transaction carries:

- reference to the latest finalized state root
- user balance or UTXO leaf
- proof of inclusion in that state root
- nullifier or one-time exit identifier
- payout outputs matching the proven leaf

Consensus rules:

- no batch may have advanced the sidechain within `escape_hatch_delay`
- the sidechain configuration must expose a Litecoin-supported `balance_leaf`
  format for escape exits
- the user's state proof must be valid against the latest finalized root
- the exit must not have been executed before

Current scaffold note:

- the current branch now uses deterministic Merkle-style escape-exit proof
  objects instead of the temporary full-list leaf encoding
- each claim still references the latest accepted `current_state_root` and
  proves membership in a staging escape-exit tree, not a final user balance
  circuit
- this is plumbing for replay protection and exact payout enforcement, not the
  final trustless per-user state-proof design

Without this mechanism, a halted sequencer can still trap users even if every
posted batch was valid.

---

# Sidechain State Tracked by Litecoin

Litecoin consensus must track at least:

- sidechain id
- registered proof configuration
- finalized state root
- latest accepted batch number
- accepted withdrawal roots by batch
- accepted DA roots by batch
- L1 message queue root
- L1 message queue head index
- time/height of the last accepted batch
- sidechain escrow balance
- pending deposit request records
- executed withdrawal nullifiers or executed leaf identifiers
- executed escape-exit nullifiers

This replaces the drivechain state model of owner-auth policies, vote windows,
bundle yes/no counts, and approval delays.

---

# BMM and Block Production

Blind merged mining is orthogonal to trustless withdrawals.

If Litecoin wishes to keep a BMM market for sidechain block production, that
logic must be decoupled from peg authorization. A sidechain may use merged
mining, proof-of-stake, centralized sequencing, or any other block-production
scheme, but LTC escrow release still depends only on the validity-sidechain
consensus rules above.

---

# Security Properties

If this draft is implemented correctly:

- invalid peg-outs fail unless the verifier, circuit, or consensus code is
  broken
- miner collusion cannot approve an invalid withdrawal
- operator collusion cannot approve an invalid withdrawal
- users retain a censorship-resistant path through forced inclusion
- users can reclaim unconsumed deposits instead of leaving them indefinitely
  trapped in escrow
- users retain a halt-recovery path through escape exits

Residual risks remain:

- verifier bugs
- circuit bugs
- data-availability bandwidth limits
- denial-of-service against proof verification
- denial-of-service through unbounded L1 message queue growth if limits are
  poorly chosen
- incorrect leaf-format standardization

---

# Open Design Questions

- Which proof systems should be supported in V1: Groth16, Plonkish variants,
  STARKs, or a single proving family only?
- Should proof verification be implemented directly in consensus or through a
  limited verifier registry abstraction?
- Can Litecoin economically support calldata-style DA, or is a separate
  witness/blob extension required first?
- Should accepted batches be final immediately, or require a short fraud-proof
  challenge window even in a validity-proof design?
- Should stale deposits be reclaimable immediately after timeout, or only after
  an additional queue-halt condition?
- Should escape exits prove account balances, UTXOs, or a standardized exit-note
  leaf format?

---

# Implementation Guidance

This draft should be implemented as a new protocol family in the codebase, not
as a cosmetic rename of drivechain. The current drivechain-specific concepts of
bundle voting, owner-auth commit signatures, and miner approval windows should
be retired from the withdrawal path entirely.

The protocol should not be described as fully trustless until all of the
following ship together:

- proof-verified batch acceptance
- onchain-enforced DA publication
- L1 message queue consumption
- stale-deposit reclaim
- forced inclusion
- escape exits
