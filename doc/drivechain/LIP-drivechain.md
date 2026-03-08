LIP: 0005
Title: Miner-Enforced Sidechains for Litecoin
Author: AllSageTech, LLC / support@allsagetech.com
Status: Final
Type: Standards Track - Consensus
Created: 2025-12-10
License: MIT

---

# Abstract

This proposal defines Litecoin-native, miner-enforced sidechains. LTC is locked on the Litecoin mainchain, sidechains are produced via blind merged mining, and LTC can be released only through a pre-committed withdrawal bundle that Litecoin miners approve on-chain over fixed vote windows. The design is inspired by BIP300/301, but LIP-0005 is specified for Litecoin's 2.5-minute blocks, scrypt miner set, and activation policy.

This soft fork adds a new opcode (`OP_DRIVECHAIN`) and new output type (`TxoutType::DRIVECHAIN`) which enable six operations:

1. **DEPOSIT** - Lock LTC into a sidechain escrow
2. **REGISTER** - Bind sidechain ownership to an owner key hash
3. **BUNDLE_COMMIT** - Publish a hash of a sidechain withdrawal bundle
4. **VOTE_YES** - Cast a miner approval vote for bundle finalization (coinbase only)
5. **VOTE_NO** - Cast an explicit miner rejection signal (coinbase only)
6. **EXECUTE** - Release escrow to mainchain addresses after approval and finalization

Security comes from objective Litecoin consensus rules, not from a federation and not from asking miners to validate arbitrary sidechain state. Mainchain consensus tracks only deterministic facts: sidechain registration, escrow balances, bundle identity, fixed vote windows, approval thresholds, owner-authenticated bundle publication, finalization delay, and exact execute-template matching. Approval requires sustained miner participation across an 8,064-block Litecoin window, with the threshold measured against the total blocks in that window rather than only the votes cast.

---

# Motivation

Litecoin is well suited for miner-enforced sidechains. Its faster block cadence permits long observation windows without extreme wall-clock delay, its scrypt miner set can monetize additional sidechain demand through blind merged mining, and LTC can remain the shared monetary base across experimental environments.

The core design principle is deliberate: rely more on miners by giving them more enforcement, not more subjectivity.

LIP-0005 is intended to let Litecoin:

- Add entirely new feature sets without modifying the mainchain  
- Host alternative execution environments  
- Experiment with privacy and ZK systems  
- Scale without fragmenting liquidity  
- Enable synthetic assets or stablecoins  
- Provide a trust-minimized sidechain ecosystem
- Give scrypt miners direct fee revenue from sidechain activity
- Make withdrawal theft require sustained coordination across thousands of Litecoin blocks

This proposal therefore gives miners a narrow, high-consequence role: approve or reject a pre-committed withdrawal bundle. Everything else remains objective mainchain validation. Miners do not need to run sidechain nodes to enforce LIP-0005, and the protocol does not depend on custodians or federated multisigs.

---

# Specification

## 1. Drivechain Output Structure

Every drivechain output contains:

```text
OP_RETURN
OP_DRIVECHAIN
<1-byte: sidechain_id>
<32-byte: payload>
<1-byte: tag>
```

### Tags

| Tag  | Meaning |
|------|---------|
| 0x00 | DEPOSIT |
| 0x01 | BUNDLE_COMMIT |
| 0x02 | VOTE_YES |
| 0x03 | EXECUTE |
| 0x04 | VOTE_NO |
| 0x05 | REGISTER |

Any other tag makes the output invalid.

---

## 2. Opcode Definition: `OP_DRIVECHAIN (0xb4)`

### Pre-activation  
Behaves as an upgradable NOP, failing under `SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS`.

### Post-activation  
Enforces full encoding rules and dispatches to consensus logic.

---

## 3. New Output Type: `TxoutType::DRIVECHAIN`

Drivechain outputs are unspendable and used only to signal state transitions.

Wallets treat them as:

- Not spendable  
- Not part of the user's balance  
- Never mineable  

---

# Sidechain State Model (Mainchain Tracked)

### Sidechain Fields
- `id` - 1-byte integer
- `escrow_balance` - aggregated deposits minus executed withdrawals
- `creation_height` - first time a REGISTER appears
- `is_active` - always true once seen (simple activation model)
- `bundles` - mapping of bundle_hash -> Bundle

### Bundle Fields
- `hash` - 32-byte payload
- `first_seen_height`  
- `yes_votes`  
- `no_votes`
- `approval_height`
- `executable_height`
- `approved` (boolean)  
- `executed` (boolean)

State is deterministic and regenerated on reorgs.

---

# Deposit (Peg-in)

A `DEPOSIT` output:

- Increases `escrow_balance[sidechain_id] += value`  
- Requires sidechain to already exist via a confirmed REGISTER  
- Payload is opaque (sidechain interprets it, e.g. an address commitment)  

Consensus ensures:

- Deposits cannot be negative  
- Deposits cannot overflow  
- Deposits revert during reorgs  

---

# Withdrawal Bundles

A withdrawal bundle is constructed by the sidechain using **canonical hashing**:

## Canonical Bundle Encoding

The bundle hash is computed as:

```text
bundle_hash = SHA256d(
    sidechain_id (1 byte) ||
    count (4 bytes LE) ||
    [withdrawal entries...]
)
```

Each withdrawal entry encodes:

```text
amount (8 bytes LE)
scriptPubKey_length (1 byte)
scriptPubKey (byte array)
```

### Bundle Lifecycle Rules

- A sidechain is created by a confirmed REGISTER.
- BUNDLE_COMMIT for an unknown sidechain is invalid.
- A sidechain may have **only one active (unapproved) bundle at a time**.  
- Any new BUNDLE_COMMIT replaces the previous unapproved one.  
- Once approved, a bundle cannot be replaced until executed.

---

# Miner Voting Rules

Votes are signaled in the **coinbase**. `VOTE_YES` and `VOTE_NO` are distinct
signals, and consensus tracks both counts. Approval, however, depends only on
whether `yes_votes` reaches a threshold measured against the total number of
blocks in the voting window. This makes non-voting blocks effectively count
against approval without overloading `VOTE_NO` into a negative tally.

## Voting Constants (Consensus)

```text
VOTE_WINDOW = 8064 blocks
APPROVAL_THRESHOLD = 6048 yes votes
FINALIZATION_DELAY = 8064 blocks
VOTE_EPOCH_START = StartHeight
```

`VOTE_EPOCH_START` SHALL be the deployment `StartHeight` defined in the activation section.

## Deterministic Vote Window Assignment

For each bundle with `first_seen_height = H_first`, nodes MUST derive voting heights as:

```text
window_index      = floor((H_first - VOTE_EPOCH_START) / VOTE_WINDOW) + 1
vote_start_height = VOTE_EPOCH_START + (window_index * VOTE_WINDOW)
vote_end_height   = vote_start_height + VOTE_WINDOW - 1
approval_height   = vote_end_height + 1
executable_height = vote_end_height + FINALIZATION_DELAY + 1
```

The `+1` in `window_index` is required so voting always begins at the **next** fixed
window boundary after the commit is first seen.

Nodes MUST count votes for a bundle only in `[vote_start_height, vote_end_height]`.
Nodes MUST NOT use sliding windows derived from `first_seen_height`.

## Consensus Rules

1. `VOTE_YES` and `VOTE_NO` outputs MUST appear only in the coinbase transaction.
2. Each vote MUST reference an existing `(sidechain_id, bundle_hash)` on the active chain.
3. A `VOTE_YES` signal MUST increment `yes_votes` only when `block_height` is in
   `[vote_start_height, vote_end_height]` for that bundle.
4. A `VOTE_NO` signal MUST increment `no_votes` only when `block_height` is in
   `[vote_start_height, vote_end_height]` for that bundle.
5. A bundle SHALL become `approved = true` at `approval_height` if and only if
   `yes_votes >= APPROVAL_THRESHOLD`.
6. A bundle that does not satisfy `yes_votes >= APPROVAL_THRESHOLD` by `approval_height`
   MUST be treated as failed, MUST NOT become approved later, and MAY be replaced by a
   new `BUNDLE_COMMIT`.
7. `no_votes` MAY be exposed by RPC or miner policy, but MUST NOT subtract from
   `yes_votes`.
8. On reorg, vote totals, approval status, and executable height MUST be recomputed
   from the active chain; votes from disconnected blocks MUST NOT be retained.

---
# Execution (Peg-out)

An EXECUTE output:

- References `(sidechain_id, bundle_hash)`  
- Must output **exactly** the list of withdrawals encoded in the bundle  
- Cannot exceed escrow  
- Must not alter withdrawal amounts or destinations  
- MUST occur only at or after `executable_height` for the referenced bundle

## Validity Conditions

1. Bundle exists  
2. Bundle is approved  
3. Not previously executed  
4. `block_height >= executable_height`
5. Outputs exactly match canonical withdrawal list  
6. Sum(outputs) <= escrow
7. State updates atomically  

---

# Bundle Failure and Replacement

Bundles that fail to reach the threshold at `approval_height` are failed, not
pending:

```text
if yes_votes < APPROVAL_THRESHOLD at approval_height:
    bundle.approved = false
    bundle is failed
```

Failure MUST be interpreted using the fixed-window derivation in the
`Miner Voting Rules` section and the total-window threshold above.

Failed bundles MUST NOT be approved or executed.

An approved bundle remains the unique executable bundle for the sidechain until
it is executed. An unapproved or failed bundle MAY be replaced by a later
`BUNDLE_COMMIT`.

On reorg, `first_seen_height`, `vote_start_height`, `vote_end_height`,
`approval_height`, and `executable_height` MUST be recomputed from the active
chain, and failure or approval status MUST follow the recomputed values.

---
# Standardness Policies

Before activation:
- All drivechain outputs are non-standard.

After activation:
- All drivechain operations become standard (DEPOSIT, BUNDLE_COMMIT, VOTE_YES, VOTE_NO, EXECUTE).
- Votes outside coinbase are rejected from mempool.
- Malformed drivechain outputs rejected.
- Stale BMM requests whose `prev_main_block_hash` no longer matches the active
  tip are evicted from mempool policy.

---

# Ownership Registration

This specification includes an ownership path:

- `REGISTER` output tag (`0x05`) with owner key hash payload.
- Compact signature required over `(sidechain_id, owner_key_hash)`.
- On success, sidechain ownership is bound and owner-auth is enabled.
- If owner-auth is enabled, each `BUNDLE_COMMIT` MUST carry a valid compact
  signature over `(sidechain_id, bundle_hash)` from the registered owner key.
- `REGISTER` output value MUST be at least the chain's minimum registration amount.

RPC support:

- `senddrivechainregister` registers a sidechain owner key using a wallet-held owner address.
- If `sidechain_id` is omitted, the wallet selects the lowest currently unused ID.

---

# Activation (BIP8, LOT=false, Boundary-Aligned)

Drivechain deployment SHALL use height-based BIP8 with lock-in-on-timeout disabled
(`LOT=false`).

```text
Deployment: drivechain
Bit: 5
Activation mechanism: BIP8 (LOT = false)
nMinerConfirmationWindow: 8064 blocks
nRuleChangeActivationThreshold: 6048 blocks (75%)
StartHeight: 3,072,384
TimeoutHeight: 3,282,048
```

`StartHeight` and `TimeoutHeight` MUST satisfy:

```text
StartHeight % 8064 == 0
TimeoutHeight % 8064 == 0
TimeoutHeight > StartHeight
```

## BIP8 State Machine (Normative)

The deployment state machine is:

```text
DEFINED -> STARTED -> LOCKED_IN -> ACTIVE
DEFINED -> STARTED -> FAILED
```

The following rules are consensus-critical:

1. State transitions SHALL occur only at period boundaries where
   `height % 8064 == 0`.
2. All blocks in the same 8064-block period MUST have the same deployment state.
3. For boundary heights `< StartHeight`, state MUST be `DEFINED`.
4. At boundary height `StartHeight`, state MUST transition to `STARTED`.
5. While in `STARTED`, signaling MUST be counted per full 8064-block period.
   If signaling count in a period is `>= 6048`, the next period MUST be `LOCKED_IN`.
6. After one full `LOCKED_IN` period, the next period MUST be `ACTIVE`.
7. `LOT=false`: if state is still `STARTED` at boundary height `TimeoutHeight`,
   the state at `TimeoutHeight` MUST be `FAILED`.
8. With `LOT=false`, timeout MUST NOT cause a transition to `LOCKED_IN`.
9. `ACTIVE` and `FAILED` are terminal states.
10. Activation MUST NOT be interpreted using rolling or sliding windows.

## Mainnet Numeric Example (Current Height = 3,065,045)

With `nMinerConfirmationWindow = 8064`:

```text
Current period boundary: 3,064,320
Current period end:      3,072,383
Next clean boundary:     3,072,384
```

Using the parameters above:

```text
STARTED begins at:  3,072,384
First STARTED end:  3,080,447
LOCKED_IN (if threshold met in first STARTED period): 3,080,448
ACTIVE (one full LOCKED_IN period later):             3,088,512
Final STARTED period before timeout starts:           3,273,984
FAILED at timeout (if never locked in):               3,282,048
```

---
# Security Considerations

## Miner Majority Threat Model

A malicious majority would need to:

- Publish a malicious bundle  
- Deliver at least 6,048 yes votes across an 8,064-block Litecoin window
- Wait through an additional 8,064-block finalization delay
- Execute it after prolonged public observation

Thus, theft is **highly visible** and economically irrational.

## Reorg Handling

State is deterministic and fully reversible.

## Escrow Safety

Execution cannot exceed escrow and must match bundle contents exactly.

---

# Reference Implementation

Includes:

- `src/drivechain/*`  
- `src/script/*` modifications  
- `src/validation.cpp`  
- `getdrivechaininfo` RPC  
- Functional tests  

---

# Copyright

Copyright (c) 2025-2026
AllSageTech, LLC
Licensed under MIT.

