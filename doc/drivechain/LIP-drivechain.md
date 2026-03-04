LIP: 0005
Title: Drivechains for Litecoin (BIP300/301-style Withdrawals)
Author: AllSageTech, LLC / support@allsagetech.com
Status: Final
Type: Standards Track - Consensus
Created: 2025-12-10
License: MIT

---

# Abstract

This proposal introduces **Drivechains for Litecoin**, a mainchain-enforced mechanism enabling opt-in sidechains whose assets are backed 1:1 with LTC locked on-chain. The mechanism is inspired by Bitcoin's BIP300/301 but uses stricter on-chain validation, simplified semantics, and enhanced transparency.

This soft fork adds a new opcode (`OP_DRIVECHAIN`) and new output type (`TxoutType::DRIVECHAIN`) which enable six operations:

1. **DEPOSIT** - Lock LTC into a sidechain escrow
2. **REGISTER** - Bind sidechain ownership to an owner key hash
3. **BUNDLE_COMMIT** - Publish a hash of a sidechain withdrawal bundle
4. **VOTE_YES** - Cast a miner yes vote for bundle approval (coinbase only)
5. **VOTE_NO** - Cast a miner no vote for bundle approval (coinbase only)
6. **EXECUTE** - Release escrow to mainchain addresses after approval

These rules allow permissionless deployment of sidechains with fully verifiable peg-in and miner-approved peg-out semantics.

---

# Motivation

Litecoin often serves as a proving ground for technologies that may later be adopted elsewhere or that expand the Litecoin ecosystem.

Drivechains allow Litecoin to:

- Add entirely new feature sets without modifying the mainchain  
- Host alternative execution environments  
- Experiment with privacy and ZK systems  
- Scale without fragmenting liquidity  
- Enable synthetic assets or stablecoins  
- Provide a trust-minimized layer-2 ecosystem  

Drivechains unify experimentation under the same global LTC monetary base and the same PoW security, using objective, on-chain rules-not custodians or federated multisigs.

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

Votes are signaled using `VOTE_YES` outputs in the **coinbase**.
Implementations may expose local miner policy to emit either `VOTE_YES` or
`VOTE_NO`; consensus only requires that a valid vote for the required bundle is
present during active vote windows.

## Voting Constants (Consensus)

```text
VOTE_WINDOW = 4032 blocks
APPROVAL_THRESHOLD = 1680 votes
VOTE_EPOCH_START = StartHeight
```

`VOTE_EPOCH_START` SHALL be the deployment `StartHeight` defined in the activation section.

## Deterministic Vote Window Assignment

For each bundle with `first_seen_height = H_first`, nodes MUST derive voting heights as:

```text
window_index      = floor((H_first - VOTE_EPOCH_START) / VOTE_WINDOW) + 1
vote_start_height = VOTE_EPOCH_START + (window_index * VOTE_WINDOW)
vote_end_height   = vote_start_height + VOTE_WINDOW - 1
expiration_height = vote_start_height + (2 * VOTE_WINDOW)
```

The `+1` in `window_index` is required so voting always begins at the **next** fixed
window boundary after the commit is first seen.

Nodes MUST count votes for a bundle only in `[vote_start_height, vote_end_height]`.
Nodes MUST NOT use sliding windows derived from `first_seen_height`.

## Consensus Rules

1. `VOTE_YES` outputs MUST appear only in the coinbase transaction.
2. Each vote MUST reference an existing `(sidechain_id, bundle_hash)` on the active chain.
3. A vote MUST increment `yes_votes` only when `block_height` is in
   `[vote_start_height, vote_end_height]` for that bundle.
4. A bundle SHALL become `approved = true` when `yes_votes >= APPROVAL_THRESHOLD`.
5. If `block_height >= expiration_height` and the bundle is not approved, the bundle
   MUST be treated as expired and MUST NOT be approved or executed.
6. On reorg, vote totals and approval status MUST be recomputed from the active chain;
   votes from disconnected blocks MUST NOT be retained.

---
# Execution (Peg-out)

An EXECUTE output:

- References `(sidechain_id, bundle_hash)`  
- Must output **exactly** the list of withdrawals encoded in the bundle  
- Cannot exceed escrow  
- Must not alter withdrawal amounts or destinations  
- MUST occur only at or after `vote_end_height + 1` for the referenced bundle

## Validity Conditions

1. Bundle exists  
2. Bundle is approved  
3. Not previously executed  
4. `block_height >= vote_end_height + 1`
5. Outputs exactly match canonical withdrawal list  
6. Sum(outputs) <= escrow
7. State updates atomically  

---

# Bundle Expiration

Bundles expire at:

```text
EXPIRATION_HEIGHT = vote_start_height + (2 * VOTE_WINDOW)
```

Expiration MUST be interpreted using the fixed-window derivation in the
`Miner Voting Rules` section.

Expired bundles MUST NOT be approved or executed.

On reorg, `first_seen_height`, `vote_start_height`, `vote_end_height`, and
`expiration_height` MUST be recomputed from the active chain, and expiration
status MUST follow the recomputed values.

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
- `REGISTER` output value MUST be at least the chain's minimum registration amount.

RPC support:

- `senddrivechainregister` registers a sidechain owner key.
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
- Vote for it continuously for ~1 week  
- Execute it after public observation  

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

