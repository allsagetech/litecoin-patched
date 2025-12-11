LIP: 0005
Title: Drivechains for Litecoin (BIP300/3001-style Withdrawals)  
Author: AllSageTech, LLC / support@allsagetech.com  
Status: Draft  
Type: Standards Track – Consensus  
Created: 2025-12-10  
License: MIT  

---

# Abstract

This proposal introduces **Drivechains for Litecoin**, a mainchain-enforced mechanism enabling opt-in sidechains whose assets are backed 1:1 with LTC locked on-chain. The mechanism is inspired by Bitcoin’s BIP300/301 but uses stricter on-chain validation, simplified semantics, and enhanced transparency.

This soft fork adds a new opcode (`OP_DRIVECHAIN`) and new output type (`TxoutType::DRIVECHAIN`) which enable four new operations:

1. **DEPOSIT** – Lock LTC into a sidechain escrow  
2. **BUNDLE_COMMIT** – Publish a hash of a sidechain withdrawal bundle  
3. **VOTE_YES** – Cast a miner vote for bundle approval (coinbase only)  
4. **EXECUTE** – Release escrow to mainchain addresses after approval  

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

Drivechains unify experimentation under the same global LTC monetary base and the same PoW security, using objective, on-chain rules—not custodians or federated multisigs.

---

# Specification

## 1. Drivechain Output Structure

Every drivechain output contains:

```text
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
- `id` – 1-byte integer  
- `escrow_balance` – aggregated deposits minus executed withdrawals  
- `creation_height` – first time a deposit or bundle appears  
- `is_active` – always true once seen (simple activation model)  
- `bundles` – mapping of bundle_hash → Bundle  

### Bundle Fields
- `hash` – 32-byte payload  
- `first_seen_height`  
- `yes_votes`  
- `approved` (boolean)  
- `executed` (boolean)

State is deterministic and regenerated on reorgs.

---

# Deposit (Peg-in)

A `DEPOSIT` output:

- Increases `escrow_balance[sidechain_id] += value`  
- Creates the sidechain entry if missing  
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
    epoch (4 bytes LE) ||
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

- A sidechain may have **only one active (unapproved) bundle at a time**.  
- Any new BUNDLE_COMMIT replaces the previous unapproved one.  
- Once approved, a bundle cannot be replaced until executed.

---

# Miner Voting Rules

Votes are signaled using `VOTE_YES` outputs in the **coinbase**.

## Consensus Rules

1. Must be in coinbase  
2. Must reference valid `(sidechain_id, bundle_hash)`  
3. Votes count within the window:

```text
VOTE_WINDOW = 4032 blocks   // ~1 week
```

4. Threshold:

```text
APPROVAL_THRESHOLD = 1680 votes
```

Equivalent security to BIP300 scaled for Litecoin’s block interval.

---

# Execution (Peg-out)

An EXECUTE output:

- References `(sidechain_id, bundle_hash)`  
- Must output **exactly** the list of withdrawals encoded in the bundle  
- Cannot exceed escrow  
- Must not alter withdrawal amounts or destinations  
- Must occur after the vote window closes  

## Validity Conditions

1. Bundle exists  
2. Bundle is approved  
3. Not previously executed  
4. Block height ≥ first_seen + VOTE_WINDOW  
5. Outputs exactly match canonical withdrawal list  
6. Sum(outputs) ≤ escrow  
7. State updates atomically  

---

# Bundle Expiration

Bundles expire if not approved within:

```text
EXPIRATION_HEIGHT = first_seen_height + (2 * VOTE_WINDOW)
```

Expired bundles cannot be approved or executed.

---

# Standardness Policies

Before activation:
- All drivechain outputs are non-standard.

After activation:
- All four drivechain operations become standard.
- Votes outside coinbase are rejected from mempool.
- Malformed drivechain outputs rejected.

---

# Activation (BIP8, LOT=false)

Drivechain uses a height-based BIP8 deployment with **lock-in-on-timeout disabled**.

```text
Deployment: drivechain
Bit: 5
Activation mechanism: BIP8 (LOT = false)
StartHeight: 3,200,000
TimeoutHeight: 3,400,000
Signaling window: 8064 blocks
Activation threshold: 6048 blocks (75% of window)
```

- Miners can activate the soft fork by signaling bit 5 in at least 75% of blocks within any 8064-block window between `StartHeight` and `TimeoutHeight`.
- If the threshold is never reached before `TimeoutHeight`, the deployment fails and does **not** forcibly activate.
- This mirrors the activation style used for MWEB on Litecoin (BIP8 LOT=false), providing deterministic height bounds without forced lock-in.

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

Copyright © 2025  
AllSageTech, LLC  
Licensed under MIT.
