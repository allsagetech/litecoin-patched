# Drivechain Operations Runbook

This runbook documents practical operator flow for the Drivechain implementation in this repository.

## 1. Preconditions

- Node is synced and Drivechain softfork is active.
- Wallet is loaded and unlocked.
- Node policy allows drivechain scripts where needed (`-acceptnonstdtxn=1` in regtest/dev environments).

## 2. Register Sidechain Ownership

Use `senddrivechainregister` with an owner WIF key.

- Preferred: omit `sidechain_id` so wallet auto-selects the lowest unused ID.
- Optional: pass explicit `sidechain_id` when coordinated externally.

Example:

```bash
litecoin-cli senddrivechainregister "<owner_wif>"
```

Response includes:

- `txid`
- `sidechain_id`
- `owner_key_hash` (RPC uint256 display order)
- `owner_key_hash_payload` (raw script payload byte order)

Mine/confirm this transaction before publishing bundle commits for that sidechain.

## 3. Fund Escrow (Deposits)

Create deposits with `senddrivechaindeposit`.

```bash
litecoin-cli senddrivechaindeposit <sidechain_id> <payload_hex_32b> "[1.0]"
```

Notes:

- Deposit payloads are sidechain-defined and opaque to Litecoin consensus.
- Owner-auth sidechains require owner signatures on `BUNDLE_COMMIT`, not owner-hash-shaped deposit payloads.
- Confirm deposits before attempting execute paths that depend on escrow.

## 4. Commit / Vote / Execute

- Commit bundle: `senddrivechainbundle`
- Vote is miner/template-driven (`-drivechainvote`, `getblocktemplate.drivechainvotes`)
- Execute approved bundle: `senddrivechainexecute`

Owner-auth sidechains require an owner signature on `BUNDLE_COMMIT`.

## 5. Health / Debug Checks

- `getdrivechaininfo`: sidechain state, bundle windows, owner-auth fields, cache stats.
- `getblockchaininfo`: softfork state.
- Monitor rejection reasons in debug logs and RPC errors (`drivechain-*` / `dc-*`).

## 6. Reorg / Restart Expectations

- Drivechain state is persisted and recomputed deterministically when needed.
- Reorgs can remove sidechain/bundle state created only on orphaned branches.
- After unusual shutdowns, validate `getdrivechaininfo` against expected tip.

## 7. Operational Guardrails

- Keep owner keys in dedicated operational wallets/HSM flows where possible.
- Do not reuse owner keys across production sidechains.
- Treat sidechain ID assignment as coordinated governance, not first-come social consensus.

## 8. Production References

- Production gates: `doc/drivechain/PRODUCTION_READINESS.md`
- Incident and rollback response: `doc/drivechain/INCIDENT_RESPONSE_RUNBOOK.md`
- Staged rollout: `doc/drivechain/STAGED_ROLLOUT_PLAN.md`
- External sign-off template: `doc/drivechain/EXTERNAL_SECURITY_SIGNOFF.md`

## 9. External Sign-Off Syntax Requirements

Release tag pushes enforce `DRIVECHAIN_ENFORCE_EXTERNAL_SIGNOFF=1`, which validates
`doc/drivechain/EXTERNAL_SECURITY_SIGNOFF.md` using the following rules:
- Required checklist fields must appear exactly once.
- Placeholder values are rejected (`PENDING`, `NOT APPROVED`, `TBD`, `TODO`, `N/A`, `UNKNOWN`, `NONE`).
- `Date`, `Effective date`, and `Approval date` must be `YYYY-MM-DD`.
- `Approval status` must be `APPROVED`.
- `Unresolved High/Critical findings` must be `NO`.
- Values can be bare text or markdown-backticked.
