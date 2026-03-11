# Drivechain Operations Runbook

This runbook documents practical operator flow for the Drivechain implementation in this repository.

## 1. Preconditions

- Node is synced and Drivechain softfork is active.
- Wallet is loaded and unlocked.
- Node policy allows drivechain scripts where needed (`-acceptnonstdtxn=1` in regtest/dev environments).

## 2. Register Sidechain Ownership

Use `senddrivechainregister` with one owner address or a JSON array of owner
addresses from the loaded wallet.

- Preferred: omit `sidechain_id` so wallet auto-selects the lowest unused ID.
- Optional: pass explicit `sidechain_id` when coordinated externally.
- The wallet must hold every corresponding private key and be unlocked.
- Set `auth_threshold`, `max_escrow_amount`, and `max_bundle_withdrawal`
  explicitly for production sidechains.

Example:

```bash
litecoin-cli senddrivechainregister \
  "[\"<owner_address_a>\",\"<owner_address_b>\"]" \
  7 \
  1.0 \
  false \
  2 \
  100.0 \
  25.0
```

Response includes:

- `txid`
- `sidechain_id`
- `policy_hash` / `policy_hash_payload`
- `auth_threshold`
- `owner_key_hashes` / `owner_key_hashes_payload`
- `max_escrow_amount`
- `max_bundle_withdrawal`
- `owner_key_hash` / `owner_key_hash_payload` only for legacy 1-of-1 compatibility

Mine/confirm this transaction before publishing bundle commits for that sidechain.

## 3. Fund Escrow (Deposits)

Create deposits with `senddrivechaindeposit`.

```bash
litecoin-cli senddrivechaindeposit <sidechain_id> <payload_hex_32b> "[1.0]"
```

Notes:

- Deposit payloads are sidechain-defined and opaque to Litecoin consensus.
- Deposit payloads do not participate in owner auth.
- Deposits that would exceed the registered `max_escrow_amount` are rejected.
- Confirm deposits before attempting execute paths that depend on escrow.

## 4. Commit / Vote / Execute

- Commit bundle: `senddrivechainbundle`
- Vote is miner/template-driven (`-drivechainvote`, `getblocktemplate.drivechainvotes`)
- Execute approved bundle: `senddrivechainexecute`

Owner-auth sidechains require enough owner signatures to satisfy the registered
`auth_threshold`, provided by the wallet keys for the supplied owner address set.
`senddrivechainbundle` accepts a single owner address or a JSON array of owner addresses.
`senddrivechainexecute` remains subject to the registered `max_bundle_withdrawal`.
`senddrivechainbundle` creates zero-value commit outputs so the RPC path does not burn funds.

## 5. Health / Debug Checks

- `getdrivechaininfo`: sidechain state, bundle windows, `policy_hash`,
  `auth_threshold`, `owner_key_hashes`, cap fields, legacy single-owner
  compatibility fields, and cache stats.
- `getblockchaininfo`: softfork state.
- Monitor rejection reasons in debug logs and RPC errors (`drivechain-*` / `dc-*`).

## 6. Reorg / Restart Expectations

- Drivechain state is persisted and recomputed deterministically when needed.
- Reorgs can remove sidechain/bundle state created only on orphaned branches.
- After unusual shutdowns, validate `getdrivechaininfo` against expected tip.

## 7. Operational Guardrails

- Keep owner keys in dedicated operational wallets/HSM flows where possible.
- Do not reuse owner keys across production sidechains or across networks.
- Review `max_escrow_amount` and `max_bundle_withdrawal` before every rollout.
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
