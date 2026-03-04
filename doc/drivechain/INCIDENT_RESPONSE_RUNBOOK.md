# Drivechain Incident Response Runbook

This runbook covers operational response for high-severity Drivechain incidents.

## Severity Levels

- `SEV-1`: Active consensus divergence, escrow safety risk, or confirmed exploit.
- `SEV-2`: Mempool/policy divergence, degraded safety signal, or suspected exploit.
- `SEV-3`: Non-critical reliability or monitoring issue.

## Immediate Response (SEV-1 / SEV-2)

1. Contain
- Pause automation that broadcasts new Drivechain transactions.
- Disable affected miner policy flags where applicable.
- Freeze release/rollout promotion.

2. Stabilize
- Record current chain tip hash, height, and deployment status.
- Capture `getdrivechaininfo`, `getblockchaininfo`, and relevant debug logs.
- Snapshot node data directories before intervention.

3. Classify
- Determine whether issue is:
  - consensus-critical,
  - policy/mempool-only,
  - wallet/RPC-only.

4. Coordinate
- Open private incident channel.
- Notify security contacts listed in `SECURITY.md`.

## Chain Split / Consensus Divergence

1. Confirm divergence using independent nodes and block hashes.
2. Halt transaction broadcast on affected operators.
3. Build a minimal reproducer from the first divergent block.
4. If rollback is required:
- Follow controlled rollback process in this document.
- Revalidate Drivechain state from recomputation path after rollback.
5. Do not resume normal operations until all upgraded nodes converge.

## Owner Key Compromise

1. Assume compromised key can authorize malicious bundle commits.
2. Stop submitting owner-auth bundle commits from compromised key immediately.
3. Coordinate emergency sidechain migration:
- Register new sidechain ownership on a new sidechain ID.
- Halt old sidechain commit flow.
4. Publish compromise notice to operators and require key rotation evidence.
5. Archive forensic timeline and compromised key fingerprint.

## Controlled Rollback Procedure

1. Pick rollback target height/hash.
2. Stop node cleanly.
3. Restore validated backup snapshot.
4. Restart with expected flags.
5. Verify:
- chain tip hash,
- deployment status,
- `getdrivechaininfo` sidechain/bundle state,
- mempool sanity.
6. Reconnect peers and monitor reorg behavior.

## Recovery Exit Criteria

All criteria must be met before closing incident:
- No active consensus divergence.
- Critical regression test reproducer passes with fix.
- `getdrivechaininfo` matches expected state on at least two independent nodes.
- Post-incident action items are tracked with owners and deadlines.
