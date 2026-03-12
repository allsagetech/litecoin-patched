# Legacy Drivechain Signet Soft-Fork Test Runbook

This runbook is for trusted testers validating the legacy drivechain soft-fork
behavior on signet while the repo transitions toward validity-enforced
sidechains.

Tested source baseline:

- Commit: `b75b076`
- Branch: `master`

Validated before publishing this runbook:

- `feature_signet.py`
- `feature_drivechain_signet.py`
- Broader regtest drivechain functional suite
- Additional reorg/restart/activation adversarial subset across multiple seeds

## Scope

This is for signet validation only. It is not a production activation instruction.

Ask testers to confirm:

- the node starts cleanly
- signet reports drivechain as active
- drivechain registration and bundle-related RPC paths behave normally
- no unexpected crashes, reorg handling issues, or restart state loss occur

## What to send testers

Send:

- the exact commit hash or tagged release
- the exact binary artifacts for their platform
- required startup flags, if any
- this runbook

Do not ask testers to build from an unspecified branch tip.

## Suggested tester steps

1. Start from the provided binary set for the tested revision.
2. Run a clean signet datadir.
3. Start `litecoind` on signet.
4. Confirm the node is healthy:

   ```bash
   litecoin-cli -signet getblockchaininfo
   ```

5. Confirm drivechain status is active in the `softforks.drivechain` section.
6. If drivechain RPCs are exposed in your package, also capture:

   ```bash
   litecoin-cli -signet getdrivechaininfo
   ```

7. Restart the node once and confirm the same status persists.
8. If you are providing a test script bundle, run it and send the results back unchanged.

## Expected result

`getblockchaininfo` should show drivechain as active on signet for this tested source line.

The exact JSON shape can vary slightly by build, but the status should resolve to `active`.

## What testers should report back

Ask testers to send:

- platform and version
- binary version string from `litecoind --version`
- whether `getblockchaininfo` reports drivechain `active`
- whether restart preserved the same status
- any RPC error text
- any relevant `debug.log` excerpt if something failed

## Recommended rollout sequence

1. Small trusted signet tester group
2. Independent confirmation from multiple environments
3. Publish binaries and operator notes
4. Broader signet test request
5. Only after successful signet validation and operator readiness, consider wider activation messaging

## Recommended message to testers

Please test the legacy drivechain soft-fork build on signet using the provided
binaries for commit `b75b076`. Confirm that `getblockchaininfo` reports
drivechain as `active`, verify the node survives restart cleanly, and send back
any RPC errors, crashes, or unexpected drivechain behavior.
