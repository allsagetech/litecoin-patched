#!/usr/bin/env python3
# Copyright (c) 2025 AllSageTech, LLC
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
drivechain_reorg_state_rollback.py

Reorg regression test: Drivechain state must rollback correctly on reorg, and
re-apply correctly when the chain with drivechain activity becomes active again.

High-level plan (2 nodes):
  1) Build baseline chain on both nodes.
  2) Disconnect nodes (fork).
  3) On node0 fork: create deposit + commit + some votes; mine blocks.
  4) On node1 fork: mine a longer chain without those txs.
  5) Reconnect -> node0 reorgs to node1's longer chain.
     Assert drivechain state == baseline (rollback succeeded).
  6) Disconnect again.
  7) Now build a longer chain on the other side *with* the drivechain txs.
  8) Reconnect -> reorg back.
     Assert drivechain state reflects those txs again (re-apply succeeded).
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    sync_blocks,
)

# ---- TODO: adapt these helpers to your repo (copy logic from your working drivechain feature test) ----

def drivechain_get_state(node):
    """
    Return a JSON-serializable state snapshot that should be identical
    if drivechain state is identical.

    Prefer a single RPC you already have (e.g. getdrivechaininfo).
    If your RPC includes volatile fields (like tip hash/time), strip them.
    """
    info = node.getdrivechaininfo()  # <-- TODO: confirm this RPC name exists in your repo

    # Strip volatile fields if present (keep only consensus-derived state)
    for k in ["bestblockhash", "tip", "height", "time", "mediantime"]:
        if k in info:
            info.pop(k)

    return info


def drivechain_make_activity(node, *, scid=0, deposit_amount=10_0000_0000, withdraw_amount=1_0000_0000):
    """
    Create drivechain activity on-chain:
      - deposit to escrow
      - create/commit a bundle
      - mine a few blocks containing coinbase votes (partial votes is fine)
    Return any IDs you might want later.
    """
    #
    # TODO: Replace this body with the same sequence you already know works:
    #   - create/send DEPOSIT tx
    #   - create/send COMMIT tx
    #   - mine blocks with VOTE outputs in coinbase (if your design needs it)
    #
    # The test only requires: some state change that must rollback/reapply.
    #

    # Example placeholders (delete/replace):
    # deposit_txid = node.sendrawtransaction(build_deposit_tx(...))
    # node.generatetoaddress(1, node.getnewaddress())
    # commit_txid = node.sendrawtransaction(build_commit_tx(...))
    # node.generatetoaddress(1, node.getnewaddress())
    # mine_votes(node, scid=scid, num_blocks=5)
    #
    # Return identifiers if helpful:
    return {
        "scid": scid,
        "deposit_amount": deposit_amount,
        "withdraw_amount": withdraw_amount,
    }


def drivechain_assert_state_changed(baseline, after):
    """
    The state snapshot should differ after activity.
    If your state structure is large, you can narrow to specific keys.
    """
    # Minimal check: not identical.
    assert baseline != after, "Drivechain state did not change after creating activity (helper likely not working)."


# -----------------------------------------------------------------------------------------------

class DrivechainReorgStateRollback(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        # Keep it permissive for constructing custom txs while you’re iterating.
        self.extra_args = [
            ["-acceptnonstdtxn=1"],
            ["-acceptnonstdtxn=1"],
        ]

    def run_test(self):
        n0 = self.nodes[0]
        n1 = self.nodes[1]

        # Step 0: Mature coinbase on a shared chain
        addr0 = n0.getnewaddress()
        n0.generatetoaddress(110, addr0)
        self.sync_all()

        # Baseline state (identical across nodes)
        baseline0 = drivechain_get_state(n0)
        baseline1 = drivechain_get_state(n1)
        assert_equal(baseline0, baseline1)

        # --- Fork the network ---
        self.log.info("Disconnecting nodes to create a fork")
        self.disconnect_nodes(0, 1)

        # Step 1: On node0 fork, create drivechain activity and mine some blocks
        self.log.info("Creating drivechain activity on node0 fork")
        drivechain_make_activity(n0, scid=0)
        n0.generatetoaddress(3, n0.getnewaddress())  # ensure activity is buried
        # node0 chain height now:
        h0 = n0.getblockcount()

        after0 = drivechain_get_state(n0)
        drivechain_assert_state_changed(baseline0, after0)

        # Step 2: On node1 fork, mine a LONGER chain without drivechain activity
        # Make node1 longer than node0 so that reconnect triggers reorg on node0
        self.log.info("Mining a longer competing chain on node1 (no drivechain txs)")
        h1_start = n1.getblockcount()
        # Ensure node1 surpasses node0 by at least 2 blocks to force reorg
        target = h0 + 2
        to_mine = target - h1_start
        assert_greater_than(to_mine, 0)
        n1.generatetoaddress(to_mine, n1.getnewaddress())
        assert_equal(n1.getblockcount(), target)

        # Step 3: Reconnect and synchronize -> node0 should reorg to node1's longer chain
        self.log.info("Reconnecting nodes; expect node0 to reorg to node1 chain")
        self.connect_nodes(0, 1)
        sync_blocks(self.nodes)

        # Now both should share node1 chain tip, and drivechain state should have rolled back
        post_reorg0 = drivechain_get_state(n0)
        post_reorg1 = drivechain_get_state(n1)

        # node1 never had the activity, so expected state is baseline
        assert_equal(post_reorg1, baseline1)
        assert_equal(post_reorg0, baseline0)

        # --- Now test re-apply direction ---
        # Fork again, but this time put activity on node1 and make it the longer chain.
        self.log.info("Disconnecting again to test re-apply on reorg back")
        self.disconnect_nodes(0, 1)

        # On node1 fork: create the same style of drivechain activity, mine blocks
        self.log.info("Creating drivechain activity on node1 fork")
        drivechain_make_activity(n1, scid=0)
        n1.generatetoaddress(3, n1.getnewaddress())
        after1 = drivechain_get_state(n1)
        drivechain_assert_state_changed(baseline1, after1)

        # On node0 fork: mine fewer blocks so node1 remains heavier
        self.log.info("Mining a shorter chain on node0 fork")
        n0.generatetoaddress(1, n0.getnewaddress())

        # Reconnect: node0 should reorg onto node1’s chain and re-apply state
        self.log.info("Reconnecting; expect node0 to reorg onto node1 chain and re-apply drivechain state")
        self.connect_nodes(0, 1)
        sync_blocks(self.nodes)

        final0 = drivechain_get_state(n0)
        final1 = drivechain_get_state(n1)

        # Both should now match node1’s post-activity state snapshot
        assert_equal(final0, final1)
        assert_equal(final1, after1)

        self.log.info("PASS: Drivechain state rolls back and re-applies correctly across reorgs")


if __name__ == "__main__":
    DrivechainReorgStateRollback().main()
