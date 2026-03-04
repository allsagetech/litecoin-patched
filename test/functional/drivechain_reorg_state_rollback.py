#!/usr/bin/env python3
# Copyright (c) 2025-2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

"""
drivechain_reorg_state_rollback.py

Goal:
- Ensure drivechain tracked state rolls back cleanly across a reorg:
  * escrow_balance (from DEPOSIT) is reverted
  * bundles (from BUNDLE_COMMIT) are reverted
  * sidechain entries created only on the losing branch are removed

This test intentionally exercises:
- Node0 creates a DEPOSIT + BUNDLE_COMMIT on a short fork.
- Node1 mines a longer competing chain without those txs.
- When nodes reconnect, node0 reorgs to node1's chain.
- After reorg, getdrivechaininfo must not show the sidechain/bundle from the orphaned blocks.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


def _get_sidechain(info: dict, scid: int):
    """Return sidechain dict from getdrivechaininfo, or None."""
    for sc in info.get("sidechains", []):
        if sc.get("id") == scid:
            return sc
    return None


def _bundle_present(sc: dict, bundle_hash_hex: str) -> bool:
    for b in sc.get("bundles", []):
        if b.get("hash") == bundle_hash_hex:
            return True
    return False


class DrivechainReorgStateRollbackTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

        # If your tree requires explicit wallet loading or certain flags,
        # you can add them here. Keeping empty by default because your other
        # drivechain tests appear to run without special args.
        self.extra_args = [[], []]

    def run_test(self):
        n0 = self.nodes[0]
        n1 = self.nodes[1]

        scid = 1
        payload = "00" * 32
        bundle_hash = "11" * 32

        self.log.info("Mining enough blocks to have spendable funds on both nodes.")
        # Mine on node0 and sync so node1 also sees/matures coinbase once connected.
        n0.generate(101)
        self.sync_blocks()

        # Sanity: before doing anything, drivechain info should be empty.
        info0 = n0.getdrivechaininfo()
        info1 = n1.getdrivechaininfo()
        assert_equal(info0["sidechains"], [])
        assert_equal(info1["sidechains"], [])

        self.log.info("Splitting the network so we can create competing chains.")
        # Nodes start connected in most functional harnesses; ensure split.
        self.disconnect_nodes(0, 1)

        #
        # Fork A (node0): create DEPOSIT + BUNDLE_COMMIT and mine them in.
        #
        self.log.info("Fork A (node0): creating DEPOSIT + BUNDLE_COMMIT, mining 2 blocks.")
        txid_dep = n0.senddrivechaindeposit(scid, payload, [Decimal("1.0")])
        self.log.debug(f"DEPOSIT txid: {txid_dep}")
        n0.generate(1)

        txid_bundle = n0.senddrivechainbundle(scid, bundle_hash, Decimal("0.1"))
        self.log.debug(f"BUNDLE_COMMIT txid: {txid_bundle}")
        n0.generate(1)

        infoA = n0.getdrivechaininfo()
        scA = _get_sidechain(infoA, scid)
        assert scA is not None, "Expected sidechain to exist on fork A after deposit/commit"

        # escrow_balance is an int CAmount (satoshis) in getdrivechaininfo.
        # 1.0 LTC => 100000000 satoshis.
        assert_equal(scA["escrow_balance"], 100000000)
        assert _bundle_present(scA, bundle_hash), "Expected bundle hash present on fork A"

        self.log.info(f"Fork A drivechain info: {infoA}")

        #
        # Fork B (node1): mine a longer chain WITHOUT those txs.
        #
        self.log.info("Fork B (node1): mining a longer competing chain (no drivechain txs).")
        # Node1 is now isolated; just mine a longer chain than node0's +2.
        n1.generate(4)

        # Confirm node1 still has no drivechain state (since it never saw node0's fork A blocks).
        infoB = n1.getdrivechaininfo()
        assert_equal(infoB["sidechains"], [])

        #
        # Reconnect and trigger reorg: node0 should reorg to node1's longer chain.
        #
        self.log.info("Reconnecting nodes and syncing to trigger reorg to fork B.")
        self.connect_nodes(0, 1)
        self.sync_blocks()
        # Do not require mempool equality here. After a reorg, txs from
        # disconnected blocks may be resurrected on one node and are not
        # guaranteed to be present in every peer mempool.

        #
        # After reorg, node0 must have rolled back:
        # - escrow_balance change
        # - bundle commit
        # - sidechain entry (since it only existed on the orphaned branch)
        #
        self.log.info("Asserting drivechain state is fully rolled back after reorg.")
        info0_after = n0.getdrivechaininfo()
        info1_after = n1.getdrivechaininfo()

        # Strong expectation: no sidechains at all after the reorg, since the only
        # sidechain activity was in orphaned blocks.
        assert_equal(info0_after["sidechains"], [])
        assert_equal(info1_after["sidechains"], [])

        self.log.info(f"Node0 drivechain info after reorg: {info0_after}")
        self.log.info(f"Node1 drivechain info after reorg: {info1_after}")

        #
        # Optional: reorg back (creates symmetric coverage)
        #
        self.log.info("Optional symmetry: create drivechain activity again, then reorg it away again.")

        # Split again
        self.disconnect_nodes(0, 1)

        # Fork A2 (node0) with same scid but new bundle hash
        bundle_hash2 = "22" * 32
        txid_dep2 = n0.senddrivechaindeposit(scid, payload, [Decimal("2.0")])
        n0.generate(1)
        txid_bundle2 = n0.senddrivechainbundle(scid, bundle_hash2, Decimal("0.1"))
        n0.generate(1)

        infoA2 = n0.getdrivechaininfo()
        scA2 = _get_sidechain(infoA2, scid)
        assert scA2 is not None
        # Reorged-out deposit transactions from prior forks may be resurrected
        # and re-mined on this branch, so escrow can be > 2.0 LTC here.
        assert scA2["escrow_balance"] >= 200000000
        assert _bundle_present(scA2, bundle_hash2)

        # Fork B2 (node1) longer again
        n1.generate(4)

        # Reconnect and reorg again
        self.connect_nodes(0, 1)
        self.sync_blocks()
        # Same rationale as above: mempool contents may legitimately differ
        # after reorg/disconnect scenarios.

        info0_after2 = n0.getdrivechaininfo()
        info1_after2 = n1.getdrivechaininfo()
        assert_equal(info0_after2["sidechains"], [])
        assert_equal(info1_after2["sidechains"], [])

        self.log.info("Reorg rollback verified twice.")


if __name__ == "__main__":
    DrivechainReorgStateRollbackTest().main()
