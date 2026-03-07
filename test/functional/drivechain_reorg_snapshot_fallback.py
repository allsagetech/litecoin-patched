#!/usr/bin/env python3
# Copyright (c) 2025-2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


def get_sidechain(info: dict, scid: int):
    for sidechain in info.get("sidechains", []):
        if sidechain.get("id") == scid:
            return sidechain
    return None


class DrivechainReorgSnapshotFallback(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def run_test(self):
        node = self.nodes[0]
        scid = 1
        payload = "00" * 32
        bundle_hash = "77" * 32

        node.generatetoaddress(110, node.getnewaddress())

        owner_privkey = node.getnewaddress()
        node.senddrivechainregister(owner_privkey, scid, Decimal("1.0"))
        node.generatetoaddress(1, node.getnewaddress())

        node.senddrivechaindeposit(scid, payload, [Decimal("1.0")])
        node.generatetoaddress(1, node.getnewaddress())
        node.senddrivechainbundle(scid, bundle_hash, owner_privkey)
        node.generatetoaddress(1, node.getnewaddress())

        self.restart_node(0)
        node = self.nodes[0]

        before = node.getdrivechaininfo()["state_cache"]
        before_recompute = int(before["recompute_fallbacks"])

        old_tip = node.getbestblockhash()
        node.invalidateblock(old_tip)

        after_info = node.getdrivechaininfo()
        after_recompute = int(after_info["state_cache"]["recompute_fallbacks"])
        assert_equal(after_recompute, before_recompute)

        sidechain = get_sidechain(after_info, scid)
        assert sidechain is not None
        assert_equal(sidechain["escrow_balance"], 100000000)
        assert_equal(sidechain["bundles"], [])


if __name__ == "__main__":
    DrivechainReorgSnapshotFallback().main()
