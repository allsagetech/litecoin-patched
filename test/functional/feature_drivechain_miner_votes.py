#!/usr/bin/env python3
# Copyright (c) 2025-2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


def get_bundle(node, sidechain_id: int, bundle_hash: str):
    info = node.getdrivechaininfo()
    for sc in info["sidechains"]:
        if int(sc["id"]) != sidechain_id:
            continue
        for bundle in sc["bundles"]:
            if bundle["hash"] == bundle_hash:
                return bundle
    return None


class DrivechainMinerVotesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [
            ["-acceptnonstdtxn=1"],
            ["-acceptnonstdtxn=1", "-drivechainvote=NO"],
        ]

    def skip_test_if_missing_module(self):
        pass

    def run_test(self):
        node_yes = self.nodes[0]
        node_no = self.nodes[1]
        sidechain_id = 1
        deposit_payload = "00" * 32
        bundle_hash = "55" * 32

        node_yes.generatetoaddress(130, node_yes.getnewaddress())
        self.sync_blocks()

        owner_privkey = node_yes.getnewaddress()
        node_yes.senddrivechainregister(owner_privkey, sidechain_id, Decimal("1.0"))
        node_yes.generatetoaddress(1, node_yes.getnewaddress())
        self.sync_blocks()

        node_yes.senddrivechaindeposit(sidechain_id, deposit_payload, [Decimal("1.0")], False)
        node_yes.generatetoaddress(1, node_yes.getnewaddress())
        self.sync_blocks()

        node_yes.senddrivechainbundle(sidechain_id, bundle_hash, owner_privkey)
        node_yes.generatetoaddress(1, node_yes.getnewaddress())
        self.sync_blocks()

        bundle = get_bundle(node_yes, sidechain_id, bundle_hash)
        assert bundle is not None
        vote_start = int(bundle["vote_start_height"])

        cur_height = node_yes.getblockcount()
        target_height = vote_start - 1
        if cur_height < target_height:
            node_yes.generatetoaddress(target_height - cur_height, node_yes.getnewaddress())
            self.sync_blocks()

        tpl_yes = node_yes.getblocktemplate({"rules": ["mweb", "segwit"]})
        tpl_no = node_no.getblocktemplate({"rules": ["mweb", "segwit"]})
        assert_equal(tpl_yes["drivechainvotes"][0]["vote"], "yes")
        assert_equal(tpl_no["drivechainvotes"][0]["vote"], "no")

        bundle_pre = get_bundle(node_yes, sidechain_id, bundle_hash)
        assert bundle_pre is not None
        assert_equal(int(bundle_pre["yes_votes"]), 0)

        # Mine competing one-block forks from the same parent to verify vote mode effects.
        self.disconnect_nodes(0, 1)

        node_yes.generate(1)
        bundle_yes = get_bundle(node_yes, sidechain_id, bundle_hash)
        assert bundle_yes is not None
        assert_equal(int(bundle_yes["yes_votes"]), 1)

        node_no.generate(1)
        bundle_no = get_bundle(node_no, sidechain_id, bundle_hash)
        assert bundle_no is not None
        assert_equal(int(bundle_no["yes_votes"]), 0)
        assert_equal(int(bundle_no["no_votes"]), 1)


if __name__ == "__main__":
    DrivechainMinerVotesTest().main()
