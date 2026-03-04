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


class DrivechainGBTVoteMetadataTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def skip_test_if_missing_module(self):
        pass

    def run_test(self):
        node = self.nodes[0]
        sidechain_id = 1
        deposit_payload = "00" * 32
        bundle_hash = "66" * 32

        node.generatetoaddress(130, node.getnewaddress())
        owner_privkey = node.dumpprivkey(node.getnewaddress())
        node.senddrivechainregister(owner_privkey, sidechain_id, Decimal("1.0"))
        node.generatetoaddress(1, node.getnewaddress())

        node.senddrivechaindeposit(sidechain_id, deposit_payload, [Decimal("1.0")], False)
        node.generatetoaddress(1, node.getnewaddress())

        node.senddrivechainbundle(sidechain_id, bundle_hash, Decimal("0.1"), False, owner_privkey)
        node.generatetoaddress(1, node.getnewaddress())

        bundle = get_bundle(node, sidechain_id, bundle_hash)
        assert bundle is not None
        vote_start = int(bundle["vote_start_height"])

        # Build a template just before vote window starts: no vote should be advertised.
        target_pre = vote_start - 2
        cur_height = node.getblockcount()
        if cur_height < target_pre:
            node.generatetoaddress(target_pre - cur_height, node.getnewaddress())

        tmpl_pre = node.getblocktemplate({"rules": ["segwit", "mweb"]})
        assert_equal(tmpl_pre["drivechainvotes"], [])

        # Move to vote_start - 1 so the next template block is in-window and should include vote metadata.
        node.generate(1)

        tmpl_vote = node.getblocktemplate({"rules": ["segwit", "mweb"]})
        votes = tmpl_vote["drivechainvotes"]
        assert_equal(len(votes), 1)
        assert_equal(int(votes[0]["sidechain_id"]), sidechain_id)
        assert_equal(votes[0]["bundle_hash"], bundle_hash)


if __name__ == "__main__":
    DrivechainGBTVoteMetadataTest().main()
