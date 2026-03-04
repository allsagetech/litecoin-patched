#!/usr/bin/env python3
# Copyright (c) 2025-2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


def get_bundle(node, scid: int, bundle_hash_hex: str):
    info = node.getdrivechaininfo()
    for sc in info["sidechains"]:
        if sc["id"] != scid:
            continue
        for bundle in sc["bundles"]:
            if bundle["hash"] == bundle_hash_hex:
                return bundle
    return None


class DrivechainBundlePruning(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def run_test(self):
        n = self.nodes[0]
        n.generatetoaddress(110, n.getnewaddress())

        scid = 1
        bundle1 = "11" * 32
        bundle2 = "22" * 32

        owner_privkey = n.dumpprivkey(n.getnewaddress())
        n.senddrivechainregister(owner_privkey, scid, Decimal("1.0"))
        n.generatetoaddress(1, n.getnewaddress())

        # Sidechain must exist before bundle commits.
        n.senddrivechaindeposit(scid, "00" * 32, [Decimal("1.0")])
        n.generatetoaddress(1, n.getnewaddress())

        n.senddrivechainbundle(scid, bundle1, Decimal("0.1"), False, owner_privkey)
        n.generatetoaddress(1, n.getnewaddress())
        b1 = get_bundle(n, scid, bundle1)
        assert b1 is not None
        exp1 = int(b1["expiration_height"])

        cur_h = n.getblockcount()
        if cur_h < 121:
            n.generatetoaddress(121 - cur_h, n.getnewaddress())

        n.senddrivechainbundle(scid, bundle2, Decimal("0.1"), False, owner_privkey)
        n.generatetoaddress(1, n.getnewaddress())
        b2 = get_bundle(n, scid, bundle2)
        assert b2 is not None
        exp2 = int(b2["expiration_height"])
        assert exp2 > exp1

        cur_h = n.getblockcount()
        if cur_h < exp1:
            n.generatetoaddress(exp1 - cur_h, n.getnewaddress())
        assert_equal(n.getblockcount(), exp1)

        assert get_bundle(n, scid, bundle1) is None
        assert get_bundle(n, scid, bundle2) is not None


if __name__ == "__main__":
    DrivechainBundlePruning().main()
