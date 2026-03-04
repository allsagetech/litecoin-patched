#!/usr/bin/env python3
# Copyright (c) 2025-2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


def _get_sidechain(info: dict, scid: int):
    for sc in info.get("sidechains", []):
        if sc.get("id") == scid:
            return sc
    return None


def _bundle_present(sc: dict, bundle_hash_hex: str) -> bool:
    for b in sc.get("bundles", []):
        if b.get("hash") == bundle_hash_hex:
            return True
    return False


class DrivechainRestartStatePersistence(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def run_test(self):
        n = self.nodes[0]
        n.generatetoaddress(110, n.getnewaddress())

        scid = 1
        payload = "00" * 32
        bundle_hash = "11" * 32

        n.senddrivechaindeposit(scid, payload, [Decimal("1.0")])
        n.generatetoaddress(1, n.getnewaddress())

        n.senddrivechainbundle(scid, bundle_hash, Decimal("0.1"))
        n.generatetoaddress(1, n.getnewaddress())

        info_before = n.getdrivechaininfo()
        sc_before = _get_sidechain(info_before, scid)
        assert sc_before is not None
        assert_equal(sc_before["escrow_balance"], 100000000)
        assert _bundle_present(sc_before, bundle_hash)

        self.restart_node(0)
        n = self.nodes[0]

        info_after = n.getdrivechaininfo()
        sc_after = _get_sidechain(info_after, scid)
        assert sc_after is not None
        assert_equal(sc_after["escrow_balance"], 100000000)
        assert _bundle_present(sc_after, bundle_hash)

        # The serialized RPC view should be stable across restart.
        assert_equal(info_after["sidechains"], info_before["sidechains"])


if __name__ == "__main__":
    DrivechainRestartStatePersistence().main()
