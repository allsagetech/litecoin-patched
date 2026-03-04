#!/usr/bin/env python3
# Copyright (c) 2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


def get_sidechain(node, scid: int):
    info = node.getdrivechaininfo()
    for sidechain in info.get("sidechains", []):
        if int(sidechain.get("id")) == scid:
            return sidechain
    return None


class DrivechainRegisterMempoolConflict(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def run_test(self):
        node = self.nodes[0]
        scid = 41

        node.generatetoaddress(110, node.getnewaddress())

        owner1_privkey = node.dumpprivkey(node.getnewaddress())
        owner2_privkey = node.dumpprivkey(node.getnewaddress())

        assert_raises_rpc_error(
            -8,
            "amount must be at least 1.00000000 LTC",
            node.senddrivechainregister,
            owner1_privkey,
            scid,
            Decimal("0.5"),
        )

        reg1 = node.senddrivechainregister(owner1_privkey, scid)
        reg1_txid = reg1["txid"]
        assert reg1_txid in node.getrawmempool()

        assert_raises_rpc_error(
            -26,
            "dc-register-duplicate-sidechain-mempool",
            node.senddrivechainregister,
            owner2_privkey,
            scid,
        )

        node.generatetoaddress(1, node.getnewaddress())

        sc = get_sidechain(node, scid)
        assert sc is not None
        assert_equal(sc["owner_auth_required"], True)
        assert_equal(sc["owner_key_hash"], reg1["owner_key_hash"])
        assert_equal(sc["owner_key_hash_payload"], reg1["owner_key_hash_payload"])

        assert_raises_rpc_error(
            -26,
            "drivechain-register-sidechain-exists",
            node.senddrivechainregister,
            owner2_privkey,
            scid,
        )


if __name__ == "__main__":
    DrivechainRegisterMempoolConflict().main()
