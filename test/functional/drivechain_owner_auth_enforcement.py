#!/usr/bin/env python3
# Copyright (c) 2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from decimal import Decimal

from test_framework.messages import hash256
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error


def get_sidechain(node, scid: int):
    info = node.getdrivechaininfo()
    for sidechain in info["sidechains"]:
        if int(sidechain["id"]) == scid:
            return sidechain
    return None


class DrivechainOwnerAuthEnforcement(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def run_test(self):
        node = self.nodes[0]
        scid = 21
        bundle_hash = "33" * 32

        node.generatetoaddress(110, node.getnewaddress())

        owner_addr = node.getnewaddress()
        owner_pubkey = bytes.fromhex(node.getaddressinfo(owner_addr)["pubkey"])
        owner_key_hash_payload = hash256(owner_pubkey).hex()
        owner_key_hash_rpc = bytes.fromhex(owner_key_hash_payload)[::-1].hex()

        wrong_addr = node.getnewaddress()

        node.senddrivechainregister(owner_addr, scid, Decimal("1.0"))
        node.generatetoaddress(1, node.getnewaddress())

        node.senddrivechaindeposit(scid, owner_key_hash_payload, [Decimal("1.0")])
        node.generatetoaddress(1, node.getnewaddress())

        sidechain = get_sidechain(node, scid)
        assert sidechain is not None
        assert sidechain["owner_auth_required"] is True
        assert sidechain.get("owner_key_hash")
        assert sidechain.get("owner_key_hash_payload")
        assert sidechain["owner_key_hash"] == owner_key_hash_rpc
        assert sidechain["owner_key_hash_payload"] == owner_key_hash_payload

        assert_raises_rpc_error(
            -8,
            "owner_address is required for registered sidechains with owner auth",
            node.senddrivechainbundle,
            scid,
            bundle_hash,
        )

        assert_raises_rpc_error(
            -8,
            "owner_address does not match the registered owner key",
            node.senddrivechainbundle,
            scid,
            bundle_hash,
            wrong_addr,
        )

        txid = node.senddrivechainbundle(
            scid,
            bundle_hash,
            owner_addr,
        )
        assert txid

        node.generatetoaddress(1, node.getnewaddress())
        sidechain = get_sidechain(node, scid)
        assert sidechain is not None
        bundles = sidechain["bundles"]
        assert any(bundle["hash"] == bundle_hash for bundle in bundles)


if __name__ == "__main__":
    DrivechainOwnerAuthEnforcement().main()
