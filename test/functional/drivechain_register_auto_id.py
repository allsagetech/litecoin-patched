#!/usr/bin/env python3
# Copyright (c) 2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from decimal import Decimal

from test_framework.messages import hash256
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


def get_sidechain(node, scid: int):
    info = node.getdrivechaininfo()
    for sidechain in info.get("sidechains", []):
        if int(sidechain.get("id")) == scid:
            return sidechain
    return None


class DrivechainRegisterAutoId(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def run_test(self):
        n = self.nodes[0]
        n.generatetoaddress(110, n.getnewaddress())

        # Populate a few sidechains first so auto-assignment must scan for an unused id.
        for scid in (1, 2, 3):
            reg_owner_privkey = n.getnewaddress()
            n.senddrivechainregister(reg_owner_privkey, scid, Decimal("1.0"))
            n.generatetoaddress(1, n.getnewaddress())

        owner_addr = n.getnewaddress()
        owner_pubkey = bytes.fromhex(n.getaddressinfo(owner_addr)["pubkey"])
        owner_key_hash_payload = hash256(owner_pubkey).hex()
        owner_key_hash_rpc = bytes.fromhex(owner_key_hash_payload)[::-1].hex()

        reg = n.senddrivechainregister(owner_addr)
        assert_equal(int(reg["sidechain_id"]), 0)
        assert_equal(reg["owner_key_hash_payload"], owner_key_hash_payload)
        assert_equal(reg["owner_key_hash"], owner_key_hash_rpc)

        n.generatetoaddress(1, n.getnewaddress())

        sc = get_sidechain(n, 0)
        assert sc is not None
        assert_equal(sc["owner_auth_required"], True)
        assert_equal(sc["owner_key_hash_payload"], owner_key_hash_payload)
        assert_equal(sc["owner_key_hash"], owner_key_hash_rpc)

        n.senddrivechaindeposit(0, "11" * 32, [Decimal("0.25")])
        n.generatetoaddress(1, n.getnewaddress())

        # Duplicate registration of the same ID must fail.
        assert_raises_rpc_error(
            -26,
            "drivechain-register-sidechain-exists",
            n.senddrivechainregister,
            owner_addr,
            0,
        )

        # Owner-auth sidechain requires authorization on bundle commits.
        bundle_hash = "44" * 32
        assert_raises_rpc_error(
            -8,
            "owner_address is required for registered sidechains with owner auth",
            n.senddrivechainbundle,
            0,
            bundle_hash,
        )

        wrong_addr = n.getnewaddress()
        assert_raises_rpc_error(
            -8,
            "owner_address does not match the registered owner key",
            n.senddrivechainbundle,
            0,
            bundle_hash,
            wrong_addr,
        )

        txid = n.senddrivechainbundle(
            0,
            bundle_hash,
            owner_addr,
        )
        assert txid


if __name__ == "__main__":
    DrivechainRegisterAutoId().main()
