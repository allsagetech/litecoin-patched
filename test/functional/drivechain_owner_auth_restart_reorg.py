#!/usr/bin/env python3
# Copyright (c) 2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from decimal import Decimal

from test_framework.messages import hash256
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


def get_sidechain(info: dict, scid: int):
    for sidechain in info.get("sidechains", []):
        if int(sidechain.get("id")) == scid:
            return sidechain
    return None


class DrivechainOwnerAuthRestartReorg(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [
            ["-acceptnonstdtxn=1"],
            ["-acceptnonstdtxn=1"],
        ]

    def run_test(self):
        n0 = self.nodes[0]
        n1 = self.nodes[1]

        scid = 22

        n0.generatetoaddress(110, n0.getnewaddress())
        self.sync_blocks()

        owner_addr = n0.getnewaddress()
        owner_pubkey = bytes.fromhex(n0.getaddressinfo(owner_addr)["pubkey"])
        owner_privkey = n0.dumpprivkey(owner_addr)
        # `senddrivechaindeposit` takes raw 32-byte payload hex, while
        # `getdrivechaininfo` reports uint256 via GetHex() (byte-reversed view).
        owner_key_hash_payload = hash256(owner_pubkey).hex()
        owner_key_hash_rpc = bytes.fromhex(owner_key_hash_payload)[::-1].hex()

        self.disconnect_nodes(0, 1)

        n0.senddrivechainregister(owner_privkey, scid, Decimal("1.0"))
        n0.generatetoaddress(1, n0.getnewaddress())
        n0.senddrivechaindeposit(scid, owner_key_hash_payload, [Decimal("1.0")])
        n0.generatetoaddress(1, n0.getnewaddress())

        info_before_restart = n0.getdrivechaininfo()
        sc_before_restart = get_sidechain(info_before_restart, scid)
        assert sc_before_restart is not None
        assert_equal(sc_before_restart["owner_auth_required"], True)
        assert_equal(sc_before_restart["owner_key_hash"], owner_key_hash_rpc)
        assert_equal(sc_before_restart["owner_key_hash_payload"], owner_key_hash_payload)
        assert_equal(sc_before_restart["escrow_balance"], 100000000)

        self.restart_node(0, extra_args=["-acceptnonstdtxn=1"])
        n0 = self.nodes[0]

        info_after_restart = n0.getdrivechaininfo()
        sc_after_restart = get_sidechain(info_after_restart, scid)
        assert sc_after_restart is not None
        assert_equal(sc_after_restart["owner_auth_required"], True)
        assert_equal(sc_after_restart["owner_key_hash"], owner_key_hash_rpc)
        assert_equal(sc_after_restart["owner_key_hash_payload"], owner_key_hash_payload)
        assert_equal(sc_after_restart["escrow_balance"], 100000000)

        # Mine a strictly longer competing chain on n1 to orphan
        # n0's sidechain-registration branch after reconnect.
        blocks_needed = (n0.getblockcount() - n1.getblockcount()) + 1
        n1.generatetoaddress(blocks_needed, n1.getnewaddress())

        self.connect_nodes(0, 1)
        self.sync_blocks()

        info_n0_after_reorg = n0.getdrivechaininfo()
        info_n1_after_reorg = n1.getdrivechaininfo()
        assert get_sidechain(info_n0_after_reorg, scid) is None
        assert get_sidechain(info_n1_after_reorg, scid) is None

        # Restart after reorg to ensure owner-auth sidechain state was not persisted incorrectly.
        self.restart_node(0, extra_args=["-acceptnonstdtxn=1"])
        n0 = self.nodes[0]
        info_after_reorg_restart = n0.getdrivechaininfo()
        assert get_sidechain(info_after_reorg_restart, scid) is None


if __name__ == "__main__":
    DrivechainOwnerAuthRestartReorg().main()
