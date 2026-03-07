#!/usr/bin/env python3
# Copyright (c) 2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from decimal import Decimal

from test_framework.messages import CTransaction, CTxOut
from test_framework.script import CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

COIN = 100_000_000


def fund_and_sign_script_tx(node, script: CScript, amount: Decimal) -> str:
    tx = CTransaction()
    tx.vin = []
    tx.vout = [CTxOut(int(amount * COIN), script)]
    funded = node.fundrawtransaction(tx.serialize().hex())["hex"]
    return node.signrawtransactionwithwallet(funded)["hex"]


def make_drivechain_script(*, sidechain_id: int, payload_hex: str, tag: int) -> CScript:
    assert 0 <= sidechain_id <= 255
    assert len(payload_hex) == 64
    payload = bytes.fromhex(payload_hex)[::-1]
    return CScript(bytes([0x6A, 0xB4, 0x01, sidechain_id, 0x20]) + payload + bytes([0x01, tag]))


def get_drivechain_status(node) -> str:
    softfork = node.getblockchaininfo()["softforks"]["drivechain"]
    state = softfork[softfork["type"]]
    return state["status"]


def mine_to_height(node, target_height: int):
    current = node.getblockcount()
    if current < target_height:
        node.generatetoaddress(target_height - current, node.getnewaddress())


def find_sidechain(node, scid: int):
    info = node.getdrivechaininfo()
    for sidechain in info["sidechains"]:
        if int(sidechain["id"]) == scid:
            return sidechain
    return None


class DrivechainSoftforkReorgDeactivation(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [
            [
                "-acceptnonstdtxn=1",
                "-vbparams=drivechain:0:999999999:144:576",
            ],
            [
                "-acceptnonstdtxn=1",
                "-vbparams=drivechain:0:999999999:144:576",
                "-blockversion=536870912",  # VERSIONBITS_TOP_BITS, no drivechain signaling.
            ],
        ]

    def run_test(self):
        n0 = self.nodes[0]
        n1 = self.nodes[1]
        scid = 29

        n0.generatetoaddress(110, n0.getnewaddress())
        self.sync_blocks()
        self.disconnect_nodes(0, 1)

        # Mine into first ACTIVE block boundary (height 432).
        mine_to_height(n0, 432)
        assert_equal(get_drivechain_status(n0), "active")

        owner_privkey = n0.getnewaddress()
        reg = n0.senddrivechainregister(owner_privkey, scid, Decimal("1.0"))
        txid = reg["txid"]
        assert txid in n0.getrawmempool()
        n0.generatetoaddress(1, n0.getnewaddress())
        assert find_sidechain(n0, scid) is not None

        mine_to_height(n1, 450)
        assert get_drivechain_status(n1) != "active"

        self.connect_nodes(0, 1)
        self.sync_blocks()

        assert_equal(n0.getblockcount(), 450)
        assert get_drivechain_status(n0) != "active"
        assert find_sidechain(n0, scid) is None

        tx_hex_after_reorg = fund_and_sign_script_tx(
            n0,
            make_drivechain_script(sidechain_id=31, payload_hex="33" * 32, tag=0x00),
            Decimal("1.0"),
        )
        res_after_reorg = n0.testmempoolaccept([tx_hex_after_reorg])[0]
        assert_equal(res_after_reorg["allowed"], False)
        assert "drivechain-before-activation" in res_after_reorg["reject-reason"]


if __name__ == "__main__":
    DrivechainSoftforkReorgDeactivation().main()
