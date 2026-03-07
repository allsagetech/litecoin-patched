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


def assert_dc_rejected_before_activation(node):
    tx_hex = fund_and_sign_script_tx(
        node,
        make_drivechain_script(sidechain_id=1, payload_hex="00" * 32, tag=0x00),
        Decimal("1.0"),
    )
    res = node.testmempoolaccept([tx_hex])[0]
    assert_equal(res["allowed"], False)
    assert "drivechain-before-activation" in res["reject-reason"]


class DrivechainSoftforkActivationBoundary(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-acceptnonstdtxn=1",
            "-vbparams=drivechain:0:999999999:144:576",
        ]]

    def run_test(self):
        node = self.nodes[0]

        node.generatetoaddress(110, node.getnewaddress())
        assert_equal(get_drivechain_status(node), "defined")
        assert_dc_rejected_before_activation(node)

        # VersionBitsTipState() reports the state for the *next* block.
        # At tip=143, height 144 is already in STARTED.
        node.generatetoaddress(33, node.getnewaddress())  # tip=143
        assert_equal(get_drivechain_status(node), "started")
        assert_dc_rejected_before_activation(node)

        # At tip=287, height 288 is in LOCKED_IN.
        node.generatetoaddress(144, node.getnewaddress())  # tip=287
        assert_equal(get_drivechain_status(node), "locked_in")
        assert_dc_rejected_before_activation(node)

        # At tip=431, height 432 is ACTIVE.
        node.generatetoaddress(144, node.getnewaddress())  # tip=431
        assert_equal(get_drivechain_status(node), "active")

        # Use wallet RPC for the active-path acceptance check to avoid
        # custom-raw-tx edge cases in CI.
        owner_privkey = node.getnewaddress()
        reg = node.senddrivechainregister(owner_privkey, 1, Decimal("1.0"))
        txid = reg["txid"]
        assert txid
        assert txid in node.getrawmempool()

        # Mine the first ACTIVE block to exercise boundary block assembly.
        node.generatetoaddress(1, node.getnewaddress())
        assert txid not in node.getrawmempool()
        scids = [int(sc["id"]) for sc in node.getdrivechaininfo()["sidechains"]]
        assert 1 in scids


if __name__ == "__main__":
    DrivechainSoftforkActivationBoundary().main()
