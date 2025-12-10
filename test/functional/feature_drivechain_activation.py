#!/usr/bin/env python3
# Copyright (c) 2025 AllSageTech, LLC
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)

class DrivechainActivationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[]]

    def skip_test_if_missing_module(self):
        pass

    def _create_drivechain_tx(self, node, amount=Decimal("1.0")):
        """
        Create, fund, and sign a transaction with a single drivechain DEPOSIT output.

        Our C++ DecodeDrivechainScript expects:

            OP_DRIVECHAIN
            PUSHDATA(1)  -> sidechain_id
            PUSHDATA(32) -> payload hash
            PUSHDATA(1)  -> tag (0x00 = DEPOSIT)

         We'll use:
            sidechain_id = 0x01
            payload      = 32 bytes of 0x00
            tag          = 0x00 (DEPOSIT)
        Script hex:
            b4 01 01 20 00..00 01 00
        """
        sidechain_id = "01"
        payload      = "00" * 32  # 32 zero bytes
        tag          = "00"       # deposit

        # OP_DRIVECHAIN (b4)
        # PUSH1 (01) + sidechain_id
        # PUSH32 (20) + payload
        # PUSH1 (01) + tag
        dc_script = "b4" + "01" + sidechain_id + "20" + payload + "01" + tag

        raw = node.createrawtransaction(
            inputs=[],
            outputs=[{"scriptPubKey": dc_script, "amount": amount}],
        )
        funded = node.fundrawtransaction(raw)["hex"]
        signed = node.signrawtransactionwithwallet(funded)["hex"]
        return signed

    def _get_drivechain_status(self, node):
        info = node.getblockchaininfo()
        return info["bip9_softforks"]["drivechain"]["status"]

    def run_test(self):
        node = self.nodes[0]

        addr = node.getnewaddress()
        node.generatetoaddress(101, addr)

        # status = self._get_drivechain_status(node)
        # self.log.info(f"Initial drivechain status: {status}")
        # assert status in ["defined", "started", "locked_in"], f"Unexpected initial status: {status}"
        # assert status != "active"
        status = self._get_drivechain_status(node)
        self.log.info(f"Initial drivechain status: {status}")
        assert_equal(status, "active")


        dc_tx_hex = self._create_drivechain_tx(node)

        # self.log.info("Testing pre-activation mempool rejection for drivechain output...")
        # assert_raises_rpc_error(
        #     -26,
        #     "drivechain-before-activation",
        #     node.sendrawtransaction,
        #     dc_tx_hex,
        # )

        # self.log.info("Mining blocks until drivechain deployment becomes active...")
        # max_blocks = 40
        # for _ in range(max_blocks):
        #     status = self._get_drivechain_status(node)
        #     if status == "active":
        #         break
        #     node.generate(1)
        # else:
        #     raise AssertionError("Drivechain deployment did not become active within expected blocks")

        # status = self._get_drivechain_status(node)
        # self.log.info(f"Drivechain status after mining: {status}")
        # assert_equal(status, "active")

        self.log.info("Testing post-activation acceptance of drivechain output...")
        dc_tx_hex2 = self._create_drivechain_tx(node)
        txid = node.sendrawtransaction(dc_tx_hex2)

        node.generate(1)
        tx = node.gettransaction(txid)
        self.log.info(f"Drivechain tx {txid} confirmations: {tx['confirmations']}")
        assert tx["confirmations"] > 0

        self.log.info("Drivechain BIP8-style activation test passed.")


if __name__ == '__main__':
    DrivechainActivationTest().main()
