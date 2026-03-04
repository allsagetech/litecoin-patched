#!/usr/bin/env python3
# Copyright (c) 2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from test_framework.messages import CTransaction, CTxOut
from test_framework.script import CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error


class DrivechainRegisterConfirmationRequired(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-acceptnonstdtxn=1",
            "-walletbroadcast=0",
        ]]

    def run_test(self):
        node = self.nodes[0]
        scid = 42
        bundle_hash_hex = "44" * 32

        node.generatetoaddress(110, node.getnewaddress())

        owner_privkey = node.dumpprivkey(node.getnewaddress())
        reg = node.senddrivechainregister(owner_privkey, scid)
        reg_tx_hex = node.gettransaction(reg["txid"])["hex"]
        reg_decoded = node.decoderawtransaction(reg_tx_hex)

        register_script_hex = None
        for vout in reg_decoded["vout"]:
            spk_hex = vout["scriptPubKey"]["hex"]
            if spk_hex.startswith("6ab4"):
                register_script_hex = spk_hex
                break
        assert register_script_hex is not None

        bundle_script = CScript(
            bytes([0x6A, 0xB4, 0x01, scid, 0x20]) +
            bytes.fromhex(bundle_hash_hex) +
            bytes([0x01, 0x01])
        )

        tx = CTransaction()
        tx.vin = []
        tx.vout = [
            CTxOut(0, CScript(bytes.fromhex(register_script_hex))),
            CTxOut(0, bundle_script),
        ]

        funded = node.fundrawtransaction(tx.serialize().hex())["hex"]
        signed = node.signrawtransactionwithwallet(funded)["hex"]

        assert_raises_rpc_error(
            -26,
            "drivechain-register-confirmation-required",
            node.sendrawtransaction,
            signed,
        )


if __name__ == "__main__":
    DrivechainRegisterConfirmationRequired().main()
