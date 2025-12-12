#!/usr/bin/env python3
# Copyright (c) 2025 AllSageTech
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

from test_framework.messages import CTransaction, CTxOut
from test_framework.script import CScript


def make_drivechain_script(sidechain_id: int, payload_hex: str, tag: int) -> CScript:
    """Build a drivechain script matching DecodeDrivechainScript.

    Layout:
        OP_DRIVECHAIN
        PUSHDATA(1)  -> sidechain_id
        PUSHDATA(32) -> payload hash
        PUSHDATA(1)  -> tag
    """
    if not (0 <= sidechain_id <= 255):
        raise ValueError("sidechain_id must fit in 1 byte")
    if len(payload_hex) != 64:
        raise ValueError("payload_hex must be 64 hex chars (32 bytes)")
    if not (0 <= tag <= 255):
        raise ValueError("tag must fit in 1 byte")

    OP_DRIVECHAIN = 0xB4
    payload = bytes.fromhex(payload_hex)
    return CScript([OP_DRIVECHAIN, bytes([sidechain_id]), payload, bytes([tag])])


def build_raw_tx_with_output(script: CScript, amount: Decimal) -> str:
    """Create a raw tx (no inputs) with one custom-script output.

    IMPORTANT (Litecoin): Avoid createrawtransaction() here; Litecoin treats unknown keys as addresses.
    """
    tx = CTransaction()
    tx.vin = []
    tx.vout = [CTxOut(int(amount * 100_000_000), script)]
    return tx.serialize().hex()


class DrivechainStateTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[]]

    def skip_test_if_missing_module(self):
        pass

    def run_test(self):
        node = self.nodes[0]

        addr = node.getnewaddress()
        node.generatetoaddress(101, addr)

        sidechain_id = 1
        deposit_payload = "00" * 32
        DEPOSIT_TAG = 0x00
        deposit_script = make_drivechain_script(sidechain_id, deposit_payload, DEPOSIT_TAG)

        self.log.info("Creating drivechain DEPOSIT output.")
        amount = Decimal("1.0")
        raw = build_raw_tx_with_output(deposit_script, amount)
        funded = node.fundrawtransaction(raw)["hex"]
        signed = node.signrawtransactionwithwallet(funded)["hex"]
        txid = node.sendrawtransaction(signed)
        node.generate(1)

        dcinfo = node.getdrivechaininfo()
        self.log.info(f"Drivechain info after deposit: {dcinfo}")

        sidechains = dcinfo["sidechains"]
        assert_equal(len(sidechains), 1)
        sc = sidechains[0]
        assert_equal(sc["id"], sidechain_id)
        assert_equal(sc["escrow_balance"], int(amount * 100_000_000))
        assert_equal(sc["is_active"], True)
        assert_equal(len(sc["bundles"]), 0)

        BUNDLE_COMMIT_TAG = 0x01
        bundle_payload = "11" * 32
        bundle_script = make_drivechain_script(sidechain_id, bundle_payload, BUNDLE_COMMIT_TAG)

        self.log.info("Creating drivechain BUNDLE_COMMIT output.")
        raw2 = build_raw_tx_with_output(bundle_script, Decimal("0.1"))
        funded2 = node.fundrawtransaction(raw2)["hex"]
        signed2 = node.signrawtransactionwithwallet(funded2)["hex"]
        txid2 = node.sendrawtransaction(signed2)
        node.generate(1)

        dcinfo2 = node.getdrivechaininfo()
        self.log.info(f"Drivechain info after bundle commit: {dcinfo2}")

        sidechains2 = dcinfo2["sidechains"]
        assert_equal(len(sidechains2), 1)
        sc2 = sidechains2[0]

        bundles = sc2["bundles"]
        assert_equal(len(bundles), 1)
        bundle = bundles[0]
        assert_equal(bundle["hash"], bundle_payload)
        assert_equal(bundle["yes_votes"], 0)
        assert_equal(bundle["approved"], False)
        assert_equal(bundle["executed"], False)

        self.log.info("Drivechain state test passed.")


if __name__ == "__main__":
    DrivechainStateTest().main()
