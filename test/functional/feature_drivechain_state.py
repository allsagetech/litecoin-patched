#!/usr/bin/env python3
# Copyright (c) 2025-2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

from test_framework.messages import CTransaction, CTxOut
from test_framework.script import CScript


def make_drivechain_script(*, sidechain_id: int, payload_hex: str, tag: int) -> CScript:
    """Build a drivechain script matching DecodeDrivechainScript.

    Encoded as bytes:
        0xb4 0x01 <id> 0x20 <32-byte payload> 0x01 <tag>
    """
    assert 0 <= sidechain_id <= 255
    if len(payload_hex) != 64:
        raise AssertionError("payload_hex must be 32 bytes (64 hex chars)")
    # RPC hash strings are displayed big-endian; script payload stores uint256 internal bytes.
    payload = bytes.fromhex(payload_hex)[::-1]
    return CScript(bytes([0x6A, 0xB4, 0x01, sidechain_id, 0x20]) + payload + bytes([0x01, tag]))


def create_drivechain_tx(node, *, script: CScript, amount: Decimal) -> str:
    """Create/fund/sign a tx paying `amount` to `script`.

    Avoids createrawtransaction() output-dict incompatibilities on Litecoin.
    """
    tx = CTransaction()
    tx.vin = []
    n_value = int(amount * 100_000_000)
    tx.vout = [CTxOut(n_value, script)]
    raw_hex = tx.serialize().hex()

    funded = node.fundrawtransaction(raw_hex)["hex"]
    signed = node.signrawtransactionwithwallet(funded)["hex"]
    return signed


class DrivechainStateTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # Keep policy from rejecting custom scriptPubKeys as non-standard on regtest.
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def skip_test_if_missing_module(self):
        pass

    def run_test(self):
        node = self.nodes[0]

        addr = node.getnewaddress()
        node.generatetoaddress(101, addr)

        sidechain_id = 1
        owner_privkey = node.getnewaddress()
        node.senddrivechainregister(owner_privkey, sidechain_id, Decimal("1.0"))
        node.generate(1)

        # --- Deposit ---
        DEPOSIT_TAG = 0x00
        deposit_payload = "00" * 32
        deposit_script = make_drivechain_script(sidechain_id=sidechain_id, payload_hex=deposit_payload, tag=DEPOSIT_TAG)

        self.log.info("Creating drivechain DEPOSIT output.")
        amount = Decimal("1.0")
        signed = create_drivechain_tx(node, script=deposit_script, amount=amount)
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

        # --- Bundle commit ---
        bundle_payload = "11" * 32

        self.log.info("Creating drivechain BUNDLE_COMMIT output with owner authorization.")
        txid2 = node.senddrivechainbundle(sidechain_id, bundle_payload, owner_privkey)
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
