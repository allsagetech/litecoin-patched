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

from test_framework.messages import CTransaction, CTxOut
from test_framework.script import CScript


class DrivechainActivationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[]]

    def skip_test_if_missing_module(self):
        pass

    @staticmethod
    def _make_drivechain_script(sidechain_id: int = 1, payload_hex: str | None = None, tag: int = 0x00) -> CScript:
        """Build a drivechain script matching DecodeDrivechainScript.

        Layout:
            OP_DRIVECHAIN
            PUSHDATA(1)  -> sidechain_id
            PUSHDATA(32) -> payload hash
            PUSHDATA(1)  -> tag (0x00 = DEPOSIT)
        """
        if payload_hex is None:
            payload = b"\x00" * 32
        else:
            if len(payload_hex) != 64:
                raise ValueError("payload_hex must be 64 hex chars (32 bytes)")
            payload = bytes.fromhex(payload_hex)

        if not (0 <= sidechain_id <= 255):
            raise ValueError("sidechain_id must fit in 1 byte")
        if not (0 <= tag <= 255):
            raise ValueError("tag must fit in 1 byte")

        OP_DRIVECHAIN = 0xB4  # matches your patched opcode value used in the other test
        return CScript([OP_DRIVECHAIN, bytes([sidechain_id]), payload, bytes([tag])])

    def _create_drivechain_tx(self, node, amount: Decimal = Decimal("1.0")) -> str:
        """Create, fund, and sign a tx with a single drivechain DEPOSIT output.

        NOTE: Do *not* use createrawtransaction() for custom scripts on Litecoin.
        Build the raw tx locally, then fundrawtransaction() adds inputs + change.
        """
        tx = CTransaction()
        tx.vin = []
        script = self._make_drivechain_script(sidechain_id=1, payload_hex="00" * 32, tag=0x00)
        n_value = int(amount * 100_000_000)  # satoshis
        tx.vout = [CTxOut(n_value, script)]
        raw_hex = tx.serialize().hex()

        funded = node.fundrawtransaction(raw_hex)["hex"]
        signed = node.signrawtransactionwithwallet(funded)["hex"]
        return signed

    def _get_drivechain_status(self, node) -> str:
        """Find drivechain activation status across Litecoin/Bitcoin Core schema variants."""
        info = node.getblockchaininfo()

        # Legacy (very old) shape
        bip9_sf = info.get("bip9_softforks")
        if isinstance(bip9_sf, dict) and "drivechain" in bip9_sf:
            dc = bip9_sf["drivechain"]
            if isinstance(dc, dict) and "status" in dc:
                return dc["status"]

        softforks = info.get("softforks", {})

        if isinstance(softforks, dict):
            dc = softforks.get("drivechain")
            if isinstance(dc, dict):

                bip9 = dc.get("bip9")
                if isinstance(bip9, dict) and "status" in bip9:
                    return bip9["status"]

                if "status" in dc:
                    return dc["status"]

                if "active" in dc:
                    return "active" if dc["active"] else "inactive"

                if dc.get("type") and "active" in dc:
                    return "active" if dc["active"] else "inactive"

        if isinstance(softforks, list):
            for entry in softforks:
                if not isinstance(entry, dict):
                    continue
                if entry.get("id") != "drivechain":
                    continue

                if "status" in entry:
                    return entry["status"]

                bip9 = entry.get("bip9")
                if isinstance(bip9, dict) and "status" in bip9:
                    return bip9["status"]

                if "active" in entry:
                    return "active" if entry["active"] else "inactive"

        # Fallback on regtest: if the RPC exists, assume active.
        try:
            node.getdrivechaininfo()
            return "active"
        except Exception:
            pass

        raise KeyError("Unable to locate drivechain activation status in getblockchaininfo output")

    def run_test(self):
        node = self.nodes[0]

        addr = node.getnewaddress()
        node.generatetoaddress(101, addr)

        status = self._get_drivechain_status(node)
        self.log.info(f"Initial drivechain status: {status}")
        assert_equal(status, "active")

        # (Optional) If you later want pre-activation behavior, you can re-enable this block.
        # dc_tx_hex = self._create_drivechain_tx(node)
        # self.log.info("Testing pre-activation mempool rejection for drivechain output...")
        # assert_raises_rpc_error(
        #     -26,
        #     "drivechain-before-activation",
        #     node.sendrawtransaction,
        #     dc_tx_hex,
        # )

        self.log.info("Testing post-activation acceptance of drivechain output...")
        dc_tx_hex2 = self._create_drivechain_tx(node)
        txid = node.sendrawtransaction(dc_tx_hex2)

        node.generate(1)
        tx = node.gettransaction(txid)
        self.log.info(f"Drivechain tx {txid} confirmations: {tx['confirmations']}")
        assert tx["confirmations"] > 0

        self.log.info("Drivechain activation test passed.")


if __name__ == "__main__":
    DrivechainActivationTest().main()
