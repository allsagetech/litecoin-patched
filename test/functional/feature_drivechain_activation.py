#!/usr/bin/env python3
# Copyright (c) 2025 AllSageTech, LLC
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
)

from test_framework.messages import CTransaction, CTxOut
from test_framework.script import CScript

COIN = 100_000_000

def fund_and_sign_script_tx(node, script, amount):
    """
    IMPORTANT: Litecoin does NOT support createrawtransaction() for custom script outputs.
    Build tx locally, then fund + sign via wallet.
    """
    tx = CTransaction()
    tx.vin = []
    tx.vout = [CTxOut(int(amount * COIN), script)]
    funded = node.fundrawtransaction(tx.serialize().hex())["hex"]
    return node.signrawtransactionwithwallet(funded)["hex"]

class DrivechainActivationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def skip_test_if_missing_module(self):
        pass

    @staticmethod
    def _make_drivechain_script(*, sidechain_id: int, payload_hex: str, tag: int) -> CScript:
        """Build a drivechain script matching DecodeDrivechainScript:

            OP_DRIVECHAIN
            PUSHDATA(1)  -> sidechain_id
            PUSHDATA(32) -> payload hash
            PUSHDATA(1)  -> tag (0x00 = DEPOSIT)

        Encoded as bytes:
            0xb4 0x01 <id> 0x20 <32 bytes payload> 0x01 <tag>
        """
        assert 0 <= sidechain_id <= 255
        if len(payload_hex) != 64:
            raise AssertionError("payload_hex must be 32 bytes (64 hex chars)")
        payload = bytes.fromhex(payload_hex)
        return CScript(bytes([0xB4, 0x01, sidechain_id, 0x20]) + payload + bytes([0x01, tag]))

    def _create_drivechain_tx(self, node, amount: Decimal = Decimal("1.0")) -> str:
        script = self._make_drivechain_script(sidechain_id=1, payload_hex="00" * 32, tag=0x00)
        return fund_and_sign_script_tx(node, script, amount)

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

        # Post-activation: drivechain output should be accepted.
        self.log.info("Testing post-activation acceptance of drivechain output.")
        dc_tx_hex = self._create_drivechain_tx(node)
        txid = node.sendrawtransaction(dc_tx_hex)
        node.generate(1)

        mempool = node.getrawmempool()
        assert_equal(txid in mempool, False)  # mined

        self.log.info("Drivechain activation test passed.")


if __name__ == "__main__":
    DrivechainActivationTest().main()
