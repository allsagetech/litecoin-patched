#!/usr/bin/env python3
# Copyright (c) 2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from decimal import Decimal

from test_framework.script import CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error


def make_bmm_request_script(sidechain_id: int, side_block_hash_hex: str, prev_main_hash_hex: str) -> CScript:
    side_block_hash = bytes.fromhex(side_block_hash_hex)[::-1]
    prev_main_hash = bytes.fromhex(prev_main_hash_hex)[::-1]
    payload = b"\x00\xbf\x00" + bytes([sidechain_id]) + side_block_hash + prev_main_hash
    return CScript(bytes([0x6A, len(payload)]) + payload)


def make_bmm_accept_script(sidechain_id: int, side_block_hash_hex: str) -> CScript:
    side_block_hash = bytes.fromhex(side_block_hash_hex)[::-1]
    payload = b"\xd1\x61\x73\x68" + bytes([sidechain_id]) + side_block_hash
    return CScript(bytes([0x6A, len(payload)]) + payload)


class DrivechainBmmRequestRpcTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def run_test(self):
        node = self.nodes[0]
        node.generatetoaddress(110, node.getnewaddress())

        sidechain_id = 9
        side_block_hash = "11" * 32
        prev_main_hash = node.getbestblockhash()

        txid = node.senddrivechainbmmrequest(sidechain_id, side_block_hash, prev_main_hash, Decimal("0"))
        tx = node.getrawtransaction(txid, True)
        expected_request_hex = make_bmm_request_script(sidechain_id, side_block_hash, prev_main_hash).hex()
        script_hexes = [vout["scriptPubKey"]["hex"] for vout in tx["vout"]]
        assert expected_request_hex in script_hexes

        block_hash = node.generatetoaddress(1, node.getnewaddress())[0]
        block = node.getblock(block_hash, 2)
        coinbase_scripts = [vout["scriptPubKey"]["hex"] for vout in block["tx"][0]["vout"]]
        expected_accept_hex = make_bmm_accept_script(sidechain_id, side_block_hash).hex()
        assert expected_accept_hex in coinbase_scripts

        stale_sidechain_id = sidechain_id + 1
        stale_side_block_hash = "22" * 32
        assert_raises_rpc_error(
            -26,
            "dc-bmm-request-prev-mainhash",
            node.senddrivechainbmmrequest,
            stale_sidechain_id,
            stale_side_block_hash,
            prev_main_hash,
            Decimal("0"),
        )


if __name__ == "__main__":
    DrivechainBmmRequestRpcTest().main()
