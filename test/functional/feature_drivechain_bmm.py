#!/usr/bin/env python3
# Copyright (c) 2025-2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from test_framework.messages import CTransaction, CTxOut
from test_framework.script import CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


def make_bmm_request_script(sidechain_id: int, side_block_hash_hex: str, prev_main_hash_hex: str) -> CScript:
    side_block_hash = bytes.fromhex(side_block_hash_hex)[::-1]
    prev_main_hash = bytes.fromhex(prev_main_hash_hex)[::-1]
    payload = b"\x00\xbf\x00" + bytes([sidechain_id]) + side_block_hash + prev_main_hash
    return CScript(bytes([0x6A, len(payload)]) + payload)


def make_bmm_accept_script(sidechain_id: int, side_block_hash_hex: str) -> CScript:
    side_block_hash = bytes.fromhex(side_block_hash_hex)[::-1]
    payload = b"\xd1\x61\x73\x68" + bytes([sidechain_id]) + side_block_hash
    return CScript(bytes([0x6A, len(payload)]) + payload)


def create_funded_signed_tx(node, script: CScript) -> str:
    tx = CTransaction()
    tx.vin = []
    tx.vout = [CTxOut(0, script)]
    raw_hex = tx.serialize().hex()
    funded = node.fundrawtransaction(raw_hex)["hex"]
    return node.signrawtransactionwithwallet(funded)["hex"]


class DrivechainBMMTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def skip_test_if_missing_module(self):
        pass

    def run_test(self):
        node = self.nodes[0]
        sidechain_id = 3
        side_block_hash = "22" * 32

        node.generatetoaddress(110, node.getnewaddress())

        bad_prev_hash = "00" * 32
        bad_req = create_funded_signed_tx(
            node,
            make_bmm_request_script(sidechain_id, side_block_hash, bad_prev_hash),
        )
        bad_req_res = node.testmempoolaccept([bad_req])[0]
        assert_equal(bad_req_res["allowed"], False)
        assert_equal(bad_req_res["reject-reason"], "dc-bmm-request-prev-mainhash")

        bad_accept = create_funded_signed_tx(
            node,
            make_bmm_accept_script(sidechain_id, side_block_hash),
        )
        bad_accept_res = node.testmempoolaccept([bad_accept])[0]
        assert_equal(bad_accept_res["allowed"], False)
        assert_equal(bad_accept_res["reject-reason"], "dc-bmm-accept-not-coinbase")

        prev_main_hash = node.getbestblockhash()
        good_req = create_funded_signed_tx(
            node,
            make_bmm_request_script(sidechain_id, side_block_hash, prev_main_hash),
        )
        txid = node.sendrawtransaction(good_req)

        tmpl = node.getblocktemplate({"rules": ["segwit", "mweb"]})
        accepts = tmpl["drivechainbmmaccepts"]
        assert_equal(len(accepts), 1)
        assert_equal(int(accepts[0]["sidechain_id"]), sidechain_id)
        assert_equal(accepts[0]["side_block_hash"], side_block_hash)

        node.generate(1)
        tx = node.gettransaction(txid)
        assert_equal(tx["confirmations"], 1)


if __name__ == "__main__":
    DrivechainBMMTest().main()
