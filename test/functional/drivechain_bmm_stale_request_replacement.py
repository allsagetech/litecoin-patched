#!/usr/bin/env python3
# Copyright (c) 2025-2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.messages import CTransaction, CTxOut
from test_framework.script import CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


def make_bmm_request_script(sidechain_id: int, side_block_hash_hex: str, prev_main_hash_hex: str) -> CScript:
    side_block_hash = bytes.fromhex(side_block_hash_hex)[::-1]
    prev_main_hash = bytes.fromhex(prev_main_hash_hex)[::-1]
    payload = b"\x00\xbf\x00" + bytes([sidechain_id]) + side_block_hash + prev_main_hash
    return CScript(bytes([0x6A, len(payload)]) + payload)


def create_funded_signed_tx_hex(node, script: CScript) -> str:
    tx = CTransaction()
    tx.vin = []
    tx.vout = [CTxOut(0, script)]
    funded = node.fundrawtransaction(tx.serialize().hex())["hex"]
    return node.signrawtransactionwithwallet(funded)["hex"]


def submit_empty_block(node):
    tip = node.getbestblockhash()
    height = node.getblockcount() + 1
    ntime = node.getblockheader(tip)["time"] + 1

    coinbase = create_coinbase(height)
    coinbase.rehash()

    block = create_block(int(tip, 16), coinbase, ntime, version=0x20000000)
    block.hashMerkleRoot = block.calc_merkle_root()
    add_witness_commitment(block)
    block.solve()
    return node.submitblock(block.serialize().hex())


class DrivechainBmmStaleRequestReplacement(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def run_test(self):
        n = self.nodes[0]
        scid = 7
        side_hash_a = "11" * 32
        side_hash_b = "22" * 32

        n.generatetoaddress(110, n.getnewaddress())

        prev_tip = n.getbestblockhash()
        req_a_hex = create_funded_signed_tx_hex(n, make_bmm_request_script(scid, side_hash_a, prev_tip))
        txid_a = n.sendrawtransaction(req_a_hex)
        assert txid_a in n.getrawmempool()

        # Advance tip without mining req_a: it becomes stale for BIP301 prev_mainhash.
        assert_equal(submit_empty_block(n), None)
        assert txid_a not in n.getrawmempool()

        new_prev_tip = n.getbestblockhash()
        req_b_hex = create_funded_signed_tx_hex(n, make_bmm_request_script(scid, side_hash_b, new_prev_tip))
        txid_b = n.sendrawtransaction(req_b_hex)

        mempool = n.getrawmempool()
        assert txid_b in mempool
        assert txid_a not in mempool

        # Sanity: new request remains mineable.
        n.generate(1)
        tx_b = n.gettransaction(txid_b)
        assert_equal(tx_b["confirmations"], 1)


if __name__ == "__main__":
    DrivechainBmmStaleRequestReplacement().main()
