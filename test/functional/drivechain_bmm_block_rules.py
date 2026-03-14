#!/usr/bin/env python3
# Copyright (c) 2025-2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from test_framework.blocktools import create_block, create_coinbase, add_witness_commitment
from test_framework.messages import CTransaction, CTxOut, FromHex
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


def create_funded_signed_tx_hex(node, script: CScript) -> str:
    tx = CTransaction()
    tx.vin = []
    tx.vout = [CTxOut(0, script)]
    raw_hex = tx.serialize().hex()
    funded = node.fundrawtransaction(raw_hex, {"lockUnspents": True})["hex"]
    return node.signrawtransactionwithwallet(funded)["hex"]


def submit_block(node, *, extra_coinbase_vouts=None, tx_hexes=None):
    if extra_coinbase_vouts is None:
        extra_coinbase_vouts = []
    if tx_hexes is None:
        tx_hexes = []

    tip = node.getbestblockhash()
    height = node.getblockcount() + 1
    ntime = node.getblockheader(tip)["time"] + 1

    coinbase = create_coinbase(height)
    for vout in extra_coinbase_vouts:
        coinbase.vout.append(vout)
    coinbase.rehash()

    block = create_block(int(tip, 16), coinbase, ntime, version=0x20000000)
    for tx_hex in tx_hexes:
        tx = FromHex(CTransaction(), tx_hex)
        tx.rehash()
        block.vtx.append(tx)

    block.hashMerkleRoot = block.calc_merkle_root()
    add_witness_commitment(block)
    block.solve()
    return node.submitblock(block.serialize().hex())


class DrivechainBmmBlockRulesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def run_test(self):
        n = self.nodes[0]
        scid = 5
        side_hash_a = "11" * 32
        side_hash_b = "22" * 32

        n.generatetoaddress(110, n.getnewaddress())

        prev_main = n.getbestblockhash()
        req_a = create_funded_signed_tx_hex(n, make_bmm_request_script(scid, side_hash_a, prev_main))

        # Request included without matching coinbase accept.
        res = submit_block(n, tx_hexes=[req_a])
        assert res is not None
        assert "dc-bmm-request-unaccepted" in str(res)

        # Coinbase accept without matching request.
        acc_out = CTxOut(0, make_bmm_accept_script(scid, side_hash_a))
        res = submit_block(n, extra_coinbase_vouts=[acc_out])
        assert res is not None
        assert "dc-bmm-accept-without-request" in str(res)

        # Request must not appear in coinbase.
        req_out = CTxOut(0, make_bmm_request_script(scid, side_hash_a, prev_main))
        res = submit_block(n, extra_coinbase_vouts=[req_out])
        assert res is not None
        assert "dc-bmm-request-coinbase" in str(res)

        # At most one request per sidechain per block.
        req_b = create_funded_signed_tx_hex(n, make_bmm_request_script(scid, side_hash_b, prev_main))
        dup_acc_out = CTxOut(0, make_bmm_accept_script(scid, side_hash_a))
        res = submit_block(n, extra_coinbase_vouts=[dup_acc_out], tx_hexes=[req_a, req_b])
        assert res is not None
        assert "dc-bmm-request-duplicate-sidechain" in str(res)

        # Positive path: request + matching coinbase accept.
        good_acc_out = CTxOut(0, make_bmm_accept_script(scid, side_hash_a))
        assert_equal(submit_block(n, extra_coinbase_vouts=[good_acc_out], tx_hexes=[req_a]), None)


if __name__ == "__main__":
    DrivechainBmmBlockRulesTest().main()
