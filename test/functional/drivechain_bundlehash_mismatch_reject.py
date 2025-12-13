#!/usr/bin/env python3
# Copyright (c) 2025 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.messages import CTxOut
from test_framework.script import CScript
from test_framework.blocktools import create_block, create_coinbase, add_witness_commitment

def make_drivechain_script(sidechain_id: int, payload_hex: str, tag: int) -> CScript:
    payload = bytes.fromhex(payload_hex)
    assert len(payload) == 32
    return CScript(bytes([0xB4, 0x01, sidechain_id, 0x20]) + payload + bytes([0x01, tag]))

def submit_block_with_coinbase_extra_outputs(node, extra_vouts):
    tip = node.getbestblockhash()
    height = node.getblockcount() + 1
    ntime = node.getblockheader(tip)["time"] + 1
    coinbase = create_coinbase(height)
    for vout in extra_vouts:
        coinbase.vout.append(vout)
    coinbase.rehash()
    block = create_block(int(tip, 16), coinbase, ntime)
    add_witness_commitment(block)
    block.solve()
    return node.submitblock(block.serialize().hex())

def mine_votes(node, *, scid: int, bundle_hash_hex: str, nblocks: int):
    vote_spk = make_drivechain_script(scid, bundle_hash_hex, 0x02)
    vote_out = CTxOut(0, vote_spk)
    for _ in range(nblocks):
        res = submit_block_with_coinbase_extra_outputs(node, [vote_out])
        assert_equal(res, None)

class DrivechainBundlehashMismatchReject(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def run_test(self):
        n = self.nodes[0]
        n.generatetoaddress(110, n.getnewaddress())

        scid = 1
        n.senddrivechaindeposit(scid, "00" * 32, [1.0])
        n.generatetoaddress(1, n.getnewaddress())

        H = "11" * 32
        n.senddrivechainbundle(scid, H, 0.1)
        n.generatetoaddress(1, n.getnewaddress())

        mine_votes(n, scid=scid, bundle_hash_hex=H, nblocks=10)

        exec_txid = n.senddrivechainexecute(scid, H, [
            {"address": n.getnewaddress(), "amount": 0.1234},
            {"address": n.getnewaddress(), "amount": 0.0100},
        ])

        res = submit_block_with_coinbase_extra_outputs(n, [])
        if res is None:
            raise AssertionError("Expected mismatch execute to be rejected but block was accepted (likely tx not included).")
        assert "dc-exec-withdrawals-hash-mismatch" in str(res)

if __name__ == "__main__":
    DrivechainBundlehashMismatchReject().main()
