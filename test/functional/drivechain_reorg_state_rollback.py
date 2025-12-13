#!/usr/bin/env python3
# Copyright (c) 2025 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than, sync_blocks
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

def dc_state(node):
    return node.getdrivechaininfo()

class DrivechainReorgStateRollback(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"], ["-acceptnonstdtxn=1"]]

    def run_test(self):
        n0, n1 = self.nodes[0], self.nodes[1]

        n0.generatetoaddress(110, n0.getnewaddress())
        self.sync_all()

        baseline0 = dc_state(n0)
        baseline1 = dc_state(n1)
        assert_equal(baseline0, baseline1)

        self.disconnect_nodes(0, 1)

        scid = 1
        dep_payload = "00" * 32
        bundle_hash = "11" * 32

        n0.senddrivechaindeposit(scid, dep_payload, [1.0])
        n0.generatetoaddress(1, n0.getnewaddress())
        n0.senddrivechainbundle(scid, bundle_hash, 0.1)
        n0.generatetoaddress(1, n0.getnewaddress())
        mine_votes(n0, scid=scid, bundle_hash_hex=bundle_hash, nblocks=3)
        n0.generatetoaddress(1, n0.getnewaddress())

        after0 = dc_state(n0)
        assert after0 != baseline0

        h0 = n0.getblockcount()

        h1_start = n1.getblockcount()
        target = h0 + 2
        to_mine = target - h1_start
        assert_greater_than(to_mine, 0)
        n1.generatetoaddress(to_mine, n1.getnewaddress())
        assert_equal(n1.getblockcount(), target)

        self.connect_nodes(0, 1)
        sync_blocks(self.nodes)

        post0 = dc_state(n0)
        post1 = dc_state(n1)

        assert_equal(post1, baseline1)
        assert_equal(post0, baseline0)

        self.disconnect_nodes(0, 1)

        n1.senddrivechaindeposit(scid, dep_payload, [1.0])
        n1.generatetoaddress(1, n1.getnewaddress())
        n1.senddrivechainbundle(scid, bundle_hash, 0.1)
        n1.generatetoaddress(1, n1.getnewaddress())
        mine_votes(n1, scid=scid, bundle_hash_hex=bundle_hash, nblocks=3)
        n1.generatetoaddress(2, n1.getnewaddress())

        after1 = dc_state(n1)
        assert after1 != baseline1

        n0.generatetoaddress(1, n0.getnewaddress())

        self.connect_nodes(0, 1)
        sync_blocks(self.nodes)

        final0 = dc_state(n0)
        final1 = dc_state(n1)

        assert_equal(final0, final1)
        assert_equal(final1, after1)

if __name__ == "__main__":
    DrivechainReorgStateRollback().main()
