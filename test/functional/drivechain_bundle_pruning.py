#!/usr/bin/env python3
# Copyright (c) 2025-2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from decimal import Decimal

from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.messages import CTxOut
from test_framework.script import CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


def get_bundle(node, scid: int, bundle_hash_hex: str):
    info = node.getdrivechaininfo()
    for sc in info["sidechains"]:
        if sc["id"] != scid:
            continue
        for bundle in sc["bundles"]:
            if bundle["hash"] == bundle_hash_hex:
                return bundle
    return None


def make_drivechain_script(sidechain_id: int, payload_hex: str, tag: int) -> CScript:
    payload = bytes.fromhex(payload_hex)[::-1]
    assert len(payload) == 32
    return CScript(bytes([0x6A, 0xB4, 0x01, sidechain_id, 0x20]) + payload + bytes([0x01, tag]))


def submit_block(node, *, extra_coinbase_vouts=None):
    if extra_coinbase_vouts is None:
        extra_coinbase_vouts = []

    tip = node.getbestblockhash()
    height = node.getblockcount() + 1
    ntime = node.getblockheader(tip)["time"] + 1

    coinbase = create_coinbase(height)
    for vout in extra_coinbase_vouts:
        coinbase.vout.append(vout)
    coinbase.rehash()

    block = create_block(int(tip, 16), coinbase, ntime, version=0x20000000)
    block.hashMerkleRoot = block.calc_merkle_root()
    add_witness_commitment(block)
    block.solve()
    return node.submitblock(block.serialize().hex())


def mine_empty_blocks(node, nblocks: int):
    for _ in range(nblocks):
        assert_equal(submit_block(node), None)


class DrivechainBundlePruning(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def run_test(self):
        n = self.nodes[0]
        n.generatetoaddress(110, n.getnewaddress())

        scid = 1
        bundle1 = "11" * 32

        owner_privkey = n.getnewaddress()
        n.senddrivechainregister(owner_privkey, scid, Decimal("1.0"))
        n.generatetoaddress(1, n.getnewaddress())

        # Sidechain must exist before bundle commits.
        n.senddrivechaindeposit(scid, "00" * 32, [Decimal("1.0")])
        n.generatetoaddress(1, n.getnewaddress())

        n.senddrivechainbundle(scid, bundle1, owner_privkey)
        n.generatetoaddress(1, n.getnewaddress())
        b1 = get_bundle(n, scid, bundle1)
        assert b1 is not None
        vote_start = int(b1["vote_start_height"])
        vote_end = int(b1["vote_end_height"])
        approval_height = int(b1["approval_height"])

        cur_h = n.getblockcount()
        if cur_h < vote_start - 1:
            mine_empty_blocks(n, vote_start - 1 - cur_h)

        vote_no_out = CTxOut(0, make_drivechain_script(scid, bundle1, 0x04))
        while n.getblockcount() < vote_end:
            assert_equal(submit_block(n, extra_coinbase_vouts=[vote_no_out]), None)

        # The bundle remains visible at the end of the vote window so operators can
        # inspect the final tally, then it is pruned at approval_height when it failed.
        assert get_bundle(n, scid, bundle1) is not None
        assert_equal(submit_block(n), None)
        assert_equal(n.getblockcount(), approval_height)
        assert get_bundle(n, scid, bundle1) is None


if __name__ == "__main__":
    DrivechainBundlePruning().main()
