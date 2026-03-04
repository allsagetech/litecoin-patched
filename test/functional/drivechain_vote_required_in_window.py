#!/usr/bin/env python3
# Copyright (c) 2025-2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from decimal import Decimal

from test_framework.blocktools import create_block, create_coinbase, add_witness_commitment
from test_framework.messages import CTxOut, CTransaction, FromHex
from test_framework.script import CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


def make_drivechain_script(sidechain_id: int, payload_hex: str, tag: int) -> CScript:
    payload = bytes.fromhex(payload_hex)[::-1]
    assert len(payload) == 32
    return CScript(bytes([0x6A, 0xB4, 0x01, sidechain_id, 0x20]) + payload + bytes([0x01, tag]))


def submit_block(node, *, extra_coinbase_vouts=None, txids=None):
    if extra_coinbase_vouts is None:
        extra_coinbase_vouts = []
    if txids is None:
        txids = []

    tip = node.getbestblockhash()
    height = node.getblockcount() + 1
    ntime = node.getblockheader(tip)["time"] + 1

    coinbase = create_coinbase(height)
    for vout in extra_coinbase_vouts:
        coinbase.vout.append(vout)
    coinbase.rehash()

    block = create_block(int(tip, 16), coinbase, ntime, version=0x20000000)
    for txid in txids:
        tx = FromHex(CTransaction(), node.getrawtransaction(txid))
        tx.rehash()
        block.vtx.append(tx)

    block.hashMerkleRoot = block.calc_merkle_root()
    add_witness_commitment(block)
    block.solve()
    return node.submitblock(block.serialize().hex())


def mine_empty_blocks(node, nblocks: int):
    for _ in range(nblocks):
        assert_equal(submit_block(node), None)


def get_bundle(node, scid: int, bundle_hash_hex: str):
    info = node.getdrivechaininfo()
    for sc in info["sidechains"]:
        if int(sc["id"]) != scid:
            continue
        for bundle in sc["bundles"]:
            if bundle["hash"] == bundle_hash_hex:
                return bundle
    return None


class DrivechainVoteRequiredInWindow(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def run_test(self):
        node = self.nodes[0]
        scid = 1
        bundle_hash = "44" * 32

        node.generatetoaddress(110, node.getnewaddress())

        owner_privkey = node.dumpprivkey(node.getnewaddress())
        node.senddrivechainregister(owner_privkey, scid, Decimal("1.0"))
        node.generatetoaddress(1, node.getnewaddress())

        node.senddrivechaindeposit(scid, "00" * 32, [Decimal("1.0")])
        node.generatetoaddress(1, node.getnewaddress())

        node.senddrivechainbundle(scid, bundle_hash, Decimal("0.1"), False, owner_privkey)
        node.generatetoaddress(1, node.getnewaddress())

        bundle = get_bundle(node, scid, bundle_hash)
        assert bundle is not None
        vote_start = int(bundle["vote_start_height"])

        cur_height = node.getblockcount()
        target_height = vote_start - 1
        if cur_height < target_height:
            mine_empty_blocks(node, target_height - cur_height)

        # At vote_start, miners must include a vote in coinbase for this sidechain.
        missing_vote_res = submit_block(node)
        assert missing_vote_res is not None
        assert "dc-vote-required-missing" in str(missing_vote_res)

        vote_no_out = CTxOut(0, make_drivechain_script(scid, bundle_hash, 0x04))
        assert_equal(submit_block(node, extra_coinbase_vouts=[vote_no_out]), None)

        updated_bundle = get_bundle(node, scid, bundle_hash)
        assert updated_bundle is not None
        assert_equal(int(updated_bundle["yes_votes"]), -1)


if __name__ == "__main__":
    DrivechainVoteRequiredInWindow().main()
