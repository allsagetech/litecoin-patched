#!/usr/bin/env python3
# Copyright (c) 2025-2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from decimal import Decimal
from test_framework.blocktools import create_block, create_coinbase, add_witness_commitment
from test_framework.messages import CTxOut, CTransaction, FromHex
from test_framework.script import CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


def make_drivechain_script(sidechain_id: int, payload_hex: str, tag: int) -> CScript:
    # RPC hash strings are displayed big-endian; script payload stores uint256 internal bytes.
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
        txhex = node.getrawtransaction(txid)
        tx = FromHex(CTransaction(), txhex)
        tx.rehash()
        block.vtx.append(tx)

    block.hashMerkleRoot = block.calc_merkle_root()
    add_witness_commitment(block)
    block.solve()
    return node.submitblock(block.serialize().hex())


def get_bundle(node, scid: int, bundle_hash_hex: str):
    info = node.getdrivechaininfo()
    for sc in info["sidechains"]:
        if sc["id"] != scid:
            continue
        for bundle in sc["bundles"]:
            if bundle["hash"] == bundle_hash_hex:
                return bundle
    return None


def mine_empty_blocks(node, nblocks: int):
    for _ in range(nblocks):
        res = submit_block(node)
        assert_equal(res, None)


def mine_vote_blocks(node, *, scid: int, bundle_hash_hex: str, nblocks: int):
    vote_spk = make_drivechain_script(scid, bundle_hash_hex, 0x02)
    vote_out = CTxOut(0, vote_spk)
    for _ in range(nblocks):
        res = submit_block(node, extra_coinbase_vouts=[vote_out])
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
        n.senddrivechaindeposit(scid, "00" * 32, [Decimal("1.0")])
        n.generatetoaddress(1, n.getnewaddress())

        committed_hash = "11" * 32
        n.senddrivechainbundle(scid, committed_hash, Decimal("0.2"))
        n.generatetoaddress(1, n.getnewaddress())

        bundle = get_bundle(n, scid, committed_hash)
        assert bundle is not None
        vote_start = int(bundle["vote_start_height"])
        vote_end = int(bundle["vote_end_height"])

        cur_h = n.getblockcount()
        if cur_h < vote_start:
            mine_empty_blocks(n, vote_start - cur_h - 1)

        while True:
            bundle = get_bundle(n, scid, committed_hash)
            assert bundle is not None
            if bundle["approved"]:
                break
            if n.getblockcount() >= vote_end:
                raise AssertionError("bundle did not get approved before vote window closed")
            mine_vote_blocks(n, scid=scid, bundle_hash_hex=committed_hash, nblocks=1)

        cur_h = n.getblockcount()
        if cur_h <= vote_end:
            mine_empty_blocks(n, vote_end + 1 - cur_h)

        # EXECUTE references committed_hash but withdrawal list does not hash to committed_hash.
        assert_raises_rpc_error(
            -26,
            "drivechain-bundlehash-mismatch",
            n.senddrivechainexecute,
            scid,
            committed_hash,
            [
                {"address": n.getnewaddress(), "amount": Decimal("0.1")},
                {"address": n.getnewaddress(), "amount": Decimal("0.1")},
            ],
            False,
        )


if __name__ == "__main__":
    DrivechainBundlehashMismatchReject().main()
