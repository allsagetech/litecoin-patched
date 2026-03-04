#!/usr/bin/env python3
# Copyright (c) 2025-2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from decimal import Decimal

from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.messages import CTxOut
from test_framework.script import CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


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


def get_bundle(node, scid: int, bundle_hash_hex: str):
    info = node.getdrivechaininfo()
    for sc in info["sidechains"]:
        if sc["id"] != scid:
            continue
        for bundle in sc["bundles"]:
            if bundle["hash"] == bundle_hash_hex:
                return bundle
    return None


class DrivechainVoteSinglePerSidechain(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def run_test(self):
        n = self.nodes[0]
        n.generatetoaddress(110, n.getnewaddress())

        scid = 1
        bundle_hash = "11" * 32
        n.senddrivechaindeposit(scid, "00" * 32, [Decimal("1.0")])
        n.generatetoaddress(1, n.getnewaddress())
        n.senddrivechainbundle(scid, bundle_hash, Decimal("0.1"))
        n.generatetoaddress(1, n.getnewaddress())

        bundle_before = get_bundle(n, scid, bundle_hash)
        assert bundle_before is not None
        assert_equal(bundle_before["yes_votes"], 0)

        vote_spk = make_drivechain_script(scid, bundle_hash, 0x02)
        res = submit_block(n, extra_coinbase_vouts=[CTxOut(0, vote_spk), CTxOut(0, vote_spk)])
        assert res is not None
        assert "dc-vote-duplicate-sidechain" in str(res)

        bundle_after = get_bundle(n, scid, bundle_hash)
        assert bundle_after is not None
        assert_equal(bundle_after["yes_votes"], 0)


if __name__ == "__main__":
    DrivechainVoteSinglePerSidechain().main()
