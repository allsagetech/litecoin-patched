#!/usr/bin/env python3
# Copyright (c) 2025 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.messages import CTransaction, CTxOut
from test_framework.script import CScript
from test_framework.blocktools import create_block, create_coinbase, add_witness_commitment
from test_framework.util import assert_equal

def make_drivechain_script(sidechain_id: int, payload_hex: str, tag: int) -> CScript:
    payload = bytes.fromhex(payload_hex)
    assert len(payload) == 32
    return CScript(bytes([0xB4, 0x01, sidechain_id, 0x20]) + payload + bytes([0x01, tag]))

def submit_block_with_coinbase_extra_outputs(node, extra_vouts):
    """
    Create a valid block on regtest with extra outputs appended to coinbase.
    extra_vouts: list[CTxOut]
    """
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

    res = node.submitblock(block.serialize().hex())
    return res

def get_dc_state(node):
    return node.getdrivechaininfo()

def get_sc(dcinfo, scid: int):
    for sc in dcinfo["sidechains"]:
        if sc["id"] == scid:
            return sc
    return None

def get_bundle(sc, bundle_hash_hex: str):
    for b in sc["bundles"]:
        if b["hash"] == bundle_hash_hex:
            return b
    return None

def mine_votes(node, *, scid: int, bundle_hash_hex: str, nblocks: int):
    vote_spk = make_drivechain_script(scid, bundle_hash_hex, 0x02)
    vote_out = CTxOut(0, vote_spk)
    for _ in range(nblocks):
        res = submit_block_with_coinbase_extra_outputs(node, [vote_out])
        assert_equal(res, None)

from test_framework.messages import CTxOut as _CTxOut  # noqa: F401
def make_drivechain_script(sidechain_id: int, payload_hex: str, tag: int) -> CScript:
    payload = bytes.fromhex(payload_hex)
    assert len(payload) == 32
    return CScript(bytes([0xB4, 0x01, sidechain_id, 0x20]) + payload + bytes([0x01, tag]))

class DrivechainVoteCoinbaseOnly(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def run_test(self):
        n = self.nodes[0]
        n.generatetoaddress(110, n.getnewaddress())

        scid = 1
        bundle_hash = "11" * 32
        vote_spk = make_drivechain_script(scid, bundle_hash, 0x02)

        tx = CTransaction()
        tx.vin = []
        tx.vout = [CTxOut(0, vote_spk)]
        funded = n.fundrawtransaction(tx.serialize().hex())["hex"]
        signed = n.signrawtransactionwithwallet(funded)["hex"]
        txid = n.sendrawtransaction(signed)

        tip = n.getbestblockhash()
        height = n.getblockcount() + 1
        ntime = n.getblockheader(tip)["time"] + 1

        coinbase = create_coinbase(height)
        coinbase.rehash()

        block = create_block(int(tip, 16), coinbase, ntime)
        block.vtx.append(n.getrawtransaction(txid, True)["tx"])

        add_witness_commitment(block)
        block.solve()

        res = n.submitblock(block.serialize().hex())
        assert res is not None
        assert "dc-vote-not-coinbase" in str(res)

if __name__ == "__main__":
    DrivechainVoteCoinbaseOnly().main()
