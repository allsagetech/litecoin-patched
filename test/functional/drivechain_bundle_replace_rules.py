#!/usr/bin/env python3
# Copyright (c) 2025-2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from decimal import Decimal

from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.messages import CTransaction, CTxOut, FromHex
from test_framework.script import CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


def make_drivechain_script(sidechain_id: int, payload_hex: str, tag: int) -> CScript:
    payload = bytes.fromhex(payload_hex)[::-1]
    assert len(payload) == 32
    return CScript(bytes([0x6A, 0xB4, 0x01, sidechain_id, 0x20]) + payload + bytes([0x01, tag]))


def submit_block(node, *, extra_coinbase_vouts=None, txids=None, tx_hexes=None):
    if extra_coinbase_vouts is None:
        extra_coinbase_vouts = []
    if txids is None:
        txids = []
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
    for txid in txids:
        txhex = node.getrawtransaction(txid)
        tx = FromHex(CTransaction(), txhex)
        tx.rehash()
        block.vtx.append(tx)
    for tx_hex in tx_hexes:
        tx = FromHex(CTransaction(), tx_hex)
        tx.rehash()
        block.vtx.append(tx)

    block.hashMerkleRoot = block.calc_merkle_root()
    add_witness_commitment(block)
    block.solve()
    return node.submitblock(block.serialize().hex())


def mine_empty(node, nblocks: int):
    for _ in range(nblocks):
        assert_equal(submit_block(node), None)


def mine_votes(node, *, scid: int, bundle_hash_hex: str, nblocks: int):
    vote_spk = make_drivechain_script(scid, bundle_hash_hex, 0x02)
    vote_out = CTxOut(0, vote_spk)
    for _ in range(nblocks):
        assert_equal(submit_block(node, extra_coinbase_vouts=[vote_out]), None)


def get_sidechain(node, scid: int):
    info = node.getdrivechaininfo()
    for sc in info["sidechains"]:
        if sc["id"] == scid:
            return sc
    return None


def get_bundle(node, scid: int, bundle_hash_hex: str):
    sc = get_sidechain(node, scid)
    if sc is None:
        return None
    for bundle in sc["bundles"]:
        if bundle["hash"] == bundle_hash_hex:
            return bundle
    return None


def create_funded_signed_tx_hex(node, script: CScript, amount: Decimal) -> str:
    tx = CTransaction()
    tx.vin = []
    tx.vout = [CTxOut(int(amount * 100_000_000), script)]
    funded = node.fundrawtransaction(tx.serialize().hex())["hex"]
    return node.signrawtransactionwithwallet(funded)["hex"]


class DrivechainBundleReplaceRules(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def run_test(self):
        n = self.nodes[0]
        n.generatetoaddress(130, n.getnewaddress())

        scid = 1
        bundle1 = "11" * 32
        bundle2 = "22" * 32
        bundle3 = "33" * 32

        owner_privkey = n.dumpprivkey(n.getnewaddress())
        n.senddrivechainregister(owner_privkey, scid, Decimal("1.0"))
        n.generatetoaddress(1, n.getnewaddress())

        # Sidechain must exist before bundle commits.
        n.senddrivechaindeposit(scid, "00" * 32, [Decimal("1.0")])
        n.generatetoaddress(1, n.getnewaddress())

        n.senddrivechainbundle(scid, bundle1, Decimal("0.1"), False, owner_privkey)
        n.generatetoaddress(1, n.getnewaddress())

        # Replaces unapproved bundle1.
        n.senddrivechainbundle(scid, bundle2, Decimal("0.1"), False, owner_privkey)
        n.generatetoaddress(1, n.getnewaddress())

        sc = get_sidechain(n, scid)
        assert sc is not None
        assert get_bundle(n, scid, bundle1) is None
        assert get_bundle(n, scid, bundle2) is not None
        assert_equal(len(sc["bundles"]), 1)

        b2 = get_bundle(n, scid, bundle2)
        assert b2 is not None
        vote_start = int(b2["vote_start_height"])
        vote_end = int(b2["vote_end_height"])

        cur_h = n.getblockcount()
        if cur_h < vote_start:
            mine_empty(n, vote_start - cur_h - 1)

        while True:
            b2 = get_bundle(n, scid, bundle2)
            assert b2 is not None
            if b2["approved"]:
                break
            if n.getblockcount() >= vote_end:
                raise AssertionError("bundle2 did not get approved before vote window closed")
            mine_votes(n, scid=scid, bundle_hash_hex=bundle2, nblocks=1)

        # While approved and unexecuted, a different commit must fail at mempool admission.
        assert_raises_rpc_error(
            -26,
            "drivechain-approved-bundle-pending",
            n.senddrivechainbundle,
            scid,
            bundle3,
            Decimal("0.1"),
        )

        # And still fail if attempted directly in a block.
        commit3_spk = make_drivechain_script(scid, bundle3, 0x01)
        tx3_hex = create_funded_signed_tx_hex(n, commit3_spk, Decimal("0.1"))
        res = submit_block(n, tx_hexes=[tx3_hex])
        assert res is not None
        assert "drivechain-approved-bundle-pending" in str(res)


if __name__ == "__main__":
    DrivechainBundleReplaceRules().main()
