#!/usr/bin/env python3
# Copyright (c) 2025-2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from decimal import Decimal
from test_framework.blocktools import create_block, create_coinbase, add_witness_commitment
from test_framework.messages import CTxOut, CTransaction, FromHex, hash256
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


def mine_empty(node, nblocks: int):
    for _ in range(nblocks):
        assert_equal(submit_block(node), None)


def mine_votes(node, *, scid: int, bundle_hash_hex: str, nblocks: int):
    vote_spk = make_drivechain_script(scid, bundle_hash_hex, 0x02)
    vote_out = CTxOut(0, vote_spk)
    for _ in range(nblocks):
        assert_equal(submit_block(node, extra_coinbase_vouts=[vote_out]), None)


def get_bundle(node, scid: int, bundle_hash_hex: str):
    info = node.getdrivechaininfo()
    for sc in info["sidechains"]:
        if sc["id"] != scid:
            continue
        for b in sc["bundles"]:
            if b["hash"] == bundle_hash_hex:
                return b
    return None


def compute_execute_bundle_hash(node, scid: int, withdrawals):
    preimage = bytearray()
    preimage.append(scid)
    preimage.extend(len(withdrawals).to_bytes(4, byteorder="little"))

    for w in withdrawals:
        script_hex = w.get("script")
        if script_hex is None:
            script_hex = node.getaddressinfo(w["address"])["scriptPubKey"]
        script = bytes.fromhex(script_hex)

        amount_sat = int(w["amount"] * 100_000_000)
        preimage.extend(amount_sat.to_bytes(8, byteorder="little", signed=False))
        preimage.append(len(script))
        preimage.extend(script)

    return hash256(bytes(preimage))[::-1].hex()


class DrivechainVoteWindowBoundary(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def run_test(self):
        n = self.nodes[0]
        n.generatetoaddress(110, n.getnewaddress())

        scid = 1
        payload = "00" * 32
        withdrawals = [{"address": n.getnewaddress(), "amount": Decimal("0.1")}]
        bundle_hash = compute_execute_bundle_hash(n, scid, withdrawals)

        n.senddrivechaindeposit(scid, payload, [Decimal("1.0")])
        n.generatetoaddress(1, n.getnewaddress())
        n.senddrivechainbundle(scid, bundle_hash, Decimal("0.1"))
        n.generatetoaddress(1, n.getnewaddress())

        bundle = get_bundle(n, scid, bundle_hash)
        assert bundle is not None
        vote_start = int(bundle["vote_start_height"])
        vote_end = int(bundle["vote_end_height"])

        cur_h = n.getblockcount()
        if cur_h < vote_start - 1:
            # Pre-window votes MUST NOT count.
            mine_votes(n, scid=scid, bundle_hash_hex=bundle_hash, nblocks=vote_start - 1 - cur_h)

        bundle = get_bundle(n, scid, bundle_hash)
        assert bundle is not None
        assert_equal(bundle["approved"], False)

        while n.getblockcount() < vote_start:
            # vote_start is inside the voting window; missing vote is consensus-invalid.
            mine_votes(n, scid=scid, bundle_hash_hex=bundle_hash, nblocks=1)

        # Approve inside the window.
        while True:
            bundle = get_bundle(n, scid, bundle_hash)
            assert bundle is not None
            if bundle["approved"]:
                break
            if n.getblockcount() >= vote_end:
                raise AssertionError("bundle did not get approved inside vote window")
            mine_votes(n, scid=scid, bundle_hash_hex=bundle_hash, nblocks=1)

        # Approved but still in window: EXECUTE must fail.
        if n.getblockcount() <= vote_end:
            assert_raises_rpc_error(
                -26,
                "dc-exec-window-open",
                n.senddrivechainexecute,
                scid,
                bundle_hash,
                withdrawals,
            )

        cur_h = n.getblockcount()
        if cur_h <= vote_end:
            mine_empty(n, vote_end + 1 - cur_h)

        ok_exec_txid = n.senddrivechainexecute(
            scid, bundle_hash, withdrawals
        )
        ok_res = submit_block(n, txids=[ok_exec_txid])
        assert_equal(ok_res, None)


if __name__ == "__main__":
    DrivechainVoteWindowBoundary().main()
