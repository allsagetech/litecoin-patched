#!/usr/bin/env python3
# Copyright (c) 2025-2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.messages import CTransaction, CTxOut, FromHex, hash256
from test_framework.script import CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


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
        try:
            txhex = node.getrawtransaction(txid)
        except JSONRPCException:
            txhex = node.gettransaction(txid)["hex"]
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


def make_bundle_hash(node, scid: int, withdrawals):
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


def get_bundle(node, scid: int, bundle_hash_hex: str):
    info = node.getdrivechaininfo()
    for sc in info["sidechains"]:
        if sc["id"] != scid:
            continue
        for bundle in sc["bundles"]:
            if bundle["hash"] == bundle_hash_hex:
                return bundle
    return None


class DrivechainSameBlockDepositEscrow(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def run_test(self):
        n = self.nodes[0]
        n.generatetoaddress(110, n.getnewaddress())

        scid = 1
        bootstrap_deposit = Decimal("0.01")
        same_block_deposit = Decimal("0.1")
        withdraw_amount = Decimal("0.1")
        withdrawals = [{"address": n.getnewaddress(), "amount": withdraw_amount}]
        bundle_hash = make_bundle_hash(n, scid, withdrawals)

        owner_privkey = n.getnewaddress()
        n.senddrivechainregister(owner_privkey, scid, Decimal("1.0"))
        n.generatetoaddress(1, n.getnewaddress())

        # Bootstrap escrow so bundle commits are valid.
        n.senddrivechaindeposit(scid, "00" * 32, [bootstrap_deposit])
        n.generatetoaddress(1, n.getnewaddress())

        # Commit + approve a bundle while escrow is still below withdrawal amount.
        n.senddrivechainbundle(scid, bundle_hash, owner_privkey)
        n.generatetoaddress(1, n.getnewaddress())

        bundle = get_bundle(n, scid, bundle_hash)
        assert bundle is not None
        vote_start = int(bundle["vote_start_height"])
        vote_end = int(bundle["vote_end_height"])
        approval_height = int(bundle["approval_height"])
        executable_height = int(bundle["executable_height"])

        cur_h = n.getblockcount()
        if cur_h < vote_start:
            mine_empty(n, vote_start - cur_h - 1)

        while n.getblockcount() < vote_end:
            mine_votes(n, scid=scid, bundle_hash_hex=bundle_hash, nblocks=1)

        bundle = get_bundle(n, scid, bundle_hash)
        assert bundle is not None
        assert_equal(bundle["approved"], False)

        assert_equal(submit_block(n), None)
        bundle = get_bundle(n, scid, bundle_hash)
        assert bundle is not None
        assert_equal(n.getblockcount(), approval_height)
        assert_equal(bundle["approved"], True)

        cur_h = n.getblockcount()
        if cur_h < executable_height:
            mine_empty(n, executable_height - cur_h)

        assert_raises_rpc_error(
            -26,
            "drivechain-escrow-insufficient",
            n.senddrivechainexecute,
            scid,
            bundle_hash,
            withdrawals,
        )

        exec_txid = n.senddrivechainexecute(scid, bundle_hash, withdrawals, True)
        dep_txid = n.senddrivechaindeposit(scid, "00" * 32, [same_block_deposit])

        # EXECUTE appears before DEPOSIT in transaction order.
        res = submit_block(n, txids=[exec_txid, dep_txid])
        assert_equal(res, None)

        info = n.getdrivechaininfo()
        sidechain = next(sc for sc in info["sidechains"] if sc["id"] == scid)
        assert_equal(sidechain["escrow_balance"], int((bootstrap_deposit + same_block_deposit - withdraw_amount) * 100_000_000))
        bundle_after = get_bundle(n, scid, bundle_hash)
        assert bundle_after is not None
        assert_equal(bundle_after["executed"], True)


if __name__ == "__main__":
    DrivechainSameBlockDepositEscrow().main()
