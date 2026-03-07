#!/usr/bin/env python3
# Copyright (c) 2025-2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from decimal import Decimal

from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut, FromHex, hash256
from test_framework.script import CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


def make_drivechain_script(sidechain_id: int, payload_hex: str, tag: int) -> CScript:
    payload = bytes.fromhex(payload_hex)[::-1]
    assert len(payload) == 32
    return CScript(bytes([0x6A, 0xB4, 0x01, sidechain_id, 0x20]) + payload + bytes([0x01, tag]))


def make_execute_script(sidechain_id: int, bundle_hash_hex: str, n_withdrawals: int) -> CScript:
    payload = bytes.fromhex(bundle_hash_hex)[::-1]
    n_le = n_withdrawals.to_bytes(4, byteorder="little")
    return CScript(bytes([0x6A, 0xB4, 0x01, sidechain_id, 0x20]) + payload + bytes([0x01, 0x03, 0x04]) + n_le)


def submit_block(node, *, extra_coinbase_vouts=None, txs=None):
    if extra_coinbase_vouts is None:
        extra_coinbase_vouts = []
    if txs is None:
        txs = []

    tip = node.getbestblockhash()
    height = node.getblockcount() + 1
    ntime = node.getblockheader(tip)["time"] + 1

    coinbase = create_coinbase(height)
    for vout in extra_coinbase_vouts:
        coinbase.vout.append(vout)
    coinbase.rehash()

    block = create_block(int(tip, 16), coinbase, ntime, version=0x20000000)
    for tx in txs:
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


class DrivechainStaleExecuteTemplate(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def run_test(self):
        n = self.nodes[0]
        n.generatetoaddress(130, n.getnewaddress())

        scid = 1
        owner_privkey = n.getnewaddress()
        n.senddrivechainregister(owner_privkey, scid, Decimal("1.0"))
        n.generatetoaddress(1, n.getnewaddress())

        n.senddrivechaindeposit(scid, "00" * 32, [Decimal("1.0")])
        n.generatetoaddress(1, n.getnewaddress())

        withdrawals = [{"address": n.getnewaddress(), "amount": Decimal("0.1")}]
        bundle_hash = make_bundle_hash(n, scid, withdrawals)
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

        # Prepare a confirmed wallet UTXO for tx2 fees before tx1 enters the mempool.
        fee_addr = n.getnewaddress()
        fee_txid = n.sendtoaddress(fee_addr, Decimal("0.001"))
        n.generatetoaddress(1, n.getnewaddress())
        fee_tx_hex = n.gettransaction(fee_txid)["hex"]
        fee_tx = n.decoderawtransaction(fee_tx_hex)

        fee_vout = None
        for vout in fee_tx["vout"]:
            spk = vout["scriptPubKey"]
            addr = spk.get("address")
            addrs = spk.get("addresses", [])
            if addr == fee_addr or fee_addr in addrs:
                fee_vout = vout["n"]
                break
        assert fee_vout is not None

        # tx1: regular wallet EXECUTE; keep this in mempool.
        txid1 = n.senddrivechainexecute(scid, bundle_hash, withdrawals)
        assert txid1 in n.getrawmempool()

        # Build an alternative EXECUTE (tx2) using the pre-confirmed fee input, mine it directly in a block.
        execute_script = make_execute_script(scid, bundle_hash, len(withdrawals))
        withdrawal_spk = bytes.fromhex(n.getaddressinfo(withdrawals[0]["address"])["scriptPubKey"])

        tx2 = CTransaction()
        tx2.vin = [CTxIn(COutPoint(int(fee_txid, 16), fee_vout), b"", 0xFFFFFFFF)]
        tx2.vout = [
            CTxOut(0, execute_script),
            CTxOut(int(Decimal("0.1") * 100_000_000), CScript(withdrawal_spk)),
        ]

        signed_hex = n.signrawtransactionwithwallet(tx2.serialize().hex())["hex"]
        tx2 = FromHex(CTransaction(), signed_hex)

        assert_equal(submit_block(n, txs=[tx2]), None)

        # tx1 remains in mempool but is now stale (bundle already executed).
        assert txid1 in n.getrawmempool()

        # Block template creation must still succeed and must not include stale tx1.
        tmpl = n.getblocktemplate({"rules": ["segwit", "mweb"]})
        txids = [entry["txid"] for entry in tmpl["transactions"]]
        assert txid1 not in txids

        # Mining another block should succeed despite stale drivechain tx in mempool.
        n.generate(1)


if __name__ == "__main__":
    DrivechainStaleExecuteTemplate().main()
