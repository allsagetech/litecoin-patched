#!/usr/bin/env python3
# Copyright (c) 2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from decimal import Decimal

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
        txhex = node.getrawtransaction(txid)
        tx = FromHex(CTransaction(), txhex)
        tx.rehash()
        block.vtx.append(tx)

    block.hashMerkleRoot = block.calc_merkle_root()
    add_witness_commitment(block)
    block.solve()
    return node.submitblock(block.serialize().hex())


def mine_empty_blocks(node, nblocks: int):
    for _ in range(nblocks):
        assert_equal(submit_block(node), None)


def mine_vote_blocks(node, *, scid: int, bundle_hash_hex: str, nblocks: int):
    vote_spk = make_drivechain_script(scid, bundle_hash_hex, 0x02)
    vote_out = CTxOut(0, vote_spk)
    for _ in range(nblocks):
        assert_equal(submit_block(node, extra_coinbase_vouts=[vote_out]), None)


def get_bundle(node, scid: int, bundle_hash_hex: str):
    info = node.getdrivechaininfo()
    for sc in info["sidechains"]:
        if sc["id"] != scid:
            continue
        for bundle in sc["bundles"]:
            if bundle["hash"] == bundle_hash_hex:
                return bundle
    return None


def compute_execute_bundle_hash(node, scid: int, withdrawals):
    preimage = bytearray()
    preimage.append(scid)
    preimage.extend(len(withdrawals).to_bytes(4, byteorder="little"))

    for withdrawal in withdrawals:
        script_hex = withdrawal.get("script")
        if script_hex is None:
            script_hex = node.getaddressinfo(withdrawal["address"])["scriptPubKey"]
        script = bytes.fromhex(script_hex)

        amount_sat = int(withdrawal["amount"] * 100_000_000)
        preimage.extend(amount_sat.to_bytes(8, byteorder="little", signed=False))
        preimage.append(len(script))
        preimage.extend(script)

    return hash256(bytes(preimage))[::-1].hex()


class DrivechainPolicyAuthCaps(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def run_test(self):
        node = self.nodes[0]
        node.generatetoaddress(110, node.getnewaddress())

        scid = 8
        deposit_payload = "11" * 32
        owner_addr = node.getnewaddress(address_type="p2sh-segwit")
        max_escrow_amount = Decimal("1.50")
        max_bundle_withdrawal = Decimal("0.75")
        withdrawals = [{"address": node.getnewaddress(), "amount": Decimal("0.80")}]
        bundle_hash = compute_execute_bundle_hash(node, scid, withdrawals)

        node.senddrivechainregister(
            owner_addr,
            scid,
            Decimal("1.0"),
            False,
            1,
            max_escrow_amount,
            max_bundle_withdrawal,
        )
        node.generatetoaddress(1, node.getnewaddress())

        node.senddrivechaindeposit(scid, deposit_payload, [Decimal("1.0")])
        node.generatetoaddress(1, node.getnewaddress())

        assert_raises_rpc_error(
            -26,
            "drivechain-escrow-cap-exceeded",
            node.senddrivechaindeposit,
            scid,
            deposit_payload,
            [Decimal("0.6")],
        )

        node.senddrivechainbundle(scid, bundle_hash, owner_addr)
        node.generatetoaddress(1, node.getnewaddress())

        bundle = get_bundle(node, scid, bundle_hash)
        assert bundle is not None
        vote_start = int(bundle["vote_start_height"])
        vote_end = int(bundle["vote_end_height"])
        approval_height = int(bundle["approval_height"])
        executable_height = int(bundle["executable_height"])

        cur_h = node.getblockcount()
        if cur_h < vote_start:
            mine_empty_blocks(node, vote_start - cur_h - 1)

        while node.getblockcount() < vote_end:
            mine_vote_blocks(node, scid=scid, bundle_hash_hex=bundle_hash, nblocks=1)

        assert_equal(submit_block(node), None)
        assert_equal(node.getblockcount(), approval_height)

        cur_h = node.getblockcount()
        if cur_h < executable_height:
            mine_empty_blocks(node, executable_height - cur_h)

        assert_raises_rpc_error(
            -26,
            "drivechain-bundle-withdraw-cap-exceeded",
            node.senddrivechainexecute,
            scid,
            bundle_hash,
            withdrawals,
        )


if __name__ == "__main__":
    DrivechainPolicyAuthCaps().main()
