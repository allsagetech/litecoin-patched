#!/usr/bin/env python3
# Copyright (c) 2026 AllSageTech, LLC
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


def create_funded_signed_tx_hex(node, script: CScript, amount: Decimal) -> str:
    tx = CTransaction()
    tx.vin = []
    tx.vout = [CTxOut(int(amount * 100_000_000), script)]
    funded = node.fundrawtransaction(tx.serialize().hex())["hex"]
    return node.signrawtransactionwithwallet(funded)["hex"]


def submit_block(node, *, tx_hexes=None):
    if tx_hexes is None:
        tx_hexes = []

    tip = node.getbestblockhash()
    height = node.getblockcount() + 1
    ntime = node.getblockheader(tip)["time"] + 1

    coinbase = create_coinbase(height)
    coinbase.rehash()

    block = create_block(int(tip, 16), coinbase, ntime, version=0x20000000)
    for tx_hex in tx_hexes:
        tx = FromHex(CTransaction(), tx_hex)
        tx.rehash()
        block.vtx.append(tx)

    block.hashMerkleRoot = block.calc_merkle_root()
    add_witness_commitment(block)
    block.solve()
    return node.submitblock(block.serialize().hex())


def has_bundle(node, scid: int, bundle_hash: str) -> bool:
    info = node.getdrivechaininfo()
    for sidechain in info["sidechains"]:
        if sidechain["id"] != scid:
            continue
        for bundle in sidechain["bundles"]:
            if bundle["hash"] == bundle_hash:
                return True
    return False


class DrivechainBundleRequiresSidechain(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def run_test(self):
        node = self.nodes[0]
        node.generatetoaddress(110, node.getnewaddress())

        scid = 13
        bundle_hash = "11" * 32

        # Mempool admission rejects commits for unknown sidechains.
        assert_raises_rpc_error(
            -26,
            "drivechain-unknown-sidechain",
            node.senddrivechainbundle,
            scid,
            bundle_hash,
            Decimal("0.1"),
        )

        # Block-level consensus also rejects direct commit for unknown sidechains.
        commit_script = make_drivechain_script(scid, bundle_hash, 0x01)
        commit_tx_hex = create_funded_signed_tx_hex(node, commit_script, Decimal("0.1"))
        res = submit_block(node, tx_hexes=[commit_tx_hex])
        assert res is not None
        assert "drivechain-unknown-sidechain" in str(res)

        # Register and confirm sidechain state; commit then succeeds.
        owner_privkey = node.getnewaddress()
        node.senddrivechainregister(owner_privkey, scid, Decimal("1.0"))
        node.generatetoaddress(1, node.getnewaddress())

        node.senddrivechaindeposit(scid, "00" * 32, [Decimal("1.0")])
        node.generatetoaddress(1, node.getnewaddress())

        txid = node.senddrivechainbundle(scid, bundle_hash, owner_privkey)
        assert isinstance(txid, str)
        node.generatetoaddress(1, node.getnewaddress())
        assert_equal(has_bundle(node, scid, bundle_hash), True)


if __name__ == "__main__":
    DrivechainBundleRequiresSidechain().main()
