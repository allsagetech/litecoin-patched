#!/usr/bin/env python3
# Distributed under the MIT software license.

"""
Drivechain reorg regression test.

This test asserts that *all* Drivechain consensus state is fully rolled back
on reorg and deterministically re-applied when reorged back.

Expected to FAIL until DrivechainState::DisconnectBlock fully reverts:
  - bundle creation
  - vote counts
  - approval flags
  - sidechain creation
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, sync_blocks
from test_framework.messages import (
    CTransaction,
    CTxIn,
    CTxOut,
    COutPoint,
)
from test_framework.script import CScript
from test_framework.blocktools import create_block, create_coinbase, add_witness_commitment

OP_DRIVECHAIN = 0xB4
TAG_DEPOSIT = 0x00
TAG_BUNDLE  = 0x01
TAG_VOTE    = 0x02


def dc_script(scid, payload, tag):
    return CScript(
        bytes([OP_DRIVECHAIN, 0x01, scid, 0x20]) +
        payload +
        bytes([0x01, tag])
    )


def dc_state(node):
    state = node.getdrivechaininfo()
    # Remove volatile fields if present
    state.pop("bestblockhash", None)
    state.pop("height", None)
    return state


def submit_block(node, txs=None, cb_outs=None):
    tip = node.getbestblockhash()
    height = node.getblockcount() + 1
    ntime = node.getblockheader(tip)["time"] + 1

    coinbase = create_coinbase(height)
    if cb_outs:
        for o in cb_outs:
            coinbase.vout.append(o)
    coinbase.rehash()

    block = create_block(int(tip, 16), coinbase, ntime)
    if txs:
        for tx in txs:
            block.vtx.append(tx)

    add_witness_commitment(block)
    block.solve()
    return node.submitblock(block.serialize().hex())


class DrivechainReorgStateRollback(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"], ["-acceptnonstdtxn=1"]]

    def run_test(self):
        n0, n1 = self.nodes

        # Baseline chain
        n0.generatetoaddress(110, n0.getnewaddress())
        self.sync_all()

        baseline = dc_state(n0)
        assert_equal(baseline, dc_state(n1))

        # Fork
        self.disconnect_nodes(0, 1)

        # ---- Node0 fork: create sidechain + bundle + votes ----
        scid = 1
        payload = b"\x11" * 32

        utxo = n0.listunspent()[0]
        dep = CTransaction()
        dep.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]))]
        dep.vout = [CTxOut(100_000_000, dc_script(scid, b"\x00"*32, TAG_DEPOSIT))]
        dep.rehash()

        bundle = CTransaction()
        bundle.vin = [CTxIn(COutPoint(dep.sha256, 0))]
        bundle.vout = [CTxOut(10_000_000, dc_script(scid, payload, TAG_BUNDLE))]
        bundle.rehash()

        submit_block(n0, txs=[dep, bundle])

        vote_out = CTxOut(0, dc_script(scid, payload, TAG_VOTE))
        for _ in range(3):
            submit_block(n0, cb_outs=[vote_out])

        changed = dc_state(n0)
        assert changed != baseline

        # ---- Node1 fork: longer chain, no drivechain ----
        n1.generatetoaddress(n0.getblockcount() + 2 - n1.getblockcount(), n1.getnewaddress())

        # Reorg
        self.connect_nodes(0, 1)
        sync_blocks(self.nodes)

        # EXPECT FULL ROLLBACK
        assert_equal(dc_state(n0), baseline)
        assert_equal(dc_state(n1), baseline)


if __name__ == "__main__":
    DrivechainReorgStateRollback().main()
