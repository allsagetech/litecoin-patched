#!/usr/bin/env python3
# Copyright (c) 2025-2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.messages import CTransaction, CTxOut, FromHex
from test_framework.script import CScript
from test_framework.blocktools import create_block, create_coinbase, add_witness_commitment
from test_framework.util import assert_raises_rpc_error


def make_drivechain_script(sidechain_id: int, payload_hex: str, tag: int) -> CScript:
    # RPC hash strings are displayed big-endian; script payload stores uint256 internal bytes.
    payload = bytes.fromhex(payload_hex)[::-1]
    assert len(payload) == 32
    return CScript(bytes([0x6A, 0xB4, 0x01, sidechain_id, 0x20]) + payload + bytes([0x01, tag]))


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

        # Build a non-coinbase VOTE_YES transaction.
        tx = CTransaction()
        tx.vin = []
        tx.vout = [CTxOut(0, vote_spk)]
        funded = n.fundrawtransaction(tx.serialize().hex())["hex"]
        signed = n.signrawtransactionwithwallet(funded)["hex"]

        assert_raises_rpc_error(
            -26,
            "dc-vote-not-coinbase",
            n.sendrawtransaction,
            signed,
        )

        tip = n.getbestblockhash()
        height = n.getblockcount() + 1
        ntime = n.getblockheader(tip)["time"] + 1

        coinbase = create_coinbase(height)
        coinbase.rehash()

        block = create_block(int(tip, 16), coinbase, ntime, version=0x20000000)
        spend_tx = FromHex(CTransaction(), signed)
        spend_tx.rehash()
        block.vtx.append(spend_tx)

        block.hashMerkleRoot = block.calc_merkle_root()
        add_witness_commitment(block)
        block.solve()

        res = n.submitblock(block.serialize().hex())
        assert res is not None
        assert "dc-vote-not-coinbase" in str(res)


if __name__ == "__main__":
    DrivechainVoteCoinbaseOnly().main()
