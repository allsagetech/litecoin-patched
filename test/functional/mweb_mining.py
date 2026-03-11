#!/usr/bin/env python3
# Copyright (c) 2014-2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test mining RPCs for MWEB blocks"""

from test_framework.blocktools import (create_coinbase, NORMAL_GBT_REQUEST_PARAMS)
from test_framework.messages import (CBlock, CTransaction, FromHex, hex_str_to_bytes)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.ltc_util import setup_mweb_chain

class MWEBMiningTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.supports_cli = False

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Setup MWEB chain")
        setup_mweb_chain(node)

        # Call getblocktemplate
        node.generatetoaddress(1, node.get_deterministic_priv_key().address)
        gbt = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        next_height = int(gbt["height"])        

        # Build proposal transactions directly from the template so the
        # framework doesn't need a local BLAKE3 implementation.
        assert "mweb" in gbt
        coinbase_tx = create_coinbase(height=next_height)
        coinbase_tx.vout[0].nValue = gbt["coinbasevalue"]
        vtx = [coinbase_tx]
        vtx.extend(FromHex(CTransaction(), tx["data"]) for tx in gbt["transactions"])
        assert vtx[-1].hogex

        # Build block proposal
        block = CBlock()
        block.nVersion = gbt["version"]
        block.hashPrevBlock = int(gbt["previousblockhash"], 16)
        block.nTime = gbt["curtime"]
        block.nBits = int(gbt["bits"], 16)
        block.nNonce = 0
        block.vtx = vtx
        block.hashMerkleRoot = block.calc_merkle_root()

        # Replace the placeholder MWEB-null marker with the template's raw
        # serialized MWEB block bytes.
        block_bytes = block.serialize()[:-1] + b"\x01" + hex_str_to_bytes(gbt["mweb"])

        # Call getblocktemplate with the block proposal
        self.log.info("getblocktemplate: Test valid block")
        rsp = node.getblocktemplate(template_request={
            'data': block_bytes.hex(),
            'mode': 'proposal',
            'rules': ['mweb', 'segwit'],
        })
        assert_equal(rsp, None)


if __name__ == '__main__':
    MWEBMiningTest().main()
