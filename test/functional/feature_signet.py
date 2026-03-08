#!/usr/bin/env python3
# Copyright (c) 2019-2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test basic signet functionality for Litecoin's scrypt-based signet."""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class SignetBasicTest(BitcoinTestFramework):
    def set_test_params(self):
        self.chain = "signet"
        self.num_nodes = 6
        self.setup_clean_chain = True
        shared_args1 = ["-signetchallenge=51"]  # OP_TRUE
        shared_args2 = []  # default challenge
        # We use the exact same keys as the default challenge except as a 2-of-2,
        # which makes blocks from the default signet invalid here.
        shared_args3 = ["-signetchallenge=522103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae"]

        self.extra_args = [
            shared_args1, shared_args1,
            shared_args2, shared_args2,
            shared_args3, shared_args3,
        ]

    def setup_network(self):
        self.setup_nodes()

        # Different signet challenges derive different message starts and must
        # not be connected to one another.
        self.connect_nodes(1, 0)
        self.connect_nodes(3, 2)
        self.connect_nodes(5, 4)

    def run_test(self):
        self.log.info("basic tests using OP_TRUE challenge")

        self.log.info("getmininginfo")
        mining_info = self.nodes[0].getmininginfo()
        assert_equal(mining_info["blocks"], 0)

        assert_equal(mining_info["chain"], "signet")
        assert "currentblocktx" not in mining_info
        assert "currentblockweight" not in mining_info
        assert_equal(mining_info["networkhashps"], Decimal("0"))
        assert_equal(mining_info["pooledtx"], 0)

        self.log.info("mine a block on the OP_TRUE signet and sync the matching peer")
        self.nodes[0].generate(1, maxtries=10000000)
        self.sync_blocks([self.nodes[0], self.nodes[1]])
        assert_equal(self.nodes[1].getblockcount(), 1)

        self.log.info("blocks from one signet challenge are rejected by other signets")
        block = self.nodes[0].getblock(self.nodes[0].getbestblockhash(), 0)
        assert_equal(self.nodes[2].submitblock(block), "bad-signet-blksig")
        assert_equal(self.nodes[2].getblockcount(), 0)
        assert_equal(self.nodes[4].submitblock(block), "bad-signet-blksig")
        assert_equal(self.nodes[4].getblockcount(), 0)

        self.log.info("test that signet logs the derived network magic on node start")
        with self.nodes[0].assert_debug_log(["Signet derived magic (message start): 54d26fbd"]):
            self.restart_node(0)
        with self.nodes[2].assert_debug_log(["Signet derived magic (message start): 0a03cf40"]):
            self.restart_node(2)
        with self.nodes[4].assert_debug_log(["Signet derived magic (message start): 7f2df3ca"]):
            self.restart_node(4)


if __name__ == "__main__":
    SignetBasicTest().main()
