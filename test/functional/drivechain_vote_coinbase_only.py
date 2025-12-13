#!/usr/bin/env python3
# Copyright (c) 2025 AllSageTech, LLC
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error, assert_equal

class DrivechainVoteCoinbaseOnly(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [[
            "-acceptnonstdtxn=1",
        ]]

    def run_test(self):
        n = self.nodes[0]
        n.generatetoaddress(110, n.getnewaddress())

        # Create a non-coinbase tx with a vote output
        raw = make_drivechain_tx(n, kind="VOTE")  # implement helper
        signed = n.signrawtransactionwithwallet(raw)["hex"]

        # Mempool rejection expected if you enforce policy
        assert_raises_rpc_error(-26, "vote", n.sendrawtransaction, signed)

if __name__ == "__main__":
    DrivechainVoteCoinbaseOnly().main()
