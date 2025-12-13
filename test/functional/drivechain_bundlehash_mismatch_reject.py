#!/usr/bin/env python3
# Copyright (c) 2025 AllSageTech, LLC
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error

class DrivechainBundlehashMismatchReject(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [[
            "-acceptnonstdtxn=1",
        ]]

    def run_test(self):
        n = self.nodes[0]
        activate_drivechain(n)  # your helper: mine + signal until active
        n.generatetoaddress(110, n.getnewaddress())

        good = make_bundle_commit_tx(n, scid=0, withdrawals=[(n.getnewaddress(), 100000)])
        good_signed = n.signrawtransactionwithwallet(good)["hex"]
        n.sendrawtransaction(good_signed)

        # Now create a "same-looking" commit but with hash intentionally wrong
        bad = make_bundle_commit_tx(n, scid=0, withdrawals=[(n.getnewaddress(), 100001)], force_bad_hash=True)
        bad_signed = n.signrawtransactionwithwallet(bad)["hex"]

        assert_raises_rpc_error(-26, "bundle", n.sendrawtransaction, bad_signed)

if __name__ == "__main__":
    DrivechainBundlehashMismatchReject().main()
