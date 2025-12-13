#!/usr/bin/env python3
# Copyright (c) 2025 AllSageTech, LLC
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error

class DrivechainRejectPreActivation(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [[
            "-acceptnonstdtxn=0",
        ]]

    def run_test(self):
        n = self.nodes[0]
        n.generatetoaddress(110, n.getnewaddress())

        raw = make_drivechain_tx(n, kind="DEPOSIT")  # or COMMIT etc
        signed = n.signrawtransactionwithwallet(raw)["hex"]

        assert_raises_rpc_error(
            -26,  # adjust to your actual reject code
            "drivechain",  # adjust substring
            n.sendrawtransaction, signed
        )

if __name__ == "__main__":
    DrivechainRejectPreActivation().main()
