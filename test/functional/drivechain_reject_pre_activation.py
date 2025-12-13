#!/usr/bin/env python3
# Copyright (c) 2025 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error

class DrivechainRejectPreActivation(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

        self.extra_args = [[
            "-acceptnonstdtxn=1",
            "-vbparams=drivechain:2000000000:2100000000:2000000:3000000",
        ]]

    def run_test(self):
        n = self.nodes[0]
        n.generatetoaddress(110, n.getnewaddress())

        assert_raises_rpc_error(
            -26,
            "drivechain-before-activation",
            n.senddrivechaindeposit,
            1,
            "00" * 32,
            [0.5],
        )

if __name__ == "__main__":
    DrivechainRejectPreActivation().main()