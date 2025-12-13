#!/usr/bin/env python3
# Copyright (c) 2025 AllSageTech, LLC
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error

class DrivechainExecuteRequiresApproval(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [[ "-acceptnonstdtxn=1" ]]

    def run_test(self):
        n = self.nodes[0]
        activate_drivechain(n)
        n.generatetoaddress(110, n.getnewaddress())

        scid = create_sidechain_and_deposit(n, scid=0, amount=5_0000_0000)

        # Create a bundle (COMMIT)
        bundle = make_bundle_commit_tx(n, scid=scid, withdrawals=[(n.getnewaddress(), 100000)])
        bundle_hex = n.signrawtransactionwithwallet(bundle)["hex"]
        bundle_txid = n.sendrawtransaction(bundle_hex)
        n.generatetoaddress(1, n.getnewaddress())

        # Try execute before approval
        ex = make_bundle_execute_tx(n, scid=scid, bundle_txid=bundle_txid)
        ex_hex = n.signrawtransactionwithwallet(ex)["hex"]
        assert_raises_rpc_error(-26, "not approved", n.sendrawtransaction, ex_hex)

        # Now vote to approval threshold and mine
        mine_votes_until_approved(n, scid=scid, bundle_txid=bundle_txid)

        ex2 = make_bundle_execute_tx(n, scid=scid, bundle_txid=bundle_txid)
        ex2_hex = n.signrawtransactionwithwallet(ex2)["hex"]
        n.sendrawtransaction(ex2_hex)
        n.generatetoaddress(1, n.getnewaddress())

        # Execute again should fail
        ex3 = make_bundle_execute_tx(n, scid=scid, bundle_txid=bundle_txid)
        ex3_hex = n.signrawtransactionwithwallet(ex3)["hex"]
        assert_raises_rpc_error(-26, "already", n.sendrawtransaction, ex3_hex)

if __name__ == "__main__":
    DrivechainExecuteRequiresApproval().main()
