#!/usr/bin/env python3
# Copyright (c) 2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.
"""Exercise deprecated legacy drivechain withdrawal RPC gating."""

from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class LegacySidechainRpcDeprecationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [
            [],
            [
                "-deprecatedrpc=senddrivechainbundle",
                "-deprecatedrpc=senddrivechainexecute",
            ],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def _should_enable_legacy_drivechain_rpcs(self):
        return False

    def assert_rpc_not_rejected_as_deprecated(self, rpc, *args):
        try:
            return rpc(*args)
        except JSONRPCException as exc:
            if exc.error["code"] == -32:
                raise AssertionError(f"unexpected deprecation rejection: {exc.error['message']}")
            return exc.error

    def run_test(self):
        node_plain, node_opt_in = self.nodes

        node_opt_in.generatetoaddress(101, node_opt_in.getnewaddress())
        self.sync_all()

        owner_address = node_opt_in.getnewaddress()
        register_result = node_opt_in.senddrivechainregister(owner_address, 7, Decimal("1.0"))
        assert_equal(register_result["sidechain_id"], 7)
        node_opt_in.generate(1)
        self.sync_all()

        bundle_hash = "11" * 32
        withdrawals = [{
            "address": node_opt_in.getnewaddress(),
            "amount": Decimal("0.25"),
        }]

        self.log.info("Legacy bundle RPC should require an explicit deprecated opt-in.")
        assert_raises_rpc_error(
            -32,
            "senddrivechainbundle is a deprecated legacy drivechain withdrawal RPC.",
            node_plain.senddrivechainbundle,
            7,
            bundle_hash,
            owner_address,
        )
        bundle_txid = node_opt_in.senddrivechainbundle(7, bundle_hash, owner_address)
        assert_equal(len(bundle_txid), 64)
        node_opt_in.generate(1)
        self.sync_all()

        self.log.info("Legacy execute RPC should require an explicit deprecated opt-in.")
        assert_raises_rpc_error(
            -32,
            "senddrivechainexecute is a deprecated legacy drivechain withdrawal RPC.",
            node_plain.senddrivechainexecute,
            7,
            bundle_hash,
            withdrawals,
        )
        result = self.assert_rpc_not_rejected_as_deprecated(
            node_opt_in.senddrivechainexecute,
            7,
            bundle_hash,
            withdrawals,
        )
        if isinstance(result, dict) and "code" in result:
            assert result["code"] != -32


if __name__ == "__main__":
    LegacySidechainRpcDeprecationTest().main()
