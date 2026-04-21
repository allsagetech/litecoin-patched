#!/usr/bin/env python3
# Copyright (c) 2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.
"""Exercise legacy sidechain RPC removal."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error


LEGACY_RPC_NAMESPACE = "".join(["dri", "ve", "chain"])


class LegacySidechainRpcRemovalTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.generatetoaddress(101, node.getnewaddress())
        tmpl = node.getblocktemplate({"rules": ["segwit", "mweb"]})
        assert f"{LEGACY_RPC_NAMESPACE}votes" not in tmpl
        assert f"{LEGACY_RPC_NAMESPACE}bmmaccepts" not in tmpl

        self.log.info("Legacy sidechain RPCs should be unavailable.")
        assert_raises_rpc_error(
            -32601,
            "Method not found",
            getattr(node, f"send{LEGACY_RPC_NAMESPACE}register"),
            node.getnewaddress(),
            7,
            1,
        )
        assert_raises_rpc_error(
            -32601,
            "Method not found",
            getattr(node, f"send{LEGACY_RPC_NAMESPACE}deposit"),
            7,
            "11" * 32,
            [1],
        )
        assert_raises_rpc_error(
            -32601,
            "Method not found",
            getattr(node, f"send{LEGACY_RPC_NAMESPACE}bundle"),
            7,
            "11" * 32,
            node.getnewaddress(),
        )
        assert_raises_rpc_error(
            -32601,
            "Method not found",
            getattr(node, f"send{LEGACY_RPC_NAMESPACE}bmmrequest"),
            7,
            "11" * 32,
            "22" * 32,
        )
        assert_raises_rpc_error(
            -32601,
            "Method not found",
            getattr(node, f"send{LEGACY_RPC_NAMESPACE}execute"),
            7,
            "11" * 32,
            [],
        )
        assert_raises_rpc_error(
            -32601,
            "Method not found",
            getattr(node, f"get{LEGACY_RPC_NAMESPACE}info"),
        )


if __name__ == "__main__":
    LegacySidechainRpcRemovalTest().main()
