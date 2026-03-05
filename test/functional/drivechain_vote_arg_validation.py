#!/usr/bin/env python3
# Copyright (c) 2025-2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from test_framework.test_framework import BitcoinTestFramework


class DrivechainVoteArgValidationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def skip_test_if_missing_module(self):
        pass

    def run_test(self):
        node = self.nodes[0]

        # Mixed-case values should be accepted.
        self.restart_node(0, extra_args=["-acceptnonstdtxn=1", "-drivechainvote=YeS"])
        self.restart_node(0, extra_args=["-acceptnonstdtxn=1", "-drivechainvote=No"])

        # Invalid values should fail startup with a clear validation error.
        self.stop_node(0)
        node.assert_start_raises_init_error(
            extra_args=["-acceptnonstdtxn=1", "-drivechainvote=not-a-mode"],
            expected_msg="Error: Unsupported -drivechainvote value 'not-a-mode' (expected: yes or no)",
        )

        # Bring node back to default to keep teardown path simple.
        self.start_node(0, extra_args=["-acceptnonstdtxn=1"])


if __name__ == "__main__":
    DrivechainVoteArgValidationTest().main()
