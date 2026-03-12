#!/usr/bin/env python3
# Copyright (c) 2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


def build_register_config(supported):
    return {
        "version": supported["version"],
        "proof_system_id": supported["proof_system_id"],
        "circuit_family_id": supported["circuit_family_id"],
        "verifier_id": supported["verifier_id"],
        "public_input_version": supported["public_input_version"],
        "state_root_format": supported["state_root_format"],
        "deposit_message_format": supported["deposit_message_format"],
        "withdrawal_leaf_format": supported["withdrawal_leaf_format"],
        "balance_leaf_format": supported["balance_leaf_format"],
        "data_availability_mode": supported["data_availability_mode"],
        "max_batch_data_bytes": supported["max_batch_data_bytes_limit"],
        "max_proof_bytes": supported["max_proof_bytes_limit"],
        "force_inclusion_delay": supported["min_force_inclusion_delay"],
        "deposit_reclaim_delay": supported["min_deposit_reclaim_delay"],
        "escape_hatch_delay": supported["min_escape_hatch_delay"],
        "initial_state_root": "11" * 32,
        "initial_withdrawal_root": "22" * 32,
    }


def get_sidechain(info, sidechain_id):
    for sidechain in info["sidechains"]:
        if sidechain["id"] == sidechain_id:
            return sidechain
    return None


class ValiditySidechainRestartReorg(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.generatetoaddress(101, node.getnewaddress())

        sidechain_id = 19
        supported = node.getvaliditysidechaininfo()["supported_proof_configs"][0]
        config = build_register_config(supported)

        self.log.info("Registering a validity sidechain and adding deposit/batch history.")
        node.sendvaliditysidechainregister(sidechain_id, config)
        node.generate(1)

        node.sendvaliditydeposit(
            sidechain_id,
            "33" * 32,
            {"address": node.getnewaddress()},
            Decimal("1.0"),
            7,
        )
        node.generate(1)

        sidechain = get_sidechain(node.getvaliditysidechaininfo(), sidechain_id)
        assert sidechain is not None
        public_inputs = {
            "batch_number": 1,
            "prior_state_root": sidechain["current_state_root"],
            "new_state_root": sidechain["current_state_root"],
            "l1_message_root_before": sidechain["queue_state"]["root"],
            "l1_message_root_after": sidechain["queue_state"]["root"],
            "consumed_queue_messages": 0,
            "withdrawal_root": sidechain["current_withdrawal_root"],
            "data_root": sidechain["current_data_root"],
            "data_size": 0,
        }
        node.sendvaliditybatch(sidechain_id, public_inputs)
        node.generate(1)
        node.generate(2)

        info_before_restart = node.getvaliditysidechaininfo()
        sidechain_before_restart = get_sidechain(info_before_restart, sidechain_id)
        assert sidechain_before_restart is not None
        assert_equal(sidechain_before_restart["escrow_balance"], 100000000)
        assert_equal(sidechain_before_restart["latest_batch_number"], 1)
        assert_equal(len(sidechain_before_restart["accepted_batches"]), 1)
        assert info_before_restart["state_cache"]["snapshots_written"] >= 1

        self.restart_node(0, extra_args=["-acceptnonstdtxn=1"])
        node = self.nodes[0]

        info_after_restart = node.getvaliditysidechaininfo()
        assert_equal(info_after_restart["sidechains"], info_before_restart["sidechains"])
        recompute_fallbacks = int(info_after_restart["state_cache"]["recompute_fallbacks"])

        self.log.info("Invalidating empty-tip blocks should restore prior validity snapshots without fallback recompute.")
        for _ in range(2):
            node.invalidateblock(node.getbestblockhash())
            info = node.getvaliditysidechaininfo()
            assert_equal(int(info["state_cache"]["recompute_fallbacks"]), recompute_fallbacks)
            sidechain = get_sidechain(info, sidechain_id)
            assert sidechain is not None
            assert_equal(sidechain["escrow_balance"], 100000000)
            assert_equal(sidechain["latest_batch_number"], 1)
            assert_equal(len(sidechain["accepted_batches"]), 1)

        self.log.info("Invalidating the batch block should roll batch state back while still avoiding fallback recompute.")
        node.invalidateblock(node.getbestblockhash())
        info = node.getvaliditysidechaininfo()
        assert_equal(int(info["state_cache"]["recompute_fallbacks"]), recompute_fallbacks)
        sidechain = get_sidechain(info, sidechain_id)
        assert sidechain is not None
        assert_equal(sidechain["escrow_balance"], 100000000)
        assert_equal(sidechain["latest_batch_number"], 0)
        assert_equal(sidechain["accepted_batches"], [])
        assert_equal(sidechain["queue_state"]["pending_message_count"], 1)

        self.log.info("Invalidating the deposit block should roll escrow and queue state back to the registration-only view.")
        node.invalidateblock(node.getbestblockhash())
        info = node.getvaliditysidechaininfo()
        assert_equal(int(info["state_cache"]["recompute_fallbacks"]), recompute_fallbacks)
        sidechain = get_sidechain(info, sidechain_id)
        assert sidechain is not None
        assert_equal(sidechain["escrow_balance"], 0)
        assert_equal(sidechain["queue_state"]["pending_message_count"], 0)
        assert_equal(sidechain["latest_batch_number"], 0)

        self.log.info("Invalidating the registration block should remove the sidechain entirely.")
        node.invalidateblock(node.getbestblockhash())
        info = node.getvaliditysidechaininfo()
        assert_equal(int(info["state_cache"]["recompute_fallbacks"]), recompute_fallbacks)
        assert get_sidechain(info, sidechain_id) is None

        self.restart_node(0, extra_args=["-acceptnonstdtxn=1"])
        node = self.nodes[0]
        info_after_reorg_restart = node.getvaliditysidechaininfo()
        assert get_sidechain(info_after_reorg_restart, sidechain_id) is None


if __name__ == "__main__":
    ValiditySidechainRestartReorg().main()
