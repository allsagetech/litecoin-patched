#!/usr/bin/env python3
# Copyright (c) 2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


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


def get_sidechain_info(node, sidechain_id):
    info = node.getvaliditysidechaininfo()
    for sidechain in info["sidechains"]:
        if sidechain["id"] == sidechain_id:
            return sidechain
    raise AssertionError(f"missing sidechain {sidechain_id} in getvaliditysidechaininfo")


class ValiditySidechainWalletTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        mining_address = node.getnewaddress()
        node.generatetoaddress(101, mining_address)

        supported = node.getvaliditysidechaininfo()["supported_proof_configs"][0]
        config = build_register_config(supported)
        sidechain_id = 7

        self.log.info("Registering a validity sidechain with the supported scaffold profile.")
        register_res = node.sendvaliditysidechainregister(sidechain_id, config)
        node.generate(1)

        sidechain = get_sidechain_info(node, sidechain_id)
        assert_equal(register_res["sidechain_id"], sidechain_id)
        assert_equal(sidechain["current_state_root"], config["initial_state_root"])
        assert_equal(sidechain["current_withdrawal_root"], config["initial_withdrawal_root"])
        assert_equal(sidechain["queue_state"]["pending_message_count"], 0)
        assert_equal(sidechain["latest_batch_number"], 0)

        self.log.info("Submitting a deposit through the wallet RPC.")
        refund_address = node.getnewaddress()
        deposit_amount = Decimal("1.25")
        destination_commitment = "33" * 32
        deposit_res = node.sendvaliditydeposit(
            sidechain_id,
            destination_commitment,
            {"address": refund_address},
            deposit_amount,
            7,
        )
        node.generate(1)
        deposit_height = node.getblockcount()

        sidechain = get_sidechain_info(node, sidechain_id)
        assert_equal(sidechain["escrow_balance"], int(deposit_amount * 100_000_000))
        assert_equal(sidechain["queue_state"]["pending_message_count"], 1)
        assert_equal(sidechain["queue_state"]["pending_deposit_count"], 1)

        deposit_obj = {
            "deposit_id": deposit_res["deposit_id"],
            "amount": deposit_amount,
            "destination_commitment": destination_commitment,
            "nonce": deposit_res["nonce"],
        }

        self.log.info("Rejecting reclaim before the deposit reclaim delay.")
        assert_raises_rpc_error(
            -26,
            "deposit reclaim delay not reached",
            node.sendstaledepositreclaim,
            sidechain_id,
            deposit_obj,
            {"address": refund_address},
        )

        self.log.info("Submitting a force-exit request through the wallet RPC.")
        force_exit_res = node.sendforceexitrequest(
            sidechain_id,
            "55" * 32,
            "66" * 32,
            Decimal("0.50"),
            {"address": node.getnewaddress()},
            9,
        )
        node.generate(1)

        sidechain = get_sidechain_info(node, sidechain_id)
        assert_equal(len(force_exit_res["request_hash"]), 64)
        assert_equal(sidechain["queue_state"]["pending_message_count"], 2)
        assert_equal(sidechain["queue_state"]["pending_force_exit_count"], 1)

        self.log.info("Submitting a no-op scaffold batch with the wallet auto-building the scaffold proof.")
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
        batch_res = node.sendvaliditybatch(sidechain_id, public_inputs)
        assert_equal(batch_res["auto_scaffold_proof"], True)
        node.generate(1)

        sidechain = get_sidechain_info(node, sidechain_id)
        assert_equal(sidechain["latest_batch_number"], 1)
        assert_equal(len(sidechain["accepted_batches"]), 1)
        assert_equal(sidechain["accepted_batches"][0]["batch_number"], 1)

        self.log.info("Advancing to the deposit reclaim height and reclaiming the stale deposit.")
        reclaim_height = deposit_height + config["deposit_reclaim_delay"]
        current_height = node.getblockcount()
        if current_height < reclaim_height:
            node.generate(reclaim_height - current_height)

        sidechain = get_sidechain_info(node, sidechain_id)
        assert_equal(sidechain["queue_state"]["reclaimable_deposit_count"], 1)
        assert_equal(sidechain["queue_state"]["matured_force_exit_count"], 1)

        reclaim_res = node.sendstaledepositreclaim(
            sidechain_id,
            deposit_obj,
            {"address": refund_address},
        )
        assert_equal(reclaim_res["deposit_id"], deposit_res["deposit_id"])
        node.generate(1)

        sidechain = get_sidechain_info(node, sidechain_id)
        assert_equal(sidechain["escrow_balance"], 0)
        assert_equal(sidechain["queue_state"]["head_index"], 1)
        assert_equal(sidechain["queue_state"]["pending_message_count"], 1)
        assert_equal(sidechain["queue_state"]["pending_deposit_count"], 0)
        assert_equal(sidechain["queue_state"]["pending_force_exit_count"], 1)


if __name__ == "__main__":
    ValiditySidechainWalletTest().main()
