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


class ValiditySidechainReclaimReorg(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [
            ["-acceptnonstdtxn=1"],
            ["-acceptnonstdtxn=1"],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        n0 = self.nodes[0]
        n1 = self.nodes[1]

        n0.generatetoaddress(110, n0.getnewaddress())
        self.sync_blocks()

        sidechain_id = 31
        supported = n0.getvaliditysidechaininfo()["supported_proof_configs"][0]
        config = build_register_config(supported)

        destination_commitment = "33" * 32
        deposit_id = "44" * 32
        deposit_amount = Decimal("1.0")
        deposit_nonce = 7
        refund_address = n0.getnewaddress()
        deposit_metadata = {
            "deposit_id": deposit_id,
            "amount": deposit_amount,
            "destination_commitment": destination_commitment,
            "nonce": deposit_nonce,
        }

        self.log.info("Building common sidechain history with one reclaimable deposit.")
        n0.sendvaliditysidechainregister(sidechain_id, config)
        n0.generatetoaddress(1, n0.getnewaddress())
        self.sync_blocks()

        n0.sendvaliditydeposit(
            sidechain_id,
            destination_commitment,
            {"address": refund_address},
            deposit_amount,
            deposit_nonce,
            deposit_id,
        )
        n0.generatetoaddress(1, n0.getnewaddress())
        self.sync_blocks()
        deposit_height = n0.getblockcount()

        target_height = deposit_height + config["deposit_reclaim_delay"]
        current_height = n0.getblockcount()
        if current_height < target_height:
            n0.generatetoaddress(target_height - current_height, n0.getnewaddress())
        self.sync_blocks()

        sidechain = get_sidechain(n0.getvaliditysidechaininfo(), sidechain_id)
        assert sidechain is not None
        assert_equal(sidechain["escrow_balance"], 100000000)
        assert_equal(sidechain["queue_state"]["pending_message_count"], 1)
        assert_equal(sidechain["queue_state"]["reclaimable_deposit_count"], 1)

        self.disconnect_nodes(0, 1)

        self.log.info("On node0 only, reclaim the stale deposit.")
        reclaim_result = n0.sendstaledepositreclaim(
            sidechain_id,
            deposit_metadata,
            {"address": refund_address},
        )
        n0.generatetoaddress(1, n0.getnewaddress())

        sidechain_n0 = get_sidechain(n0.getvaliditysidechaininfo(), sidechain_id)
        assert sidechain_n0 is not None
        assert_equal(reclaim_result["deposit_id"], deposit_id)
        assert_equal(sidechain_n0["escrow_balance"], 0)
        assert_equal(sidechain_n0["queue_state"]["head_index"], 1)
        assert_equal(sidechain_n0["queue_state"]["pending_message_count"], 0)
        assert_equal(sidechain_n0["queue_state"]["reclaimable_deposit_count"], 0)

        self.log.info("Mine a longer competing fork on node1 that omits the reclaim.")
        blocks_needed = (n0.getblockcount() - n1.getblockcount()) + 1
        n1.generatetoaddress(blocks_needed, n1.getnewaddress())

        self.connect_nodes(0, 1)
        self.sync_blocks()

        self.log.info("After reorg, the deposit should be reclaimable again on both nodes.")
        info_n0 = n0.getvaliditysidechaininfo()
        info_n1 = n1.getvaliditysidechaininfo()
        sidechain_n0 = get_sidechain(info_n0, sidechain_id)
        sidechain_n1 = get_sidechain(info_n1, sidechain_id)
        assert sidechain_n0 is not None
        assert sidechain_n1 is not None
        assert_equal(sidechain_n0["escrow_balance"], 100000000)
        assert_equal(sidechain_n1["escrow_balance"], 100000000)
        assert_equal(sidechain_n0["queue_state"]["head_index"], 0)
        assert_equal(sidechain_n1["queue_state"]["head_index"], 0)
        assert_equal(sidechain_n0["queue_state"]["pending_message_count"], 1)
        assert_equal(sidechain_n1["queue_state"]["pending_message_count"], 1)
        assert_equal(sidechain_n0["queue_state"]["reclaimable_deposit_count"], 1)
        assert_equal(sidechain_n1["queue_state"]["reclaimable_deposit_count"], 1)

        self.restart_node(0, extra_args=["-acceptnonstdtxn=1"])
        n0 = self.nodes[0]
        sidechain_after_restart = get_sidechain(n0.getvaliditysidechaininfo(), sidechain_id)
        assert sidechain_after_restart is not None
        assert_equal(sidechain_after_restart["escrow_balance"], 100000000)
        assert_equal(sidechain_after_restart["queue_state"]["pending_message_count"], 1)
        assert_equal(sidechain_after_restart["queue_state"]["reclaimable_deposit_count"], 1)

        self.log.info("Reclaiming the same deposit again after reorg should succeed.")
        reclaim_result = n0.sendstaledepositreclaim(
            sidechain_id,
            deposit_metadata,
            {"address": refund_address},
        )
        n0.generatetoaddress(1, n0.getnewaddress())

        sidechain_final = get_sidechain(n0.getvaliditysidechaininfo(), sidechain_id)
        assert sidechain_final is not None
        assert_equal(reclaim_result["deposit_id"], deposit_id)
        assert_equal(sidechain_final["escrow_balance"], 0)
        assert_equal(sidechain_final["queue_state"]["head_index"], 1)
        assert_equal(sidechain_final["queue_state"]["pending_message_count"], 0)
        assert_equal(sidechain_final["queue_state"]["reclaimable_deposit_count"], 0)


if __name__ == "__main__":
    ValiditySidechainReclaimReorg().main()
