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


class ValiditySidechainRegistrationReorg(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [
            ["-acceptnonstdtxn=1", "-persistmempool=0"],
            ["-acceptnonstdtxn=1", "-persistmempool=0"],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        n0 = self.nodes[0]
        n1 = self.nodes[1]

        n0.generatetoaddress(110, n0.getnewaddress())
        self.sync_blocks()

        sidechain_id = 35
        supported = n0.getvaliditysidechaininfo()["supported_proof_configs"][0]
        config = build_register_config(supported)
        deposit_id = "44" * 32
        destination_commitment = "33" * 32
        refund_address = n0.getnewaddress()

        self.log.info("Split the network and create sidechain state only on node0.")
        self.disconnect_nodes(0, 1)

        n0.sendvaliditysidechainregister(sidechain_id, config)
        n0.generatetoaddress(1, n0.getnewaddress())
        deposit_result = n0.sendvaliditydeposit(
            sidechain_id,
            destination_commitment,
            {"address": refund_address},
            Decimal("1.0"),
            7,
            deposit_id,
        )
        n0.generatetoaddress(1, n0.getnewaddress())

        sidechain_n0 = get_sidechain(n0.getvaliditysidechaininfo(), sidechain_id)
        assert sidechain_n0 is not None
        assert_equal(sidechain_n0["escrow_balance"], 100000000)
        assert_equal(sidechain_n0["queue_state"]["pending_message_count"], 1)

        self.log.info("Mine a longer competing fork on node1 that omits the sidechain entirely.")
        blocks_needed = (n0.getblockcount() - n1.getblockcount()) + 1
        n1.generatetoaddress(blocks_needed, n1.getnewaddress())

        self.connect_nodes(0, 1)
        self.sync_blocks()

        self.log.info("After reorg, the orphaned sidechain registration and deposit must disappear.")
        assert_equal(n0.getvaliditysidechaininfo()["sidechains"], [])
        assert_equal(n1.getvaliditysidechaininfo()["sidechains"], [])

        self.restart_node(0, extra_args=["-acceptnonstdtxn=1", "-persistmempool=0"])
        n0 = self.nodes[0]
        assert_equal(n0.getvaliditysidechaininfo()["sidechains"], [])

        self.log.info("Re-registering the same sidechain id and deposit after reorg should succeed.")
        n0.sendvaliditysidechainregister(sidechain_id, config)
        n0.generatetoaddress(1, n0.getnewaddress())
        repeat_deposit_result = n0.sendvaliditydeposit(
            sidechain_id,
            destination_commitment,
            {"address": refund_address},
            Decimal("1.0"),
            7,
            deposit_id,
        )
        n0.generatetoaddress(1, n0.getnewaddress())

        sidechain_after = get_sidechain(n0.getvaliditysidechaininfo(), sidechain_id)
        assert sidechain_after is not None
        assert_equal(sidechain_after["escrow_balance"], 100000000)
        assert_equal(sidechain_after["queue_state"]["pending_message_count"], 1)
        assert_equal(repeat_deposit_result["deposit_id"], deposit_result["deposit_id"])


if __name__ == "__main__":
    ValiditySidechainRegistrationReorg().main()
