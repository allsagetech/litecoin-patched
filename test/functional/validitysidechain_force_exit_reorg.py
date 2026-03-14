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


class ValiditySidechainForceExitReorg(BitcoinTestFramework):
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

        sidechain_id = 33
        supported = n0.getvaliditysidechaininfo()["supported_proof_configs"][0]
        config = build_register_config(supported)

        account_id = "55" * 32
        exit_asset_id = "66" * 32
        max_exit_amount = Decimal("0.50")
        destination = {"address": n0.getnewaddress()}
        nonce = 9

        self.log.info("Building common validity-sidechain history on both nodes.")
        n0.sendvaliditysidechainregister(sidechain_id, config)
        n0.generatetoaddress(1, n0.getnewaddress())
        self.sync_blocks()

        sidechain = get_sidechain(n0.getvaliditysidechaininfo(), sidechain_id)
        assert sidechain is not None
        initial_queue_root = sidechain["queue_state"]["root"]

        self.disconnect_nodes(0, 1)

        self.log.info("On node0 only, post a force-exit request and let it mature.")
        request_result = n0.sendforceexitrequest(
            sidechain_id,
            account_id,
            exit_asset_id,
            max_exit_amount,
            destination,
            nonce,
        )
        request_txid = request_result["txid"]
        n0.generatetoaddress(1, n0.getnewaddress())
        request_hash = request_result["request_hash"]
        request_height = n0.getblockcount()

        target_height = request_height + config["force_inclusion_delay"]
        current_height = n0.getblockcount()
        if current_height < target_height:
            n0.generatetoaddress(target_height - current_height, n0.getnewaddress())

        sidechain_n0 = get_sidechain(n0.getvaliditysidechaininfo(), sidechain_id)
        assert sidechain_n0 is not None
        assert_equal(sidechain_n0["queue_state"]["pending_message_count"], 1)
        assert_equal(sidechain_n0["queue_state"]["pending_force_exit_count"], 1)
        assert_equal(sidechain_n0["queue_state"]["matured_force_exit_count"], 1)

        self.log.info("Mine a longer competing fork on node1 that omits the force-exit request.")
        blocks_needed = (n0.getblockcount() - n1.getblockcount()) + 1
        n1.generatetoaddress(blocks_needed, n1.getnewaddress())

        self.connect_nodes(0, 1)
        self.sync_blocks()

        self.log.info("After reorg, the pending/matured request state must be gone on both nodes.")
        sidechain_n0 = get_sidechain(n0.getvaliditysidechaininfo(), sidechain_id)
        sidechain_n1 = get_sidechain(n1.getvaliditysidechaininfo(), sidechain_id)
        assert sidechain_n0 is not None
        assert sidechain_n1 is not None
        assert_equal(sidechain_n0["queue_state"]["root"], initial_queue_root)
        assert_equal(sidechain_n1["queue_state"]["root"], initial_queue_root)
        assert_equal(sidechain_n0["queue_state"]["head_index"], 0)
        assert_equal(sidechain_n1["queue_state"]["head_index"], 0)
        assert_equal(sidechain_n0["queue_state"]["pending_message_count"], 0)
        assert_equal(sidechain_n1["queue_state"]["pending_message_count"], 0)
        assert_equal(sidechain_n0["queue_state"]["pending_force_exit_count"], 0)
        assert_equal(sidechain_n1["queue_state"]["pending_force_exit_count"], 0)
        assert_equal(sidechain_n0["queue_state"]["matured_force_exit_count"], 0)
        assert_equal(sidechain_n1["queue_state"]["matured_force_exit_count"], 0)

        self.restart_node(0, extra_args=["-acceptnonstdtxn=1", "-persistmempool=0"])
        n0 = self.nodes[0]

        sidechain_after_restart = get_sidechain(n0.getvaliditysidechaininfo(), sidechain_id)
        assert sidechain_after_restart is not None
        assert_equal(sidechain_after_restart["queue_state"]["root"], initial_queue_root)
        assert_equal(sidechain_after_restart["queue_state"]["pending_message_count"], 0)
        assert_equal(sidechain_after_restart["queue_state"]["pending_force_exit_count"], 0)
        assert_equal(sidechain_after_restart["queue_state"]["matured_force_exit_count"], 0)

        self.log.info("After restart, the same force-exit request should either be resurrected into mempool or be resubmittable.")
        mempool = n0.getrawmempool()
        if request_txid in mempool:
            self.log.info("The original force-exit request was restored to mempool after the reorg.")
        else:
            repeat_result = n0.sendforceexitrequest(
                sidechain_id,
                account_id,
                exit_asset_id,
                max_exit_amount,
                destination,
                nonce,
            )
            assert_equal(repeat_result["request_hash"], request_hash)
            request_txid = repeat_result["txid"]

        assert request_txid in n0.getrawmempool()
        n0.generatetoaddress(1, n0.getnewaddress())

        sidechain_final = get_sidechain(n0.getvaliditysidechaininfo(), sidechain_id)
        assert sidechain_final is not None
        assert_equal(sidechain_final["queue_state"]["pending_message_count"], 1)
        assert_equal(sidechain_final["queue_state"]["pending_force_exit_count"], 1)

        request_height = n0.getblockcount()
        target_height = request_height + config["force_inclusion_delay"]
        current_height = n0.getblockcount()
        if current_height < target_height:
            n0.generatetoaddress(target_height - current_height, n0.getnewaddress())

        sidechain_final = get_sidechain(n0.getvaliditysidechaininfo(), sidechain_id)
        assert sidechain_final is not None
        assert_equal(sidechain_final["queue_state"]["matured_force_exit_count"], 1)


if __name__ == "__main__":
    ValiditySidechainForceExitReorg().main()
