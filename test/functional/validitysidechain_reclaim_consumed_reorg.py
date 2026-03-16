#!/usr/bin/env python3
# Copyright (c) 2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from decimal import Decimal
import struct

from test_framework.messages import hash256, ser_uint256, uint256_from_str
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


def get_sidechain(info, sidechain_id):
    for sidechain in info["sidechains"]:
        if sidechain["id"] == sidechain_id:
            return sidechain
    return None


def get_supported_profile(node, profile_name):
    info = node.getvaliditysidechaininfo()
    for supported in info["supported_proof_configs"]:
        if supported["profile_name"] == profile_name:
            return supported
    raise AssertionError(f"missing supported proof profile {profile_name}")


def hash256_uint256(payload):
    return uint256_from_str(hash256(payload))


def compute_queue_consume_root(sidechain_id, prior_root_hex, queue_index, message_kind, message_id_hex, message_hash_hex):
    payload = bytearray(b"VSCQC\x01")
    payload.append(sidechain_id)
    payload.extend(ser_uint256(int(prior_root_hex, 16)))
    payload.extend(struct.pack("<Q", queue_index))
    payload.append(message_kind)
    payload.extend(ser_uint256(int(message_id_hex, 16)))
    payload.extend(ser_uint256(int(message_hash_hex, 16)))
    return f"{hash256_uint256(bytes(payload)):064x}"


def compute_consumed_queue_root(sidechain_id, prior_root_hex, entries):
    root = prior_root_hex
    for entry in entries:
        root = compute_queue_consume_root(
            sidechain_id,
            root,
            entry["queue_index"],
            entry["message_kind"],
            entry["message_id"],
            entry["message_hash"],
        )
    return root


def compute_queue_prefix_commitment_step(sidechain_id, prior_commitment_hex, queue_index, message_kind, message_id_hex, message_hash_hex):
    payload = bytearray(b"VSCQP\x01")
    payload.append(sidechain_id)
    payload.extend(ser_uint256(int(prior_commitment_hex, 16)))
    payload.extend(struct.pack("<Q", queue_index))
    payload.append(message_kind)
    payload.extend(ser_uint256(int(message_id_hex, 16)))
    payload.extend(ser_uint256(int(message_hash_hex, 16)))
    return f"{hash256_uint256(bytes(payload)):064x}"


def compute_queue_prefix_commitment(sidechain_id, entries):
    commitment = "00" * 32
    for entry in entries:
        commitment = compute_queue_prefix_commitment_step(
            sidechain_id,
            commitment,
            entry["queue_index"],
            entry["message_kind"],
            entry["message_id"],
            entry["message_hash"],
        )
    return commitment


class ValiditySidechainReclaimConsumedReorg(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.common_args = ["-acceptnonstdtxn=1", "-persistmempool=0"]
        self.extra_args = [self.common_args, self.common_args]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        n0 = self.nodes[0]
        n1 = self.nodes[1]

        n0.generatetoaddress(110, n0.getnewaddress())
        self.sync_blocks()
        self.log.info("Funding node1 so it can build winning-fork transactions after the split.")
        n0.sendtoaddress(n1.getnewaddress(), Decimal("5.0"))
        n0.generatetoaddress(1, n0.getnewaddress())
        self.sync_blocks()

        sidechain_id = 47
        supported = get_supported_profile(n0, "scaffold_onchain_da_v1")
        config = build_register_config(supported)
        deposit_destination = "33" * 32
        deposit_amount = Decimal("1.0")
        deposit_nonce = 7
        deposit_id = "44" * 32
        refund_destination = {"address": n0.getnewaddress()}

        self.log.info("Building common sidechain history with a single pending deposit on both nodes.")
        n0.sendvaliditysidechainregister(sidechain_id, config)
        n0.generatetoaddress(1, n0.getnewaddress())
        self.sync_blocks()

        deposit_result = n0.sendvaliditydeposit(
            sidechain_id,
            deposit_destination,
            refund_destination,
            deposit_amount,
            deposit_nonce,
            deposit_id,
        )
        n0.generatetoaddress(1, n0.getnewaddress())
        self.sync_blocks()
        deposit_height = n0.getblockcount()

        mature_height = deposit_height + config["deposit_reclaim_delay"]
        current_height = n0.getblockcount()
        if current_height < mature_height:
            n0.generatetoaddress(mature_height - current_height, n0.getnewaddress())
        self.sync_blocks()

        shared_sidechain = get_sidechain(n0.getvaliditysidechaininfo(), sidechain_id)
        assert shared_sidechain is not None
        assert_equal(shared_sidechain["queue_state"]["head_index"], 0)
        assert_equal(shared_sidechain["queue_state"]["pending_message_count"], 1)
        assert_equal(shared_sidechain["queue_state"]["reclaimable_deposit_count"], 1)

        deposit_metadata = {
            "deposit_id": deposit_id,
            "amount": deposit_amount,
            "destination_commitment": deposit_destination,
            "nonce": deposit_nonce,
        }

        consumed_entries = [{
            "queue_index": 0,
            "message_kind": 1,
            "message_id": deposit_id,
            "message_hash": deposit_result["deposit_message_hash"],
        }]

        self.disconnect_nodes(0, 1)

        self.log.info("On node0 only, mine the reclaim for the matured deposit.")
        reclaim_result = n0.sendstaledepositreclaim(sidechain_id, deposit_metadata, refund_destination)
        reclaim_txid = reclaim_result["txid"]
        n0.generatetoaddress(1, n0.getnewaddress())

        self.log.info("On node1 only, mine a winning batch that consumes the same deposit instead of reclaiming it.")
        sidechain_n1 = get_sidechain(n1.getvaliditysidechaininfo(), sidechain_id)
        assert sidechain_n1 is not None
        public_inputs = {
            "batch_number": 1,
            "prior_state_root": sidechain_n1["current_state_root"],
            "new_state_root": sidechain_n1["current_state_root"],
            "l1_message_root_before": sidechain_n1["queue_state"]["root"],
            "l1_message_root_after": compute_consumed_queue_root(
                sidechain_id,
                sidechain_n1["queue_state"]["root"],
                consumed_entries,
            ),
            "consumed_queue_messages": 1,
            "queue_prefix_commitment": compute_queue_prefix_commitment(sidechain_id, consumed_entries),
            "withdrawal_root": sidechain_n1["current_withdrawal_root"],
            "data_root": sidechain_n1["current_data_root"],
            "data_size": 0,
        }
        batch_result = n1.sendvaliditybatch(sidechain_id, public_inputs)
        batch_txid = batch_result["txid"]
        n1.generatetoaddress(1, n1.getnewaddress())

        blocks_needed = (n0.getblockcount() - n1.getblockcount()) + 1
        if blocks_needed > 0:
            n1.generatetoaddress(blocks_needed, n1.getnewaddress())

        self.connect_nodes(0, 1)
        self.sync_blocks()

        self.log.info("After reorg, the consumed deposit state should win and the orphaned reclaim must not return to mempool.")
        info_n0_after = n0.getvaliditysidechaininfo()
        info_n1_after = n1.getvaliditysidechaininfo()
        sidechain_n0_after = get_sidechain(info_n0_after, sidechain_id)
        sidechain_n1_after = get_sidechain(info_n1_after, sidechain_id)
        assert sidechain_n0_after is not None
        assert sidechain_n1_after is not None
        assert reclaim_txid not in n0.getrawmempool()
        assert batch_txid not in n0.getrawmempool()
        assert_equal(sidechain_n0_after["latest_batch_number"], 1)
        assert_equal(sidechain_n1_after["latest_batch_number"], 1)
        assert_equal(len(sidechain_n0_after["accepted_batches"]), 1)
        assert_equal(len(sidechain_n1_after["accepted_batches"]), 1)
        assert_equal(sidechain_n0_after["accepted_batches"][0]["consumed_queue_messages"], 1)
        assert_equal(sidechain_n1_after["accepted_batches"][0]["consumed_queue_messages"], 1)
        assert_equal(sidechain_n0_after["accepted_batches"][0]["queue_prefix_commitment"], public_inputs["queue_prefix_commitment"])
        assert_equal(sidechain_n1_after["accepted_batches"][0]["queue_prefix_commitment"], public_inputs["queue_prefix_commitment"])
        assert_equal(sidechain_n0_after["queue_state"]["head_index"], 1)
        assert_equal(sidechain_n1_after["queue_state"]["head_index"], 1)
        assert_equal(sidechain_n0_after["queue_state"]["pending_message_count"], 0)
        assert_equal(sidechain_n1_after["queue_state"]["pending_message_count"], 0)
        assert_equal(sidechain_n0_after["queue_state"]["reclaimable_deposit_count"], 0)
        assert_equal(sidechain_n1_after["queue_state"]["reclaimable_deposit_count"], 0)
        assert_equal(sidechain_n0_after["escrow_balance"], 100000000)
        assert_equal(sidechain_n1_after["escrow_balance"], 100000000)

        assert_raises_rpc_error(
            -26,
            "deposit id is not pending",
            n0.sendstaledepositreclaim,
            sidechain_id,
            deposit_metadata,
            refund_destination,
        )

        self.restart_node(0, extra_args=self.common_args)
        n0 = self.nodes[0]
        info_after_restart = n0.getvaliditysidechaininfo()
        sidechain_after_restart = get_sidechain(info_after_restart, sidechain_id)
        assert sidechain_after_restart is not None
        assert reclaim_txid not in n0.getrawmempool()
        assert_equal(sidechain_after_restart["latest_batch_number"], 1)
        assert_equal(len(sidechain_after_restart["accepted_batches"]), 1)
        assert_equal(sidechain_after_restart["queue_state"]["head_index"], 1)
        assert_equal(sidechain_after_restart["queue_state"]["pending_message_count"], 0)
        assert_equal(sidechain_after_restart["queue_state"]["reclaimable_deposit_count"], 0)

        assert_raises_rpc_error(
            -26,
            "deposit id is not pending",
            n0.sendstaledepositreclaim,
            sidechain_id,
            deposit_metadata,
            refund_destination,
        )


if __name__ == "__main__":
    ValiditySidechainReclaimConsumedReorg().main()
