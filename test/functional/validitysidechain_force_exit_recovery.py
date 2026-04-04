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


def get_sidechain(info, sidechain_id):
    for sidechain in info["sidechains"]:
        if sidechain["id"] == sidechain_id:
            return sidechain
    return None


class ValiditySidechainForceExitRecovery(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.generatetoaddress(101, node.getnewaddress())

        sidechain_id = 29
        supported = node.getvaliditysidechaininfo()["supported_proof_configs"][0]
        config = build_register_config(supported)

        self.log.info("Registering a validity sidechain and posting a force-exit request.")
        node.sendvaliditysidechainregister(sidechain_id, config)
        node.generatetoaddress(1, node.getnewaddress())

        request_result = node.sendforceexitrequest(
            sidechain_id,
            "55" * 32,
            "66" * 32,
            Decimal("0.50"),
            {"address": node.getnewaddress()},
            9,
        )
        node.generatetoaddress(1, node.getnewaddress())
        request_hash = request_result["request_hash"]
        request_height = node.getblockcount()

        self.log.info("Advancing to the force-inclusion deadline.")
        target_height = request_height + config["force_inclusion_delay"]
        current_height = node.getblockcount()
        if current_height < target_height:
            node.generatetoaddress(target_height - current_height, node.getnewaddress())

        sidechain = get_sidechain(node.getvaliditysidechaininfo(), sidechain_id)
        assert sidechain is not None
        assert_equal(sidechain["queue_state"]["pending_force_exit_count"], 1)
        assert_equal(sidechain["queue_state"]["matured_force_exit_count"], 1)
        assert_equal(sidechain["queue_state"]["head_index"], 0)

        self.log.info("Rejecting a no-op batch that refuses to consume the matured force-exit request.")
        rejected_public_inputs = {
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
        assert_raises_rpc_error(
            -8,
            "batch must consume all matured force-exit requests in reachable queue prefix",
            node.sendvaliditybatch,
            sidechain_id,
            rejected_public_inputs,
        )

        self.log.info("Submitting a batch that consumes the reachable force-exit queue prefix.")
        accepted_public_inputs = dict(rejected_public_inputs)
        accepted_public_inputs["l1_message_root_after"] = compute_queue_consume_root(
            sidechain_id,
            sidechain["queue_state"]["root"],
            sidechain["queue_state"]["head_index"],
            2,
            request_hash,
            request_hash,
        )
        accepted_public_inputs["consumed_queue_messages"] = 1
        batch_result = node.sendvaliditybatch(sidechain_id, accepted_public_inputs)
        node.generatetoaddress(1, node.getnewaddress())

        sidechain = get_sidechain(node.getvaliditysidechaininfo(), sidechain_id)
        assert sidechain is not None
        assert_equal(sidechain["latest_batch_number"], 1)
        assert_equal(len(sidechain["accepted_batches"]), 1)
        assert_equal(sidechain["accepted_batches"][0]["batch_number"], 1)
        assert_equal(sidechain["accepted_batches"][0]["consumed_queue_messages"], 1)
        assert_equal(sidechain["accepted_batches"][0]["published_in_txid"], batch_result["txid"])
        assert_equal(sidechain["queue_state"]["head_index"], 1)
        assert_equal(sidechain["queue_state"]["pending_message_count"], 0)
        assert_equal(sidechain["queue_state"]["pending_force_exit_count"], 0)
        assert_equal(sidechain["queue_state"]["matured_force_exit_count"], 0)


if __name__ == "__main__":
    ValiditySidechainForceExitRecovery().main()
