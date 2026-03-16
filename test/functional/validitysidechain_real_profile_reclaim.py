#!/usr/bin/env python3
# Copyright (c) 2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from decimal import Decimal
import json
from pathlib import Path

from test_framework.messages import hash256, uint256_from_str
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


def build_register_config(supported, initial_state_root):
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
        "initial_state_root": initial_state_root,
        "initial_withdrawal_root": "00" * 32,
    }


def load_json(path):
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


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


def pad_field_hex(raw_value):
    return raw_value.lower().rjust(64, "0")


def amount_to_sats(amount):
    return int(amount * Decimal("100000000"))


def hash256_uint256(payload):
    return uint256_from_str(hash256(payload))


def compute_script_commitment(script_hex):
    return f"{hash256_uint256(bytes.fromhex(script_hex)):064x}"


class ValiditySidechainRealProfileReclaim(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.repo_root = Path(__file__).resolve().parents[2]
        self.artifact_root = self.repo_root / "artifacts"
        self.real_vector_path = self.artifact_root / "validitysidechain" / "groth16_bls12_381_poseidon_v1" / "valid" / "valid_proof.json"
        self.common_args = [
            "-acceptnonstdtxn=1",
            f"-validityartifactsdir={self.artifact_root}",
        ]
        self.extra_args = [self.common_args]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        if not self.real_vector_path.exists():
            self.skipTest(f"missing committed real-profile vector: {self.real_vector_path}")

    def run_test(self):
        node = self.nodes[0]
        real_valid_vector = load_json(self.real_vector_path)

        node.generatetoaddress(110, node.getnewaddress())

        supported = get_supported_profile(node, "groth16_bls12_381_poseidon_v1")
        sidechain_id = int(real_valid_vector["public_inputs"]["sidechain_id"])
        config = build_register_config(
            supported,
            initial_state_root=pad_field_hex(real_valid_vector["public_inputs"]["prior_state_root"]),
        )

        self.log.info("Registering the real profile and replaying the committed deposit fixture.")
        node.sendvaliditysidechainregister(sidechain_id, config)
        node.generatetoaddress(1, node.getnewaddress())

        setup_deposits = list(real_valid_vector.get("setup_deposits", []))
        assert_equal(len(setup_deposits), 1)
        deposit = setup_deposits[0]
        node.sendvaliditydeposit(
            sidechain_id,
            deposit["destination_commitment"],
            {"script": deposit["refund_script"]},
            Decimal(deposit["amount"]),
            deposit["nonce"],
            deposit["deposit_id"],
        )
        node.generatetoaddress(1, node.getnewaddress())
        deposit_height = node.getblockcount()

        sidechain = get_sidechain(node.getvaliditysidechaininfo(), sidechain_id)
        assert sidechain is not None
        assert_equal(sidechain["queue_state"]["root"], pad_field_hex(real_valid_vector["public_inputs"]["l1_message_root_before"]))
        assert_equal(sidechain["queue_state"]["pending_message_count"], 1)
        assert_equal(sidechain["queue_state"]["reclaimable_deposit_count"], 0)
        assert_equal(sidechain["escrow_balance"], amount_to_sats(Decimal(deposit["amount"])))

        self.log.info("Advancing to reclaim maturity for the committed real-profile deposit.")
        target_height = deposit_height + config["deposit_reclaim_delay"]
        current_height = node.getblockcount()
        if current_height < target_height:
            node.generatetoaddress(target_height - current_height, node.getnewaddress())

        matured_sidechain = get_sidechain(node.getvaliditysidechaininfo(), sidechain_id)
        assert matured_sidechain is not None
        assert_equal(matured_sidechain["queue_state"]["pending_message_count"], 1)
        assert_equal(matured_sidechain["queue_state"]["reclaimable_deposit_count"], 1)
        assert_equal(matured_sidechain["escrow_balance"], amount_to_sats(Decimal(deposit["amount"])))
        assert_equal(node.getrawmempool(), [])

        deposit_metadata = {
            "deposit_id": deposit["deposit_id"],
            "amount": Decimal(deposit["amount"]),
            "destination_commitment": deposit["destination_commitment"],
            "nonce": deposit["nonce"],
        }

        self.log.info("Rejecting stale reclaim because the experimental real-profile tombstone root still falls outside the scalar field.")
        assert_raises_rpc_error(
            -8,
            "experimental real profile reclaim queue root does not fit BLS12-381 scalar field",
            node.sendstaledepositreclaim,
            sidechain_id,
            deposit_metadata,
            {"script": deposit["refund_script"]},
        )
        assert_equal(node.getrawmempool(), [])

        failed_reclaim_sidechain = get_sidechain(node.getvaliditysidechaininfo(), sidechain_id)
        assert failed_reclaim_sidechain is not None
        assert_equal(failed_reclaim_sidechain["queue_state"]["head_index"], 0)
        assert_equal(failed_reclaim_sidechain["queue_state"]["pending_message_count"], 1)
        assert_equal(failed_reclaim_sidechain["queue_state"]["reclaimable_deposit_count"], 1)
        assert_equal(failed_reclaim_sidechain["escrow_balance"], amount_to_sats(Decimal(deposit["amount"])))

        self.log.info("Persisting the failed-reclaim state across restart.")
        self.restart_node(0, extra_args=self.common_args)
        node = self.nodes[0]

        restarted_sidechain = get_sidechain(node.getvaliditysidechaininfo(), sidechain_id)
        assert restarted_sidechain is not None
        assert_equal(restarted_sidechain["queue_state"]["head_index"], 0)
        assert_equal(restarted_sidechain["queue_state"]["pending_message_count"], 1)
        assert_equal(restarted_sidechain["queue_state"]["reclaimable_deposit_count"], 1)
        assert_equal(restarted_sidechain["escrow_balance"], amount_to_sats(Decimal(deposit["amount"])))
        assert_raises_rpc_error(
            -8,
            "experimental real profile reclaim queue root does not fit BLS12-381 scalar field",
            node.sendstaledepositreclaim,
            sidechain_id,
            deposit_metadata,
            {"script": deposit["refund_script"]},
        )
        assert_equal(node.getrawmempool(), [])

        self.log.info("A matured-but-unreclaimable committed deposit must still be consumable by the committed real-profile batch.")
        real_public_inputs = {
            "batch_number": int(real_valid_vector["public_inputs"]["batch_number"]),
            "prior_state_root": pad_field_hex(real_valid_vector["public_inputs"]["prior_state_root"]),
            "new_state_root": pad_field_hex(real_valid_vector["public_inputs"]["new_state_root"]),
            "l1_message_root_before": pad_field_hex(real_valid_vector["public_inputs"]["l1_message_root_before"]),
            "l1_message_root_after": pad_field_hex(real_valid_vector["public_inputs"]["l1_message_root_after"]),
            "consumed_queue_messages": int(real_valid_vector["public_inputs"]["consumed_queue_messages"]),
            "queue_prefix_commitment": pad_field_hex(real_valid_vector["public_inputs"]["queue_prefix_commitment"]),
            "withdrawal_root": pad_field_hex(real_valid_vector["public_inputs"]["withdrawal_root"]),
            "data_root": pad_field_hex(real_valid_vector["public_inputs"]["data_root"]),
            "data_size": int(real_valid_vector["public_inputs"]["data_size"]),
        }
        real_data_chunks = list(real_valid_vector.get("data_chunks_hex", []))
        batch_res = node.sendvaliditybatch(
            sidechain_id,
            real_public_inputs,
            real_valid_vector["proof_bytes_hex"],
            real_data_chunks,
        )
        assert "txid" in batch_res
        node.generatetoaddress(1, node.getnewaddress())

        sidechain_after_batch = get_sidechain(node.getvaliditysidechaininfo(), sidechain_id)
        assert sidechain_after_batch is not None
        assert_equal(sidechain_after_batch["latest_batch_number"], real_public_inputs["batch_number"])
        assert_equal(sidechain_after_batch["queue_state"]["pending_message_count"], 0)
        assert_equal(sidechain_after_batch["queue_state"]["reclaimable_deposit_count"], 0)
        assert_equal(sidechain_after_batch["current_state_root"], real_public_inputs["new_state_root"])

        withdrawal_rpc_entries = [
            {
                "withdrawal_id": leaf["withdrawal_id"],
                "script": leaf["script"],
                "amount": Decimal(leaf["amount"]),
            }
            for leaf in real_valid_vector.get("withdrawal_leaves", [])
        ]
        assert_equal(len(withdrawal_rpc_entries), 1)

        self.log.info("Verified withdrawal execution should still succeed after the failed reclaim attempts.")
        verified_withdrawal_res = node.sendverifiedwithdrawals(
            sidechain_id,
            real_public_inputs["batch_number"],
            withdrawal_rpc_entries,
        )
        assert "txid" in verified_withdrawal_res
        node.generatetoaddress(1, node.getnewaddress())

        final_sidechain = get_sidechain(node.getvaliditysidechaininfo(), sidechain_id)
        assert final_sidechain is not None
        assert_equal(final_sidechain["latest_batch_number"], real_public_inputs["batch_number"])
        assert_equal(final_sidechain["executed_withdrawal_count"], 1)
        assert_equal(final_sidechain["queue_state"]["pending_message_count"], 0)
        assert_equal(final_sidechain["queue_state"]["reclaimable_deposit_count"], 0)
        assert_equal(
            final_sidechain["escrow_balance"],
            amount_to_sats(Decimal(deposit["amount"]) - withdrawal_rpc_entries[0]["amount"]),
        )
        assert_equal(final_sidechain["current_withdrawal_root"], real_public_inputs["withdrawal_root"])
        assert_equal(
            compute_script_commitment(withdrawal_rpc_entries[0]["script"]),
            real_valid_vector["withdrawal_leaves"][0]["destination_commitment"],
        )


if __name__ == "__main__":
    ValiditySidechainRealProfileReclaim().main()
