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


class ValiditySidechainRealProfileReclaimReorg(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.repo_root = Path(__file__).resolve().parents[2]
        self.artifact_root = self.repo_root / "artifacts"
        self.real_vector_path = self.artifact_root / "validitysidechain" / "groth16_bls12_381_poseidon_v1" / "valid" / "valid_proof.json"
        self.common_args = [
            "-acceptnonstdtxn=1",
            f"-validityartifactsdir={self.artifact_root}",
        ]
        self.extra_args = [self.common_args, self.common_args]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        if not self.real_vector_path.exists():
            self.skipTest(f"missing committed real-profile vector: {self.real_vector_path}")

    def run_test(self):
        n0 = self.nodes[0]
        n1 = self.nodes[1]
        real_valid_vector = load_json(self.real_vector_path)

        n0.generatetoaddress(110, n0.getnewaddress())
        self.sync_blocks()

        supported = get_supported_profile(n0, "groth16_bls12_381_poseidon_v1")
        sidechain_id = int(real_valid_vector["public_inputs"]["sidechain_id"])
        config = build_register_config(
            supported,
            initial_state_root=pad_field_hex(real_valid_vector["public_inputs"]["prior_state_root"]),
        )

        self.log.info("Building shared matured real-profile deposit history.")
        n0.sendvaliditysidechainregister(sidechain_id, config)
        n0.generatetoaddress(1, n0.getnewaddress())
        self.sync_blocks()

        setup_deposits = list(real_valid_vector.get("setup_deposits", []))
        assert_equal(len(setup_deposits), 1)
        deposit = setup_deposits[0]
        n0.sendvaliditydeposit(
            sidechain_id,
            deposit["destination_commitment"],
            {"script": deposit["refund_script"]},
            Decimal(deposit["amount"]),
            deposit["nonce"],
            deposit["deposit_id"],
        )
        n0.generatetoaddress(1, n0.getnewaddress())
        self.sync_blocks()
        deposit_height = n0.getblockcount()

        target_height = deposit_height + config["deposit_reclaim_delay"]
        current_height = n0.getblockcount()
        if current_height < target_height:
            n0.generatetoaddress(target_height - current_height, n0.getnewaddress())
        self.sync_blocks()

        shared_info = n0.getvaliditysidechaininfo()
        shared_sidechain = get_sidechain(shared_info, sidechain_id)
        assert shared_sidechain is not None
        assert_equal(shared_sidechain["current_state_root"], config["initial_state_root"])
        assert_equal(shared_sidechain["current_withdrawal_root"], "00" * 32)
        assert_equal(shared_sidechain["queue_state"]["root"], pad_field_hex(real_valid_vector["public_inputs"]["l1_message_root_before"]))
        assert_equal(shared_sidechain["queue_state"]["head_index"], 0)
        assert_equal(shared_sidechain["queue_state"]["pending_message_count"], 1)
        assert_equal(shared_sidechain["queue_state"]["reclaimable_deposit_count"], 1)
        assert_equal(shared_sidechain["escrow_balance"], amount_to_sats(Decimal(deposit["amount"])))

        deposit_metadata = {
            "deposit_id": deposit["deposit_id"],
            "amount": Decimal(deposit["amount"]),
            "destination_commitment": deposit["destination_commitment"],
            "nonce": deposit["nonce"],
        }
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
        withdrawal_rpc_entries = [
            {
                "withdrawal_id": leaf["withdrawal_id"],
                "script": leaf["script"],
                "amount": Decimal(leaf["amount"]),
            }
            for leaf in real_valid_vector.get("withdrawal_leaves", [])
        ]
        assert_equal(len(withdrawal_rpc_entries), 1)

        self.disconnect_nodes(0, 1)

        self.log.info("On node0 only, reject reclaim and then consume the matured deposit with the committed batch.")
        assert_raises_rpc_error(
            -26,
            "experimental real profile reclaim queue root does not fit BLS12-381 scalar field",
            n0.sendstaledepositreclaim,
            sidechain_id,
            deposit_metadata,
            {"script": deposit["refund_script"]},
        )
        assert_equal(n0.getrawmempool(), [])

        batch_res = n0.sendvaliditybatch(
            sidechain_id,
            real_public_inputs,
            real_valid_vector["proof_bytes_hex"],
            real_data_chunks,
        )
        batch_txid = batch_res["txid"]
        n0.generatetoaddress(1, n0.getnewaddress())

        verified_withdrawal_res = n0.sendverifiedwithdrawals(
            sidechain_id,
            real_public_inputs["batch_number"],
            withdrawal_rpc_entries,
        )
        verified_withdrawal_txid = verified_withdrawal_res["txid"]
        n0.generatetoaddress(1, n0.getnewaddress())

        info_n0 = n0.getvaliditysidechaininfo()
        sidechain_n0 = get_sidechain(info_n0, sidechain_id)
        assert sidechain_n0 is not None
        recompute_fallbacks = int(info_n0["state_cache"]["recompute_fallbacks"])
        assert_equal(sidechain_n0["latest_batch_number"], real_public_inputs["batch_number"])
        assert_equal(len(sidechain_n0["accepted_batches"]), 1)
        assert_equal(sidechain_n0["executed_withdrawal_count"], 1)
        assert_equal(sidechain_n0["current_state_root"], real_public_inputs["new_state_root"])
        assert_equal(sidechain_n0["current_withdrawal_root"], real_public_inputs["withdrawal_root"])
        assert_equal(sidechain_n0["queue_state"]["root"], real_public_inputs["l1_message_root_after"])
        assert_equal(sidechain_n0["queue_state"]["head_index"], real_public_inputs["consumed_queue_messages"])
        assert_equal(sidechain_n0["queue_state"]["pending_message_count"], 0)
        assert_equal(sidechain_n0["queue_state"]["reclaimable_deposit_count"], 0)
        assert_equal(
            sidechain_n0["escrow_balance"],
            amount_to_sats(Decimal(deposit["amount"]) - withdrawal_rpc_entries[0]["amount"]),
        )

        self.log.info("Mine a longer competing fork on node1 that leaves the matured deposit pending.")
        blocks_needed = (n0.getblockcount() - n1.getblockcount()) + 1
        n1.generatetoaddress(blocks_needed, n1.getnewaddress())

        self.connect_nodes(0, 1)
        self.sync_blocks()

        self.log.info("After reorg, node0 must return to the matured reclaimable state with no accepted batch state left behind.")
        info_n0_after = n0.getvaliditysidechaininfo()
        info_n1_after = n1.getvaliditysidechaininfo()
        sidechain_n0_after = get_sidechain(info_n0_after, sidechain_id)
        sidechain_n1_after = get_sidechain(info_n1_after, sidechain_id)
        assert sidechain_n0_after is not None
        assert sidechain_n1_after is not None
        assert_equal(int(info_n0_after["state_cache"]["recompute_fallbacks"]), recompute_fallbacks)
        assert_equal(sidechain_n0_after["latest_batch_number"], 0)
        assert_equal(sidechain_n1_after["latest_batch_number"], 0)
        assert_equal(sidechain_n0_after["accepted_batches"], [])
        assert_equal(sidechain_n1_after["accepted_batches"], [])
        assert_equal(sidechain_n0_after["executed_withdrawal_count"], 0)
        assert_equal(sidechain_n1_after["executed_withdrawal_count"], 0)
        assert_equal(sidechain_n0_after["current_state_root"], real_public_inputs["prior_state_root"])
        assert_equal(sidechain_n1_after["current_state_root"], real_public_inputs["prior_state_root"])
        assert_equal(sidechain_n0_after["current_withdrawal_root"], "00" * 32)
        assert_equal(sidechain_n1_after["current_withdrawal_root"], "00" * 32)
        assert_equal(sidechain_n0_after["queue_state"]["root"], real_public_inputs["l1_message_root_before"])
        assert_equal(sidechain_n1_after["queue_state"]["root"], real_public_inputs["l1_message_root_before"])
        assert_equal(sidechain_n0_after["queue_state"]["head_index"], 0)
        assert_equal(sidechain_n1_after["queue_state"]["head_index"], 0)
        assert_equal(sidechain_n0_after["queue_state"]["pending_message_count"], 1)
        assert_equal(sidechain_n1_after["queue_state"]["pending_message_count"], 1)
        assert_equal(sidechain_n0_after["queue_state"]["reclaimable_deposit_count"], 1)
        assert_equal(sidechain_n1_after["queue_state"]["reclaimable_deposit_count"], 1)
        assert_equal(
            sidechain_n0_after["escrow_balance"],
            amount_to_sats(Decimal(deposit["amount"])),
        )
        assert_equal(
            sidechain_n1_after["escrow_balance"],
            amount_to_sats(Decimal(deposit["amount"])),
        )

        self.restart_node(0, extra_args=self.common_args)
        n0 = self.nodes[0]
        info_after_restart = n0.getvaliditysidechaininfo()
        sidechain_after_restart = get_sidechain(info_after_restart, sidechain_id)
        assert sidechain_after_restart is not None
        assert_equal(int(info_after_restart["state_cache"]["recompute_fallbacks"]), recompute_fallbacks)
        assert_equal(sidechain_after_restart["latest_batch_number"], 0)
        assert_equal(sidechain_after_restart["accepted_batches"], [])
        assert_equal(sidechain_after_restart["executed_withdrawal_count"], 0)
        assert_equal(sidechain_after_restart["current_state_root"], real_public_inputs["prior_state_root"])
        assert_equal(sidechain_after_restart["current_withdrawal_root"], "00" * 32)
        assert_equal(sidechain_after_restart["queue_state"]["root"], real_public_inputs["l1_message_root_before"])
        assert_equal(sidechain_after_restart["queue_state"]["head_index"], 0)
        assert_equal(sidechain_after_restart["queue_state"]["pending_message_count"], 1)
        assert_equal(sidechain_after_restart["queue_state"]["reclaimable_deposit_count"], 1)
        assert_equal(
            sidechain_after_restart["escrow_balance"],
            amount_to_sats(Decimal(deposit["amount"])),
        )

        self.log.info("The reverted matured deposit should still reject reclaim and still support replay of the committed batch and withdrawal.")
        mempool_before_reclaim = sorted(n0.getrawmempool())
        assert_raises_rpc_error(
            -26,
            "experimental real profile reclaim queue root does not fit BLS12-381 scalar field",
            n0.sendstaledepositreclaim,
            sidechain_id,
            deposit_metadata,
            {"script": deposit["refund_script"]},
        )
        assert_equal(sorted(n0.getrawmempool()), mempool_before_reclaim)

        mempool = n0.getrawmempool()
        if batch_txid not in mempool:
            batch_res = n0.sendvaliditybatch(
                sidechain_id,
                real_public_inputs,
                real_valid_vector["proof_bytes_hex"],
                real_data_chunks,
            )
            batch_txid = batch_res["txid"]
        assert batch_txid in n0.getrawmempool()
        n0.generatetoaddress(1, n0.getnewaddress())

        mempool = n0.getrawmempool()
        if verified_withdrawal_txid not in mempool:
            verified_withdrawal_res = n0.sendverifiedwithdrawals(
                sidechain_id,
                real_public_inputs["batch_number"],
                withdrawal_rpc_entries,
            )
            verified_withdrawal_txid = verified_withdrawal_res["txid"]
        assert verified_withdrawal_txid in n0.getrawmempool()
        n0.generatetoaddress(1, n0.getnewaddress())

        final_sidechain = get_sidechain(n0.getvaliditysidechaininfo(), sidechain_id)
        assert final_sidechain is not None
        assert_equal(final_sidechain["latest_batch_number"], real_public_inputs["batch_number"])
        assert_equal(len(final_sidechain["accepted_batches"]), 1)
        assert_equal(final_sidechain["executed_withdrawal_count"], 1)
        assert_equal(final_sidechain["current_state_root"], real_public_inputs["new_state_root"])
        assert_equal(final_sidechain["queue_state"]["pending_message_count"], 0)
        assert_equal(final_sidechain["queue_state"]["reclaimable_deposit_count"], 0)
        assert_equal(final_sidechain["queue_state"]["root"], real_public_inputs["l1_message_root_after"])
        assert_equal(final_sidechain["queue_state"]["head_index"], real_public_inputs["consumed_queue_messages"])
        assert_equal(
            final_sidechain["escrow_balance"],
            amount_to_sats(Decimal(deposit["amount"]) - withdrawal_rpc_entries[0]["amount"]),
        )
        assert_equal(
            final_sidechain["current_withdrawal_root"],
            pad_field_hex(real_valid_vector["public_inputs"]["withdrawal_root"]),
        )
        assert_equal(
            compute_script_commitment(withdrawal_rpc_entries[0]["script"]),
            real_valid_vector["withdrawal_leaves"][0]["destination_commitment"],
        )


if __name__ == "__main__":
    ValiditySidechainRealProfileReclaimReorg().main()
