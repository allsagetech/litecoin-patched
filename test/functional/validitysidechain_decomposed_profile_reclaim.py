#!/usr/bin/env python3
# Copyright (c) 2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from decimal import Decimal
from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


def build_register_config(supported, initial_state_root, initial_withdrawal_root):
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
        "initial_withdrawal_root": initial_withdrawal_root,
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


def amount_to_sats(amount):
    return int(amount * Decimal("100000000"))


def pad_field_hex(raw_value):
    return raw_value.lower().rjust(64, "0")


class ValiditySidechainDecomposedProfileReclaim(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.repo_root = Path(__file__).resolve().parents[2]
        self.artifact_root = self.repo_root / "artifacts"
        self.common_args = [
            "-acceptnonstdtxn=1",
            f"-validityartifactsdir={self.artifact_root}",
        ]
        self.extra_args = [self.common_args]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.generatetoaddress(110, node.getnewaddress())

        supported = get_supported_profile(node, "groth16_bls12_381_poseidon_v2")
        sidechain_id = 58
        initial_withdrawal_root = "ff" * 32
        config = build_register_config(
            supported,
            initial_state_root=pad_field_hex("1"),
            initial_withdrawal_root=initial_withdrawal_root,
        )

        destination_commitment = "33" * 32
        deposit_id = "44" * 32
        deposit_amount = Decimal("1.0")
        deposit_nonce = 7
        refund_address = node.getnewaddress()
        deposit_metadata = {
            "deposit_id": deposit_id,
            "amount": deposit_amount,
            "destination_commitment": destination_commitment,
            "nonce": deposit_nonce,
        }

        self.log.info("Registering a decomposed real-profile sidechain with a full-width initial withdrawal root.")
        node.sendvaliditysidechainregister(sidechain_id, config)
        node.generatetoaddress(1, node.getnewaddress())

        self.log.info("Creating one pending deposit on the decomposed profile.")
        node.sendvaliditydeposit(
            sidechain_id,
            destination_commitment,
            {"address": refund_address},
            deposit_amount,
            deposit_nonce,
            deposit_id,
        )
        node.generatetoaddress(1, node.getnewaddress())
        deposit_height = node.getblockcount()

        sidechain = get_sidechain(node.getvaliditysidechaininfo(), sidechain_id)
        assert sidechain is not None
        assert_equal(sidechain["current_withdrawal_root"], initial_withdrawal_root)
        assert_equal(sidechain["escrow_balance"], amount_to_sats(deposit_amount))
        assert_equal(sidechain["queue_state"]["pending_message_count"], 1)
        assert_equal(sidechain["queue_state"]["pending_deposit_count"], 1)
        assert_equal(sidechain["queue_state"]["reclaimable_deposit_count"], 0)

        self.log.info("Advancing to reclaim maturity.")
        target_height = deposit_height + config["deposit_reclaim_delay"]
        current_height = node.getblockcount()
        if current_height < target_height:
            node.generatetoaddress(target_height - current_height, node.getnewaddress())

        sidechain = get_sidechain(node.getvaliditysidechaininfo(), sidechain_id)
        assert sidechain is not None
        assert_equal(sidechain["current_withdrawal_root"], initial_withdrawal_root)
        assert_equal(sidechain["queue_state"]["pending_message_count"], 1)
        assert_equal(sidechain["queue_state"]["pending_deposit_count"], 1)
        assert_equal(sidechain["queue_state"]["reclaimable_deposit_count"], 1)
        assert_equal(node.getrawmempool(), [])

        self.log.info("Reclaiming the matured deposit through the wallet RPC.")
        reclaim_result = node.sendstaledepositreclaim(
            sidechain_id,
            deposit_metadata,
            {"address": refund_address},
        )
        reclaim_txid = reclaim_result["txid"]
        assert_equal(reclaim_result["deposit_id"], deposit_id)
        assert reclaim_txid in node.getrawmempool()

        node.generatetoaddress(1, node.getnewaddress())

        sidechain = get_sidechain(node.getvaliditysidechaininfo(), sidechain_id)
        assert sidechain is not None
        assert_equal(sidechain["current_withdrawal_root"], initial_withdrawal_root)
        assert_equal(sidechain["escrow_balance"], 0)
        assert_equal(sidechain["queue_state"]["head_index"], 1)
        assert_equal(sidechain["queue_state"]["pending_message_count"], 0)
        assert_equal(sidechain["queue_state"]["pending_deposit_count"], 0)
        assert_equal(sidechain["queue_state"]["reclaimable_deposit_count"], 0)

        self.log.info("Persisting the reclaimed v2 state across restart.")
        self.restart_node(0, extra_args=self.common_args)
        node = self.nodes[0]

        sidechain = get_sidechain(node.getvaliditysidechaininfo(), sidechain_id)
        assert sidechain is not None
        assert_equal(sidechain["current_withdrawal_root"], initial_withdrawal_root)
        assert_equal(sidechain["escrow_balance"], 0)
        assert_equal(sidechain["queue_state"]["head_index"], 1)
        assert_equal(sidechain["queue_state"]["pending_message_count"], 0)
        assert_equal(sidechain["queue_state"]["pending_deposit_count"], 0)
        assert_equal(sidechain["queue_state"]["reclaimable_deposit_count"], 0)


if __name__ == "__main__":
    ValiditySidechainDecomposedProfileReclaim().main()
