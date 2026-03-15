#!/usr/bin/env python3
# Copyright (c) 2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from decimal import Decimal
import json
from pathlib import Path
import struct

from test_framework.messages import CTransaction, CTxOut, hash256, ser_uint256, uint256_from_str
from test_framework.script import CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than, assert_raises_rpc_error


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


def get_sidechain_info(node, sidechain_id):
    info = node.getvaliditysidechaininfo()
    for sidechain in info["sidechains"]:
        if sidechain["id"] == sidechain_id:
            return sidechain
    raise AssertionError(f"missing sidechain {sidechain_id} in getvaliditysidechaininfo")


def get_supported_profile(node, profile_name):
    info = node.getvaliditysidechaininfo()
    for supported in info["supported_proof_configs"]:
        if supported["profile_name"] == profile_name:
            return supported
    raise AssertionError(f"missing supported proof profile {profile_name}")


def load_json(path):
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def amount_to_sats(amount):
    return int(amount * Decimal("100000000"))


def hash256_uint256(payload):
    return uint256_from_str(hash256(payload))


def compute_script_commitment(script_hex):
    return f"{hash256_uint256(bytes.fromhex(script_hex)):064x}"


def pad_field_hex(raw_value):
    return raw_value.lower().rjust(64, "0")


def compute_merkle_root(encoded_leaves, leaf_magic, node_magic, root_magic):
    if not encoded_leaves:
        return f"{hash256_uint256(root_magic + struct.pack('<I', 0) + ser_uint256(0)):064x}"

    level = [hash256_uint256(leaf_magic + leaf) for leaf in encoded_leaves]
    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else level[i]
            next_level.append(hash256_uint256(node_magic + ser_uint256(left) + ser_uint256(right)))
        level = next_level

    return f"{hash256_uint256(root_magic + struct.pack('<I', len(encoded_leaves)) + ser_uint256(level[0])):064x}"


def compute_withdrawal_root(withdrawals):
    encoded_leaves = []
    for withdrawal in withdrawals:
        encoded_leaves.append(
            ser_uint256(int(withdrawal["withdrawal_id"], 16)) +
            amount_to_sats(withdrawal["amount"]).to_bytes(8, "little") +
            ser_uint256(int(withdrawal["destination_commitment"], 16))
        )
    return compute_merkle_root(encoded_leaves, b"VSCW\x02", b"VSCW\x03", b"VSCW\x01")


def compute_escape_exit_root(exits):
    encoded_leaves = []
    for exit_leaf in exits:
        encoded_leaves.append(
            ser_uint256(int(exit_leaf["exit_id"], 16)) +
            amount_to_sats(exit_leaf["amount"]).to_bytes(8, "little") +
            ser_uint256(int(exit_leaf["destination_commitment"], 16))
        )
    return compute_merkle_root(encoded_leaves, b"VSCE\x02", b"VSCE\x03", b"VSCE\x01")


def compute_data_root(chunks):
    payload = bytearray(b"VSCR\x01")
    payload.extend(struct.pack("<I", len(chunks)))
    for chunk in chunks:
        payload.extend(struct.pack("<I", len(chunk)))
        payload.extend(chunk)
    return f"{hash256_uint256(bytes(payload)):064x}"


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


def encode_pushdata(payload):
    if len(payload) < 0x4C:
        return bytes([len(payload)]) + payload
    if len(payload) <= 0xFF:
        return b"\x4c" + bytes([len(payload)]) + payload
    if len(payload) <= 0xFFFF:
        return b"\x4d" + struct.pack("<H", len(payload)) + payload
    return b"\x4e" + struct.pack("<I", len(payload)) + payload


def encode_batch_public_inputs(public_inputs):
    return (
        struct.pack("<I", public_inputs["batch_number"]) +
        ser_uint256(int(public_inputs["prior_state_root"], 16)) +
        ser_uint256(int(public_inputs["new_state_root"], 16)) +
        ser_uint256(int(public_inputs["l1_message_root_before"], 16)) +
        ser_uint256(int(public_inputs["l1_message_root_after"], 16)) +
        struct.pack("<I", public_inputs["consumed_queue_messages"]) +
        ser_uint256(int(public_inputs.get("queue_prefix_commitment", "00" * 32), 16)) +
        ser_uint256(int(public_inputs["withdrawal_root"], 16)) +
        ser_uint256(int(public_inputs["data_root"], 16)) +
        struct.pack("<I", public_inputs["data_size"])
    )


def compute_batch_commitment_hash(sidechain_id, public_inputs):
    payload = b"VSCB\x01" + bytes([sidechain_id]) + encode_batch_public_inputs(public_inputs)
    return f"{hash256_uint256(payload):064x}"


def encode_batch_data_chunk(index, chunk_count, chunk_bytes):
    return struct.pack("<II", index, chunk_count) + chunk_bytes


def build_commit_script(sidechain_id, public_inputs, proof_bytes, encoded_chunks):
    payload = ser_uint256(int(compute_batch_commitment_hash(sidechain_id, public_inputs), 16))
    raw = bytearray([0x6A, 0xB4])
    raw.extend(encode_pushdata(bytes([sidechain_id])))
    raw.extend(encode_pushdata(payload))
    raw.extend(encode_pushdata(bytes([0x08])))
    raw.extend(encode_pushdata(encode_batch_public_inputs(public_inputs)))
    raw.extend(encode_pushdata(proof_bytes))
    for chunk in encoded_chunks:
        raw.extend(encode_pushdata(chunk))
    return CScript(bytes(raw))


def fund_and_sign_script_tx(node, script, amount):
    tx = CTransaction()
    tx.vin = []
    tx.vout = [CTxOut(amount, script)]
    funded = node.fundrawtransaction(tx.serialize().hex())["hex"]
    return node.signrawtransactionwithwallet(funded)["hex"]


def build_script_destination(node):
    address = node.getnewaddress()
    return node.getaddressinfo(address)["scriptPubKey"]


class ValiditySidechainWalletTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        repo_root = Path(__file__).resolve().parents[2]
        artifact_root = repo_root / "artifacts"
        self.extra_args = [[
            "-acceptnonstdtxn=1",
            f"-validityartifactsdir={artifact_root}",
        ]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        repo_root = Path(__file__).resolve().parents[2]
        real_artifact_dir = repo_root / "artifacts" / "validitysidechain" / "groth16_bls12_381_poseidon_v1"
        real_proving_key_present = (real_artifact_dir / "batch_pk.bin").exists()
        real_valid_vector = load_json(real_artifact_dir / "valid" / "valid_proof.json")
        real_mismatch_vector = load_json(real_artifact_dir / "invalid" / "public_input_mismatch.json")
        real_queue_prefix_mismatch_vector = load_json(real_artifact_dir / "invalid" / "queue_prefix_commitment_mismatch.json")
        real_withdrawal_root_mismatch_vector = load_json(real_artifact_dir / "invalid" / "withdrawal_root_mismatch.json")
        real_corrupt_vector = load_json(real_artifact_dir / "invalid" / "corrupt_proof.json")
        mining_address = node.getnewaddress()
        node.generatetoaddress(101, mining_address)

        info = node.getvaliditysidechaininfo()
        assert_equal(info["batch_validation_mode"], "profile_specific")
        assert_equal(info["verified_withdrawal_execution_mode"], "profile_specific")
        assert_equal(info["escape_exit_mode"], "profile_specific")
        supported = get_supported_profile(node, "scaffold_onchain_da_v1")
        transition_supported = get_supported_profile(node, "scaffold_transition_da_v1")
        toy_supported = get_supported_profile(node, "gnark_groth16_toy_batch_transition_v1")
        native_toy_supported = get_supported_profile(node, "native_blst_groth16_toy_batch_transition_v1")
        real_supported = get_supported_profile(node, "groth16_bls12_381_poseidon_v1")
        assert_equal(supported["verified_withdrawal_execution_mode"], "merkle_inclusion_scaffold")
        assert_equal(supported["escape_exit_mode"], "merkle_inclusion_scaffold")
        assert_equal(transition_supported["verified_withdrawal_execution_mode"], "merkle_inclusion_scaffold")
        assert_equal(transition_supported["escape_exit_mode"], "merkle_inclusion_scaffold")
        assert_equal(toy_supported["scaffolding_only"], False)
        assert_equal(toy_supported["requires_external_verifier_assets"], True)
        assert_equal(toy_supported["supports_external_prover"], True)
        assert_equal(toy_supported["verifier_backend"], "external_gnark_command")
        assert_equal(toy_supported["batch_verifier_mode"], "gnark_groth16_toy_batch_transition_v1")
        assert_equal(toy_supported["verified_withdrawal_execution_mode"], "withdrawal_root_merkle_inclusion")
        assert_equal(toy_supported["escape_exit_mode"], "disabled_pending_real_state_proof")
        assert_equal(toy_supported["verifier_artifact_name"], "gnark_groth16_toy_batch_transition_v1")
        assert_equal(toy_supported["verifier_assets"]["required"], True)
        if toy_supported["verifier_assets"]["profile_manifest_parsed"]:
            assert_equal(toy_supported["verifier_assets"]["profile_manifest_name_matches"], True)
            assert_equal(toy_supported["verifier_assets"]["profile_manifest_backend_matches"], True)
            assert_equal(toy_supported["verifier_assets"]["profile_manifest_key_layout_matches"], True)
            assert_equal(toy_supported["verifier_assets"]["profile_manifest_tuple_matches"], True)
            assert_equal(toy_supported["verifier_assets"]["profile_manifest_public_inputs_match"], True)
            assert_equal(toy_supported["verifier_assets"]["valid_proof_vectors_present"], True)
            assert_equal(toy_supported["verifier_assets"]["invalid_proof_vectors_present"], True)
        assert_equal(native_toy_supported["scaffolding_only"], False)
        assert_equal(native_toy_supported["requires_external_verifier_assets"], True)
        assert_equal(native_toy_supported["supports_external_prover"], False)
        assert_equal(native_toy_supported["verifier_backend"], "native_blst_groth16")
        assert_equal(native_toy_supported["batch_verifier_mode"], "native_blst_groth16_toy_batch_transition_v1")
        assert_equal(native_toy_supported["verified_withdrawal_execution_mode"], "withdrawal_root_merkle_inclusion")
        assert_equal(native_toy_supported["escape_exit_mode"], "disabled_pending_real_state_proof")
        assert_equal(native_toy_supported["verifier_artifact_name"], "native_blst_groth16_toy_batch_transition_v1")
        assert_equal(native_toy_supported["verifier_assets"]["required"], True)
        assert_equal(native_toy_supported["verifier_assets"]["available"], True)
        assert_equal(native_toy_supported["verifier_assets"]["backend_ready"], True)
        assert_equal(native_toy_supported["verifier_assets"]["native_backend_available"], True)
        assert_equal(native_toy_supported["verifier_assets"]["native_backend_self_test_passed"], True)
        assert_greater_than(native_toy_supported["verifier_assets"]["native_backend_pairing_context_bytes"], 0)
        if native_toy_supported["verifier_assets"]["profile_manifest_parsed"]:
            assert_equal(native_toy_supported["verifier_assets"]["profile_manifest_name_matches"], True)
            assert_equal(native_toy_supported["verifier_assets"]["profile_manifest_backend_matches"], True)
            assert_equal(native_toy_supported["verifier_assets"]["profile_manifest_key_layout_matches"], True)
            assert_equal(native_toy_supported["verifier_assets"]["profile_manifest_tuple_matches"], True)
            assert_equal(native_toy_supported["verifier_assets"]["profile_manifest_public_inputs_match"], True)
            assert_equal(native_toy_supported["verifier_assets"]["valid_proof_vectors_present"], True)
            assert_equal(native_toy_supported["verifier_assets"]["invalid_proof_vectors_present"], True)
        assert_equal(real_supported["scaffolding_only"], False)
        assert_equal(real_supported["requires_external_verifier_assets"], True)
        assert_equal(real_supported["supports_external_prover"], True)
        assert_equal(real_supported["verifier_backend"], "native_blst_groth16")
        assert_equal(real_supported["batch_verifier_mode"], "groth16_bls12_381_poseidon_v1")
        assert_equal(real_supported["verified_withdrawal_execution_mode"], "withdrawal_root_merkle_inclusion")
        assert_equal(real_supported["escape_exit_mode"], "disabled_pending_real_state_proof")
        assert_equal(real_supported["verifier_artifact_name"], "groth16_bls12_381_poseidon_v1")
        assert_equal(real_supported["verifier_assets"]["required"], True)
        assert_equal(real_supported["verifier_assets"]["available"], True)
        assert_equal(real_supported["verifier_assets"]["prover_assets_present"], real_proving_key_present)
        assert_equal(real_supported["verifier_assets"]["backend_ready"], True)
        assert_equal(real_supported["verifier_assets"]["native_backend_available"], True)
        assert_equal(real_supported["verifier_assets"]["native_backend_self_test_passed"], True)
        assert_greater_than(real_supported["verifier_assets"]["native_backend_pairing_context_bytes"], 0)
        if real_supported["verifier_assets"]["profile_manifest_parsed"]:
            assert_equal(real_supported["verifier_assets"]["profile_manifest_name_matches"], True)
            assert_equal(real_supported["verifier_assets"]["profile_manifest_backend_matches"], True)
            assert_equal(real_supported["verifier_assets"]["profile_manifest_key_layout_matches"], True)
            assert_equal(real_supported["verifier_assets"]["profile_manifest_tuple_matches"], True)
            assert_equal(real_supported["verifier_assets"]["profile_manifest_public_inputs_match"], True)
            assert_equal(real_supported["verifier_assets"]["valid_proof_vectors_present"], True)
            assert_equal(real_supported["verifier_assets"]["invalid_proof_vectors_present"], True)

        withdrawals = [
            {
                "withdrawal_id": "77" * 32,
                "amount": Decimal("0.25"),
                "script": build_script_destination(node),
            },
            {
                "withdrawal_id": "88" * 32,
                "amount": Decimal("0.50"),
                "script": build_script_destination(node),
            },
        ]
        for withdrawal in withdrawals:
            withdrawal["destination_commitment"] = compute_script_commitment(withdrawal["script"])

        escape_exits = [
            {
                "exit_id": "99" * 32,
                "amount": Decimal("0.20"),
                "script": build_script_destination(node),
            },
            {
                "exit_id": "aa" * 32,
                "amount": Decimal("0.30"),
                "script": build_script_destination(node),
            },
        ]
        for exit_leaf in escape_exits:
            exit_leaf["destination_commitment"] = compute_script_commitment(exit_leaf["script"])

        config = build_register_config(
            supported,
            initial_state_root=compute_escape_exit_root(escape_exits),
            initial_withdrawal_root=compute_withdrawal_root(withdrawals),
        )
        sidechain_id = 7

        self.log.info("Registering a validity sidechain with the supported scaffold profile.")
        register_res = node.sendvaliditysidechainregister(sidechain_id, config)
        node.generate(1)

        sidechain = get_sidechain_info(node, sidechain_id)
        assert_equal(register_res["sidechain_id"], sidechain_id)
        assert_equal(sidechain["verified_withdrawal_execution_mode"], "merkle_inclusion_scaffold")
        assert_equal(sidechain["escape_exit_mode"], "merkle_inclusion_scaffold")
        assert_equal(sidechain["current_state_root"], config["initial_state_root"])
        assert_equal(sidechain["current_withdrawal_root"], config["initial_withdrawal_root"])
        assert_equal(sidechain["queue_state"]["pending_message_count"], 0)
        assert_equal(sidechain["latest_batch_number"], 0)

        self.log.info("Submitting two deposits so one can remain reclaimable while the other funds exits.")
        refund_address = node.getnewaddress()
        second_refund_address = node.getnewaddress()
        first_deposit_amount = Decimal("1.25")
        second_deposit_amount = Decimal("1.25")
        first_destination_commitment = "33" * 32
        second_destination_commitment = "44" * 32
        first_deposit_res = node.sendvaliditydeposit(
            sidechain_id,
            first_destination_commitment,
            {"address": refund_address},
            first_deposit_amount,
            7,
        )
        node.generate(1)
        first_deposit_height = node.getblockcount()

        node.sendvaliditydeposit(
            sidechain_id,
            second_destination_commitment,
            {"address": second_refund_address},
            second_deposit_amount,
            8,
        )
        node.generate(1)

        sidechain = get_sidechain_info(node, sidechain_id)
        assert_equal(
            sidechain["escrow_balance"],
            amount_to_sats(first_deposit_amount + second_deposit_amount),
        )
        assert_equal(sidechain["queue_state"]["pending_message_count"], 2)
        assert_equal(sidechain["queue_state"]["pending_deposit_count"], 2)

        reclaim_deposit = {
            "deposit_id": first_deposit_res["deposit_id"],
            "amount": first_deposit_amount,
            "destination_commitment": first_destination_commitment,
            "nonce": first_deposit_res["nonce"],
        }

        self.log.info("Rejecting reclaim before the deposit reclaim delay.")
        assert_raises_rpc_error(
            -26,
            "deposit reclaim delay not reached",
            node.sendstaledepositreclaim,
            sidechain_id,
            reclaim_deposit,
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
        assert_equal(sidechain["queue_state"]["pending_message_count"], 3)
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

        self.log.info("Rejecting a batch that advertises non-zero data_size without publishing DA chunks.")
        missing_da_public_inputs = dict(public_inputs)
        missing_da_public_inputs["data_root"] = compute_data_root([bytes.fromhex("01")])
        missing_da_public_inputs["data_size"] = 1
        assert_raises_rpc_error(
            -26,
            "data chunks missing for non-zero data_size",
            node.sendvaliditybatch,
            sidechain_id,
            missing_da_public_inputs,
        )

        self.log.info("Rejecting a batch that exceeds the configured DA payload size.")
        oversized_da_public_inputs = dict(public_inputs)
        oversized_da_public_inputs["data_size"] = config["max_batch_data_bytes"] + 1
        assert_raises_rpc_error(
            -26,
            "data size exceeds configured limit",
            node.sendvaliditybatch,
            sidechain_id,
            oversized_da_public_inputs,
        )

        self.log.info("Rejecting a batch whose published DA chunks do not match data_root.")
        bad_da_root_public_inputs = dict(public_inputs)
        bad_da_root_public_inputs["data_root"] = "99" * 32
        bad_da_root_public_inputs["data_size"] = 1
        assert_raises_rpc_error(
            -26,
            "data root does not match published chunks",
            node.sendvaliditybatch,
            sidechain_id,
            bad_da_root_public_inputs,
            None,
            ["01"],
        )

        self.log.info("Rejecting a batch whose DA chunk metadata is out of order.")
        malformed_da_public_inputs = dict(public_inputs)
        malformed_chunks = [b"\x01", b"\x02\x03"]
        malformed_da_public_inputs["data_root"] = compute_data_root(malformed_chunks)
        malformed_da_public_inputs["data_size"] = sum(len(chunk) for chunk in malformed_chunks)
        malformed_script = build_commit_script(
            sidechain_id,
            malformed_da_public_inputs,
            bytes.fromhex("01"),
            [
                encode_batch_data_chunk(1, 2, malformed_chunks[1]),
                encode_batch_data_chunk(0, 2, malformed_chunks[0]),
            ],
        )
        malformed_batch_hex = fund_and_sign_script_tx(node, malformed_script, 0)
        assert_raises_rpc_error(
            -26,
            "validitysidechain-batch-metadata-bad",
            node.sendrawtransaction,
            malformed_batch_hex,
        )

        self.log.info("Rejecting a batch whose proof bytes exceed the configured limit.")
        assert_raises_rpc_error(
            -26,
            "proof bytes exceed configured limit",
            node.sendvaliditybatch,
            sidechain_id,
            public_inputs,
            "00" * (config["max_proof_bytes"] + 1),
        )

        batch_res = node.sendvaliditybatch(sidechain_id, public_inputs)
        assert_equal(batch_res["auto_scaffold_proof"], True)
        node.generate(1)

        sidechain = get_sidechain_info(node, sidechain_id)
        assert_equal(sidechain["latest_batch_number"], 1)
        assert_equal(len(sidechain["accepted_batches"]), 1)
        assert_equal(sidechain["accepted_batches"][0]["batch_number"], 1)
        assert_equal(sidechain["accepted_batches"][0]["data_size"], 0)
        assert_equal(sidechain["accepted_batches"][0]["published_data_chunk_count"], 0)
        assert_equal(sidechain["accepted_batches"][0]["published_data_bytes"], 0)
        assert_equal(sidechain["accepted_batches"][0]["published_in_txid"], batch_res["txid"])
        assert_equal(len(sidechain["accepted_batches"][0]["published_in_block"]), 64)
        assert sidechain["accepted_batches"][0]["proof_size"] > 0
        batch_height = node.getblockcount()

        self.log.info("Executing verified withdrawals through the new wallet RPC.")
        withdrawal_rpc_entries = [
            {
                "withdrawal_id": withdrawal["withdrawal_id"],
                "script": withdrawal["script"],
                "amount": withdrawal["amount"],
            }
            for withdrawal in withdrawals
        ]
        verified_withdrawal_res = node.sendverifiedwithdrawals(sidechain_id, 1, withdrawal_rpc_entries)
        assert_equal(len(verified_withdrawal_res["accepted_batch_id"]), 64)
        assert_equal(verified_withdrawal_res["withdrawal_root"], config["initial_withdrawal_root"])
        assert_equal(verified_withdrawal_res["withdrawal_count"], len(withdrawals))
        node.generate(1)

        sidechain = get_sidechain_info(node, sidechain_id)
        assert_equal(sidechain["executed_withdrawal_count"], len(withdrawals))
        assert_equal(
            sidechain["escrow_balance"],
            amount_to_sats(first_deposit_amount + second_deposit_amount - Decimal("0.75")),
        )

        self.log.info("Rejecting escape exits before the escape hatch delay.")
        escape_exit_rpc_entries = [
            {
                "exit_id": exit_leaf["exit_id"],
                "script": exit_leaf["script"],
                "amount": exit_leaf["amount"],
            }
            for exit_leaf in escape_exits
        ]
        assert_raises_rpc_error(
            -26,
            "escape hatch delay not reached",
            node.sendescapeexit,
            sidechain_id,
            sidechain["current_state_root"],
            escape_exit_rpc_entries,
        )

        self.log.info("Advancing to both reclaim and escape-exit eligibility heights.")
        reclaim_height = first_deposit_height + config["deposit_reclaim_delay"]
        escape_height = batch_height + config["escape_hatch_delay"]
        target_height = max(reclaim_height, escape_height)
        current_height = node.getblockcount()
        if current_height < target_height:
            node.generate(target_height - current_height)

        sidechain = get_sidechain_info(node, sidechain_id)
        assert_equal(sidechain["queue_state"]["reclaimable_deposit_count"], 2)
        assert_equal(sidechain["queue_state"]["matured_force_exit_count"], 1)

        self.log.info("Executing escape exits through the new wallet RPC.")
        escape_exit_res = node.sendescapeexit(
            sidechain_id,
            sidechain["current_state_root"],
            escape_exit_rpc_entries,
        )
        assert_equal(escape_exit_res["state_root_reference"], sidechain["current_state_root"])
        assert_equal(escape_exit_res["exit_count"], len(escape_exits))
        node.generate(1)

        sidechain = get_sidechain_info(node, sidechain_id)
        assert_equal(sidechain["executed_escape_exit_count"], len(escape_exits))
        assert_equal(
            sidechain["escrow_balance"],
            amount_to_sats(first_deposit_amount + second_deposit_amount - Decimal("1.25")),
        )

        self.log.info("Reclaiming the stale deposit after the delay.")
        reclaim_res = node.sendstaledepositreclaim(
            sidechain_id,
            reclaim_deposit,
            {"address": refund_address},
        )
        assert_equal(reclaim_res["deposit_id"], first_deposit_res["deposit_id"])
        node.generate(1)

        sidechain = get_sidechain_info(node, sidechain_id)
        assert_equal(sidechain["escrow_balance"], 0)
        assert_equal(sidechain["queue_state"]["head_index"], 1)
        assert_equal(sidechain["queue_state"]["pending_message_count"], 2)
        assert_equal(sidechain["queue_state"]["pending_deposit_count"], 1)
        assert_equal(sidechain["queue_state"]["pending_force_exit_count"], 1)

        self.log.info("Registering a second sidechain on the transition-scaffold profile.")
        transition_sidechain_id = 8
        transition_config = build_register_config(
            transition_supported,
            initial_state_root="11" * 32,
            initial_withdrawal_root="22" * 32,
        )
        node.sendvaliditysidechainregister(transition_sidechain_id, transition_config)
        node.generate(1)

        transition_sidechain = get_sidechain_info(node, transition_sidechain_id)
        assert_equal(transition_sidechain["batch_verifier_mode"], "scaffold_transition_commitment_v1")
        assert_equal(transition_sidechain["verified_withdrawal_execution_mode"], "merkle_inclusion_scaffold")
        assert_equal(transition_sidechain["escape_exit_mode"], "merkle_inclusion_scaffold")
        assert_equal(transition_sidechain["current_state_root"], transition_config["initial_state_root"])
        assert_equal(transition_sidechain["current_withdrawal_root"], transition_config["initial_withdrawal_root"])

        self.log.info("Submitting a scaffold transition batch with changed roots and real DA chunks.")
        transition_chunks = [bytes.fromhex("dead"), bytes.fromhex("beef01")]
        transition_public_inputs = {
            "batch_number": 1,
            "prior_state_root": transition_sidechain["current_state_root"],
            "new_state_root": "33" * 32,
            "l1_message_root_before": transition_sidechain["queue_state"]["root"],
            "l1_message_root_after": transition_sidechain["queue_state"]["root"],
            "consumed_queue_messages": 0,
            "withdrawal_root": "44" * 32,
            "data_root": compute_data_root(transition_chunks),
            "data_size": sum(len(chunk) for chunk in transition_chunks),
        }
        transition_batch_res = node.sendvaliditybatch(
            transition_sidechain_id,
            transition_public_inputs,
            None,
            [chunk.hex() for chunk in transition_chunks],
        )
        assert_equal(transition_batch_res["auto_scaffold_proof"], True)
        node.generate(1)

        transition_sidechain = get_sidechain_info(node, transition_sidechain_id)
        assert_equal(transition_sidechain["latest_batch_number"], 1)
        assert_equal(transition_sidechain["current_state_root"], transition_public_inputs["new_state_root"])
        assert_equal(transition_sidechain["current_withdrawal_root"], transition_public_inputs["withdrawal_root"])
        assert_equal(transition_sidechain["current_data_root"], transition_public_inputs["data_root"])
        assert_equal(transition_sidechain["accepted_batches"][0]["data_size"], transition_public_inputs["data_size"])
        assert_equal(transition_sidechain["accepted_batches"][0]["published_data_chunk_count"], len(transition_chunks))
        assert_equal(transition_sidechain["accepted_batches"][0]["published_data_bytes"], transition_public_inputs["data_size"])
        assert_equal(transition_sidechain["accepted_batches"][0]["published_in_txid"], transition_batch_res["txid"])
        assert_equal(transition_sidechain["accepted_batches"][0]["new_state_root"], transition_public_inputs["new_state_root"])
        assert_equal(transition_sidechain["accepted_batches"][0]["withdrawal_root"], transition_public_inputs["withdrawal_root"])
        assert_equal(transition_sidechain["accepted_batches"][0]["data_root"], transition_public_inputs["data_root"])

        self.log.info("Rejecting escape exits on a non-scaffold profile before real state-root proofs exist.")
        non_scaffold_escape_sidechain_id = 9
        non_scaffold_escape_exits = [
            {
                "exit_id": "ab" * 32,
                "amount": Decimal("0.15"),
                "script": build_script_destination(node),
            },
            {
                "exit_id": "bc" * 32,
                "amount": Decimal("0.10"),
                "script": build_script_destination(node),
            },
        ]
        non_scaffold_escape_root = compute_escape_exit_root(non_scaffold_escape_exits)
        non_scaffold_escape_config = build_register_config(
            real_supported,
            initial_state_root=non_scaffold_escape_root,
        )
        node.sendvaliditysidechainregister(non_scaffold_escape_sidechain_id, non_scaffold_escape_config)
        node.generate(1)

        non_scaffold_escape_sidechain = get_sidechain_info(node, non_scaffold_escape_sidechain_id)
        assert_equal(non_scaffold_escape_sidechain["verified_withdrawal_execution_mode"], "withdrawal_root_merkle_inclusion")
        assert_equal(non_scaffold_escape_sidechain["escape_exit_mode"], "disabled_pending_real_state_proof")
        assert_raises_rpc_error(
            -26,
            "escape exits are not implemented for non-scaffold profiles",
            node.sendescapeexit,
            non_scaffold_escape_sidechain_id,
            non_scaffold_escape_root,
            non_scaffold_escape_exits,
        )

        self.log.info("Registering the proposed Groth16 profile and replaying committed native proof vectors.")
        real_sidechain_id = int(real_valid_vector["public_inputs"]["sidechain_id"])
        real_config = build_register_config(
            real_supported,
            initial_state_root=pad_field_hex(real_valid_vector["public_inputs"]["prior_state_root"]),
            initial_withdrawal_root="00" * 32,
        )
        node.sendvaliditysidechainregister(real_sidechain_id, real_config)
        node.generate(1)

        real_sidechain = get_sidechain_info(node, real_sidechain_id)
        assert_equal(real_sidechain["batch_verifier_mode"], "groth16_bls12_381_poseidon_v1")
        assert_equal(real_sidechain["verified_withdrawal_execution_mode"], "withdrawal_root_merkle_inclusion")
        assert_equal(real_sidechain["escape_exit_mode"], "disabled_pending_real_state_proof")
        assert_equal(real_sidechain["verifier_assets"]["required"], True)
        assert_equal(real_sidechain["verifier_assets"]["available"], True)
        assert_equal(real_sidechain["verifier_assets"]["prover_assets_present"], real_proving_key_present)
        assert_equal(real_sidechain["verifier_assets"]["backend_ready"], True)
        assert_equal(real_sidechain["verifier_assets"]["native_backend_available"], True)
        assert_equal(real_sidechain["verifier_assets"]["native_backend_self_test_passed"], True)
        assert_greater_than(real_sidechain["verifier_assets"]["native_backend_pairing_context_bytes"], 0)
        if real_sidechain["verifier_assets"]["profile_manifest_parsed"]:
            assert_equal(real_sidechain["verifier_assets"]["profile_manifest_name_matches"], True)
            assert_equal(real_sidechain["verifier_assets"]["profile_manifest_backend_matches"], True)
            assert_equal(real_sidechain["verifier_assets"]["profile_manifest_key_layout_matches"], True)
            assert_equal(real_sidechain["verifier_assets"]["profile_manifest_tuple_matches"], True)
            assert_equal(real_sidechain["verifier_assets"]["profile_manifest_public_inputs_match"], True)

        real_queue_entries = []
        for index, deposit in enumerate(real_valid_vector.get("setup_deposits", [])):
            deposit_res = node.sendvaliditydeposit(
                real_sidechain_id,
                deposit["destination_commitment"],
                {"script": deposit["refund_script"]},
                Decimal(deposit["amount"]),
                deposit["nonce"],
                deposit["deposit_id"],
            )
            real_queue_entries.append({
                "queue_index": index,
                "message_kind": 1,
                "message_id": deposit_res["deposit_id"],
                "message_hash": deposit_res["deposit_message_hash"],
            })
        if real_queue_entries:
            node.generate(1)

        real_sidechain = get_sidechain_info(node, real_sidechain_id)
        if real_queue_entries:
            assert_equal(real_sidechain["queue_state"]["pending_message_count"], len(real_queue_entries))
            assert_equal(
                real_sidechain["queue_state"]["root"],
                pad_field_hex(real_valid_vector["public_inputs"]["l1_message_root_before"]),
            )
            assert_equal(
                compute_consumed_queue_root(
                    real_sidechain_id,
                    real_sidechain["queue_state"]["root"],
                    real_queue_entries,
                ),
                pad_field_hex(real_valid_vector["public_inputs"]["l1_message_root_after"]),
            )
            assert_equal(
                compute_queue_prefix_commitment(real_sidechain_id, real_queue_entries),
                pad_field_hex(real_valid_vector["public_inputs"]["queue_prefix_commitment"]),
            )

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

        assert_raises_rpc_error(
            -26,
            "Groth16",
            node.sendvaliditybatch,
            real_sidechain_id,
            {
                **real_public_inputs,
                "new_state_root": pad_field_hex(real_mismatch_vector["public_inputs"]["new_state_root"]),
            },
            real_mismatch_vector["proof_bytes_hex"],
            real_data_chunks,
        )
        assert_raises_rpc_error(
            -26,
            "Groth16",
            node.sendvaliditybatch,
            real_sidechain_id,
            {
                **real_public_inputs,
                "withdrawal_root": pad_field_hex(real_withdrawal_root_mismatch_vector["public_inputs"]["withdrawal_root"]),
            },
            real_withdrawal_root_mismatch_vector["proof_bytes_hex"],
            real_data_chunks,
        )
        assert_raises_rpc_error(
            -26,
            "Groth16",
            node.sendvaliditybatch,
            real_sidechain_id,
            {
                **real_public_inputs,
                "queue_prefix_commitment": pad_field_hex(real_queue_prefix_mismatch_vector["public_inputs"]["queue_prefix_commitment"]),
            },
            real_queue_prefix_mismatch_vector["proof_bytes_hex"],
            real_data_chunks,
        )
        assert_raises_rpc_error(
            -26,
            "Groth16",
            node.sendvaliditybatch,
            real_sidechain_id,
            real_public_inputs,
            real_corrupt_vector["proof_bytes_hex"],
            real_data_chunks,
        )

        real_batch_res = node.sendvaliditybatch(
            real_sidechain_id,
            real_public_inputs,
            real_valid_vector["proof_bytes_hex"],
            real_data_chunks,
        )
        assert_equal(real_batch_res["auto_scaffold_proof"], False)
        assert_equal(real_batch_res["auto_external_proof"], False)
        node.generate(1)

        real_sidechain = get_sidechain_info(node, real_sidechain_id)
        assert_equal(real_sidechain["latest_batch_number"], real_public_inputs["batch_number"])
        assert_equal(real_sidechain["current_state_root"], real_public_inputs["new_state_root"])
        assert_equal(real_sidechain["current_withdrawal_root"], real_public_inputs["withdrawal_root"])
        assert_equal(real_sidechain["current_data_root"], real_public_inputs["data_root"])
        assert_equal(real_sidechain["accepted_batches"][0]["proof_size"], len(bytes.fromhex(real_valid_vector["proof_bytes_hex"])))
        assert_equal(real_sidechain["accepted_batches"][0]["published_data_chunk_count"], len(real_data_chunks))
        assert_equal(real_sidechain["accepted_batches"][0]["published_data_bytes"], real_public_inputs["data_size"])
        assert_equal(real_sidechain["queue_state"]["head_index"], len(real_queue_entries))
        assert_equal(real_sidechain["queue_state"]["pending_message_count"], 0)

        real_withdrawals = real_valid_vector.get("withdrawal_leaves", [])
        if real_withdrawals:
            verified_withdrawal_res = node.sendverifiedwithdrawals(
                real_sidechain_id,
                real_public_inputs["batch_number"],
                [
                    {
                        "withdrawal_id": leaf["withdrawal_id"],
                        "script": leaf["script"],
                        "amount": Decimal(leaf["amount"]),
                    }
                    for leaf in real_withdrawals
                ],
            )
            assert_equal(verified_withdrawal_res["withdrawal_root"], real_public_inputs["withdrawal_root"])
            assert_equal(verified_withdrawal_res["withdrawal_count"], len(real_withdrawals))
            node.generate(1)

            real_sidechain = get_sidechain_info(node, real_sidechain_id)
            assert_equal(real_sidechain["executed_withdrawal_count"], len(real_withdrawals))
            assert_equal(real_sidechain["escrow_balance"], amount_to_sats(Decimal("1.0") - Decimal(real_withdrawals[0]["amount"])))


if __name__ == "__main__":
    ValiditySidechainWalletTest().main()
