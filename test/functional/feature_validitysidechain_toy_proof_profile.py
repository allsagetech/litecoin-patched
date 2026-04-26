#!/usr/bin/env python3
# Copyright (c) 2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from pathlib import Path
from unittest import SkipTest
from decimal import Decimal
import json
import os
import shlex
import shutil
import struct
import subprocess
import sys

from test_framework.messages import CTransaction, CTxOut, hash256, ser_uint256, uint256_from_str
from test_framework.script import CScript
from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error, get_rpc_proxy


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


def get_supported_profile(node, profile_name):
    info = node.getvaliditysidechaininfo()
    for supported in info["supported_proof_configs"]:
        if supported["profile_name"] == profile_name:
            return supported
    raise AssertionError(f"missing supported proof profile {profile_name}")


def get_sidechain_info(node, sidechain_id):
    info = node.getvaliditysidechaininfo()
    for sidechain in info["sidechains"]:
        if sidechain["id"] == sidechain_id:
            return sidechain
    raise AssertionError(f"missing sidechain {sidechain_id} in getvaliditysidechaininfo")


def hex_uint(value):
    return f"{value:064x}"


def pad_field_hex(raw_value):
    return raw_value.lower().rjust(64, "0")


def combine_128_bit_limbs(low_hex, high_hex):
    combined = high_hex.lower().rjust(32, "0") + low_hex.lower().rjust(32, "0")
    combined = combined.lstrip("0")
    return combined or "0"


def load_json(path):
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def hash256_uint256(payload):
    return uint256_from_str(hash256(payload))


def compute_script_commitment(script_hex):
    return f"{hash256_uint256(bytes.fromhex(script_hex)):064x}"


def get_destination_commitment(leaf):
    if "destination_commitment" in leaf:
        return leaf["destination_commitment"]
    if "script" in leaf:
        return compute_script_commitment(leaf["script"])
    raise KeyError("destination_commitment")


def amount_to_sats(amount):
    return int(amount * Decimal("100000000"))


def compute_queue_consume_root(sidechain_id, prior_root, queue_index, message_kind, message_id, message_hash):
    payload = b"VSCQC\x01"
    payload += sidechain_id.to_bytes(1, "little")
    payload += ser_uint256(int(prior_root, 16))
    payload += queue_index.to_bytes(8, "little")
    payload += message_kind.to_bytes(1, "little")
    payload += ser_uint256(int(message_id, 16))
    payload += ser_uint256(int(message_hash, 16))
    return hash256(payload)[::-1].hex()


def compute_consumed_queue_root(sidechain_id, prior_root, entries):
    root = prior_root
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


def compute_queue_prefix_commitment_step(sidechain_id, prior_commitment, queue_index, message_kind, message_id, message_hash):
    payload = b"VSCQP\x01"
    payload += sidechain_id.to_bytes(1, "little")
    payload += ser_uint256(int(prior_commitment, 16))
    payload += queue_index.to_bytes(8, "little")
    payload += message_kind.to_bytes(1, "little")
    payload += ser_uint256(int(message_id, 16))
    payload += ser_uint256(int(message_hash, 16))
    return hash256(payload)[::-1].hex()


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


def order_queue_entries_by_block(node, block_hash, pending_entries, start_index=0):
    block = node.getblock(block_hash)
    entries_by_txid = {entry["txid"]: entry for entry in pending_entries}
    ordered_entries = []
    for txid in block["tx"]:
        entry = entries_by_txid.get(txid)
        if entry is None:
            continue
        ordered_entries.append({
            "queue_index": start_index + len(ordered_entries),
            "message_kind": entry["message_kind"],
            "message_id": entry["message_id"],
            "message_hash": entry["message_hash"],
        })
    if len(ordered_entries) != len(pending_entries):
        missing = sorted(set(entries_by_txid) - {txid for txid in block["tx"]})
        raise AssertionError(f"missing queued entry txids in block {block_hash}: {missing}")
    return ordered_entries


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
            ser_uint256(int(get_destination_commitment(withdrawal), 16))
        )
    return compute_merkle_root(encoded_leaves, b"VSCW\x02", b"VSCW\x03", b"VSCW\x01")


def compute_data_root(chunks):
    payload = bytearray(b"VSCR\x01")
    payload.extend(struct.pack("<I", len(chunks)))
    for chunk in chunks:
        payload.extend(struct.pack("<I", len(chunk)))
        payload.extend(chunk)
    return f"{hash256_uint256(bytes(payload)):064x}"


def build_script_destination(node):
    address = node.getnewaddress()
    return node.getaddressinfo(address)["scriptPubKey"]


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


def shell_join(argv):
    args = [str(arg) for arg in argv]
    if os.name == "nt":
        return subprocess.list2cmdline(args)
    return shlex.join(args)


def assert_raises_rpc_error_any(code, messages, fun, *args, **kwargs):
    try:
        fun(*args, **kwargs)
    except JSONRPCException as exc:
        error = exc.error
        if error["code"] != code:
            raise AssertionError(
                f"Unexpected JSONRPC error code {error['code']}, expected {code}: {error['message']}"
            ) from exc
        if any(message in error["message"] for message in messages):
            return
        raise AssertionError(
            "Expected one of the substrings {} in error message: '{}'".format(messages, error["message"])
        ) from exc
    raise AssertionError("No exception raised")


class ValiditySidechainToyProofProfileTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.rpc_timeout = 240

        self.repo_root = Path(__file__).resolve().parents[2]
        self.zk_demo_dir = self.repo_root / "contrib" / "validitysidechain-zk-demo"
        self.zk_runner = self.zk_demo_dir / "run_tool.py"
        self.artifact_root = self.repo_root / "artifacts"
        self.toy_artifact_dir = self.artifact_root / "validitysidechain" / "gnark_groth16_toy_batch_transition_v1"
        self.native_toy_artifact_dir = self.artifact_root / "validitysidechain" / "native_blst_groth16_toy_batch_transition_v1"
        self.real_artifact_dir = self.artifact_root / "validitysidechain" / "groth16_bls12_381_poseidon_v1"
        self.real_v2_artifact_dir = self.artifact_root / "validitysidechain" / "groth16_bls12_381_poseidon_v2"
        self.real_v3_artifact_dir = self.artifact_root / "validitysidechain" / "groth16_bls12_381_poseidon_v3"
        self.real_proving_key_path = self.real_artifact_dir / "batch_pk.bin"
        self.real_v2_proving_key_path = self.real_v2_artifact_dir / "batch_pk.bin"
        self.real_v3_proving_key_path = self.real_v3_artifact_dir / "batch_pk.bin"
        self.valid_vector_path = self.toy_artifact_dir / "valid" / "valid_proof.json"
        self.invalid_mismatch_vector_path = self.toy_artifact_dir / "invalid" / "public_input_mismatch.json"
        self.invalid_corrupt_vector_path = self.toy_artifact_dir / "invalid" / "corrupt_proof.json"
        self.native_valid_vector_path = self.native_toy_artifact_dir / "valid" / "valid_proof.json"
        self.native_invalid_mismatch_vector_path = self.native_toy_artifact_dir / "invalid" / "public_input_mismatch.json"
        self.native_invalid_corrupt_vector_path = self.native_toy_artifact_dir / "invalid" / "corrupt_proof.json"
        self.real_valid_vector_path = self.real_artifact_dir / "valid" / "valid_proof.json"
        self.real_v2_valid_vector_path = self.real_v2_artifact_dir / "valid" / "valid_proof.json"
        self.real_invalid_mismatch_vector_path = self.real_artifact_dir / "invalid" / "public_input_mismatch.json"
        self.real_v2_invalid_mismatch_vector_path = self.real_v2_artifact_dir / "invalid" / "public_input_mismatch.json"
        self.real_v3_valid_vector_path = self.real_v3_artifact_dir / "valid" / "valid_proof.json"
        self.real_v3_invalid_mismatch_vector_path = self.real_v3_artifact_dir / "invalid" / "public_input_mismatch.json"
        self.real_invalid_queue_prefix_mismatch_vector_path = self.real_artifact_dir / "invalid" / "queue_prefix_commitment_mismatch.json"
        self.real_v2_invalid_queue_prefix_mismatch_vector_path = self.real_v2_artifact_dir / "invalid" / "queue_prefix_commitment_mismatch.json"
        self.real_v3_invalid_queue_prefix_mismatch_vector_path = self.real_v3_artifact_dir / "invalid" / "queue_prefix_commitment_mismatch.json"
        self.real_invalid_withdrawal_root_mismatch_vector_path = self.real_artifact_dir / "invalid" / "withdrawal_root_mismatch.json"
        self.real_v2_invalid_withdrawal_root_mismatch_vector_path = self.real_v2_artifact_dir / "invalid" / "withdrawal_root_mismatch.json"
        self.real_v3_invalid_withdrawal_root_mismatch_vector_path = self.real_v3_artifact_dir / "invalid" / "withdrawal_root_mismatch.json"
        self.real_invalid_corrupt_vector_path = self.real_artifact_dir / "invalid" / "corrupt_proof.json"
        self.real_v2_invalid_corrupt_vector_path = self.real_v2_artifact_dir / "invalid" / "corrupt_proof.json"
        self.real_v3_invalid_corrupt_vector_path = self.real_v3_artifact_dir / "invalid" / "corrupt_proof.json"
        self.have_go = shutil.which("go") is not None

        base_args = ["-acceptnonstdtxn=1", "-validityallowmigrationprofiles=1"]
        if self.have_go:
            base_args.extend([
                f"-validityartifactsdir={self.artifact_root}",
                f"-validityverifiercommand={shell_join([sys.executable, self.zk_runner, 'verify'])}",
                f"-validityprovercommand={shell_join([sys.executable, self.zk_runner, 'prove'])}",
            ])
        self.extra_args = [base_args]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        if not self.have_go:
            raise SkipTest("go toolchain not available for the experimental toy proof profile")
        if not self.zk_runner.exists():
            raise SkipTest("toy zk runner script is missing")
        for required_path in (
            self.valid_vector_path,
            self.invalid_mismatch_vector_path,
            self.invalid_corrupt_vector_path,
            self.native_valid_vector_path,
            self.native_invalid_mismatch_vector_path,
            self.native_invalid_corrupt_vector_path,
            self.real_valid_vector_path,
            self.real_v2_valid_vector_path,
            self.real_invalid_mismatch_vector_path,
            self.real_v2_invalid_mismatch_vector_path,
            self.real_v3_valid_vector_path,
            self.real_v3_invalid_mismatch_vector_path,
            self.real_invalid_queue_prefix_mismatch_vector_path,
            self.real_v2_invalid_queue_prefix_mismatch_vector_path,
            self.real_v3_invalid_queue_prefix_mismatch_vector_path,
            self.real_invalid_withdrawal_root_mismatch_vector_path,
            self.real_v2_invalid_withdrawal_root_mismatch_vector_path,
            self.real_v3_invalid_withdrawal_root_mismatch_vector_path,
            self.real_invalid_corrupt_vector_path,
            self.real_v2_invalid_corrupt_vector_path,
            self.real_v3_invalid_corrupt_vector_path,
        ):
            if not required_path.exists():
                raise SkipTest(f"toy proof vector is missing: {required_path}")
        smoke = subprocess.run(
            [sys.executable, str(self.zk_runner), "verify"],
            input=b"{}\n",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.zk_demo_dir,
            check=False,
        )
        if smoke.returncode != 0:
            raise SkipTest(f"toy zk verifier helper is unavailable: {smoke.stderr.decode('utf-8', errors='replace').strip()}")

    def run_tool(self, mode, request):
        completed = subprocess.run(
            [sys.executable, str(self.zk_runner), mode],
            input=(json.dumps(request) + "\n").encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.zk_demo_dir,
            check=False,
        )
        if completed.returncode != 0:
            raise AssertionError(
                f"{mode} helper failed with code {completed.returncode}: "
                f"{completed.stderr.decode('utf-8', errors='replace')}"
            )
        return json.loads(completed.stdout.decode("utf-8"))

    def run_test(self):
        node = self.nodes[0]
        node.generatetoaddress(101, node.getnewaddress())

        toy_supported = get_supported_profile(node, "gnark_groth16_toy_batch_transition_v1")
        native_toy_supported = get_supported_profile(node, "native_blst_groth16_toy_batch_transition_v1")
        real_supported = get_supported_profile(node, "groth16_bls12_381_poseidon_v1")
        real_v2_supported = get_supported_profile(node, "groth16_bls12_381_poseidon_v2")
        real_v3_supported = get_supported_profile(node, "groth16_bls12_381_poseidon_v3")
        assert_equal(toy_supported["batch_verifier_mode"], "gnark_groth16_toy_batch_transition_v1")
        assert_equal(toy_supported["verifier_backend"], "external_gnark_command")
        assert_equal(toy_supported["supports_external_prover"], True)
        assert_equal(toy_supported["batch_queue_binding_mode"], "local_prefix_consensus_count_only")
        assert_equal(toy_supported["batch_withdrawal_binding_mode"], "accepted_root_generic")
        assert_equal(toy_supported["force_exit_request_mode"], "enabled_local_queue_consensus")
        assert_equal(toy_supported["verifier_assets"]["required"], True)
        assert_equal(toy_supported["verifier_assets"]["available"], True)
        assert_equal(toy_supported["verifier_assets"]["prover_assets_present"], True)
        toy_external_backend_ready = toy_supported["verifier_assets"]["backend_ready"]
        if toy_external_backend_ready:
            assert_equal(toy_supported["verifier_assets"]["verifier_command_configured"], True)
            assert_equal(toy_supported["verifier_assets"]["prover_command_configured"], True)
        else:
            assert_equal(toy_supported["verifier_assets"]["status"], "boost process support not built")
        assert_equal(toy_supported["verifier_assets"]["profile_manifest_parsed"], True)
        assert_equal(toy_supported["verifier_assets"]["profile_manifest_name_matches"], True)
        assert_equal(toy_supported["verifier_assets"]["profile_manifest_backend_matches"], True)
        assert_equal(toy_supported["verifier_assets"]["profile_manifest_key_layout_matches"], True)
        assert_equal(toy_supported["verifier_assets"]["profile_manifest_tuple_matches"], True)
        assert_equal(toy_supported["verifier_assets"]["profile_manifest_public_inputs_match"], True)
        assert_equal(toy_supported["verifier_assets"]["profile_manifest_name"], "gnark_groth16_toy_batch_transition_v1")
        assert_equal(toy_supported["verifier_assets"]["profile_manifest_backend"], "external_gnark_command")
        assert_equal(toy_supported["verifier_assets"]["profile_manifest_public_input_count"], 7)
        assert_equal(toy_supported["verifier_assets"]["valid_proof_vectors_present"], True)
        assert_equal(toy_supported["verifier_assets"]["invalid_proof_vectors_present"], True)
        assert_equal(toy_supported["verifier_assets"]["valid_proof_vector_count"], 1)
        assert_equal(toy_supported["verifier_assets"]["invalid_proof_vector_count"], 2)
        assert_equal(native_toy_supported["batch_verifier_mode"], "native_blst_groth16_toy_batch_transition_v1")
        assert_equal(native_toy_supported["verifier_backend"], "native_blst_groth16")
        assert_equal(native_toy_supported["supports_external_prover"], False)
        assert_equal(native_toy_supported["batch_queue_binding_mode"], "local_prefix_consensus_count_only")
        assert_equal(native_toy_supported["batch_withdrawal_binding_mode"], "accepted_root_generic")
        assert_equal(native_toy_supported["force_exit_request_mode"], "enabled_local_queue_consensus")
        assert_equal(native_toy_supported["verifier_assets"]["required"], True)
        assert_equal(native_toy_supported["verifier_assets"]["available"], True)
        assert_equal(native_toy_supported["verifier_assets"]["backend_ready"], True)
        assert_equal(native_toy_supported["verifier_assets"]["native_backend_available"], True)
        assert_equal(native_toy_supported["verifier_assets"]["native_backend_self_test_passed"], True)
        assert_equal(native_toy_supported["verifier_assets"]["profile_manifest_parsed"], True)
        assert_equal(native_toy_supported["verifier_assets"]["profile_manifest_name_matches"], True)
        assert_equal(native_toy_supported["verifier_assets"]["profile_manifest_backend_matches"], True)
        assert_equal(native_toy_supported["verifier_assets"]["profile_manifest_key_layout_matches"], True)
        assert_equal(native_toy_supported["verifier_assets"]["profile_manifest_tuple_matches"], True)
        assert_equal(native_toy_supported["verifier_assets"]["profile_manifest_public_inputs_match"], True)
        assert_equal(native_toy_supported["verifier_assets"]["profile_manifest_name"], "native_blst_groth16_toy_batch_transition_v1")
        assert_equal(native_toy_supported["verifier_assets"]["profile_manifest_backend"], "native_blst_groth16")
        assert_equal(native_toy_supported["verifier_assets"]["profile_manifest_public_input_count"], 7)
        assert_equal(native_toy_supported["verifier_assets"]["valid_proof_vectors_present"], True)
        assert_equal(native_toy_supported["verifier_assets"]["invalid_proof_vectors_present"], True)
        assert_equal(native_toy_supported["verifier_assets"]["valid_proof_vector_count"], 1)
        assert_equal(native_toy_supported["verifier_assets"]["invalid_proof_vector_count"], 2)
        assert_equal(real_supported["batch_verifier_mode"], "groth16_bls12_381_poseidon_v1")
        assert_equal(real_supported["verifier_backend"], "native_blst_groth16")
        assert_equal(real_supported["supports_external_prover"], True)
        assert_equal(real_supported["deposit_admission_mode"], "single_pending_entry_scalar_field_experimental")
        assert_equal(real_supported["batch_queue_binding_mode"], "local_prefix_consensus_single_deposit_entry_experimental")
        assert_equal(real_supported["batch_withdrawal_binding_mode"], "accepted_root_single_leaf_experimental")
        assert_equal(real_supported["force_exit_request_mode"], "disabled_pending_real_queue_entry_proof")
        assert_equal(real_supported["verifier_assets"]["required"], True)
        assert_equal(real_supported["verifier_assets"]["available"], True)
        assert_equal(real_supported["verifier_assets"]["prover_assets_present"], self.real_proving_key_path.exists())
        assert_equal(real_supported["verifier_assets"]["backend_ready"], True)
        assert_equal(real_supported["verifier_assets"]["native_backend_available"], True)
        assert_equal(real_supported["verifier_assets"]["native_backend_self_test_passed"], True)
        assert_equal(real_supported["verifier_assets"]["profile_manifest_parsed"], True)
        assert_equal(real_supported["verifier_assets"]["profile_manifest_name_matches"], True)
        assert_equal(real_supported["verifier_assets"]["profile_manifest_backend_matches"], True)
        assert_equal(real_supported["verifier_assets"]["profile_manifest_key_layout_matches"], True)
        assert_equal(real_supported["verifier_assets"]["profile_manifest_tuple_matches"], True)
        assert_equal(real_supported["verifier_assets"]["profile_manifest_public_inputs_match"], True)
        assert_equal(real_supported["verifier_assets"]["groth16_commitment_extension_matches_profile"], True)
        assert_equal(real_supported["verifier_assets"]["profile_manifest_name"], "groth16_bls12_381_poseidon_v1")
        assert_equal(real_supported["verifier_assets"]["profile_manifest_backend"], "native_blst_groth16")
        assert_equal(real_supported["verifier_assets"]["profile_manifest_public_input_count"], 11)
        assert_equal(real_supported["verifier_assets"]["expected_groth16_commitment_extension_count"], 0)
        assert_equal(real_supported["verifier_assets"]["verifying_key_groth16_commitment_extension_count"], 0)
        assert_equal(real_supported["verifier_assets"]["valid_proof_vectors_present"], True)
        assert_equal(real_supported["verifier_assets"]["invalid_proof_vectors_present"], True)
        assert_equal(real_supported["verifier_assets"]["valid_proof_vector_count"], 1)
        assert_equal(real_supported["verifier_assets"]["invalid_proof_vector_count"], 4)
        assert_equal(real_v2_supported["batch_verifier_mode"], "groth16_bls12_381_poseidon_v2")
        assert_equal(real_v2_supported["verifier_backend"], "native_blst_groth16")
        assert_equal(real_v2_supported["supports_external_prover"], True)
        assert_equal(real_v2_supported["deposit_admission_mode"], "enabled_local_queue_consensus")
        assert_equal(real_v2_supported["derived_public_input_mode"], "helper_derives_queue_withdrawal_and_da_bindings")
        assert_equal(
            real_v2_supported["external_prover_request_mode"],
            "current_chainstate_bound_explicit_witness_vectors",
        )
        assert_equal(real_v2_supported["external_prover_requires_current_chainstate"], True)
        assert_equal(real_v2_supported["external_prover_requires_explicit_witness_vectors"], True)
        assert_equal(real_v2_supported["queue_binding_proven_in_circuit"], False)
        assert_equal(real_v2_supported["withdrawal_binding_proven_in_circuit"], False)
        assert_equal(real_v2_supported["data_binding_proven_in_circuit"], False)
        assert_equal(real_v2_supported["in_circuit_binding_blocker"], "superseded_by_canonical_v3_target")
        assert_equal(
            real_v2_supported["batch_queue_binding_mode"],
            "local_prefix_consensus_committed_public_inputs",
        )
        assert_equal(
            real_v2_supported["batch_withdrawal_binding_mode"],
            "accepted_root_generic_public_input",
        )
        assert_equal(real_v2_supported["force_exit_request_mode"], "enabled_local_queue_consensus")
        assert_equal(real_v2_supported["verifier_assets"]["required"], True)
        assert_equal(real_v2_supported["verifier_assets"]["available"], True)
        assert_equal(real_v2_supported["verifier_assets"]["prover_assets_present"], self.real_v2_proving_key_path.exists())
        assert_equal(real_v2_supported["verifier_assets"]["backend_ready"], True)
        assert_equal(real_v2_supported["verifier_assets"]["native_backend_available"], True)
        assert_equal(real_v2_supported["verifier_assets"]["native_backend_self_test_passed"], True)
        assert_equal(real_v2_supported["verifier_assets"]["profile_manifest_parsed"], True)
        assert_equal(real_v2_supported["verifier_assets"]["profile_manifest_name_matches"], True)
        assert_equal(real_v2_supported["verifier_assets"]["profile_manifest_backend_matches"], True)
        assert_equal(real_v2_supported["verifier_assets"]["profile_manifest_key_layout_matches"], True)
        assert_equal(real_v2_supported["verifier_assets"]["profile_manifest_tuple_matches"], True)
        assert_equal(real_v2_supported["verifier_assets"]["profile_manifest_public_inputs_match"], True)
        assert_equal(real_v2_supported["verifier_assets"]["groth16_commitment_extension_matches_profile"], True)
        assert_equal(real_v2_supported["verifier_assets"]["profile_manifest_name"], "groth16_bls12_381_poseidon_v2")
        assert_equal(real_v2_supported["verifier_assets"]["profile_manifest_backend"], "native_blst_groth16")
        assert_equal(real_v2_supported["verifier_assets"]["profile_manifest_public_input_count"], 16)
        assert_equal(real_v2_supported["verifier_assets"]["expected_groth16_commitment_extension_count"], 0)
        assert_equal(real_v2_supported["verifier_assets"]["verifying_key_groth16_commitment_extension_count"], 0)
        assert_equal(real_v2_supported["verifier_assets"]["valid_proof_vectors_present"], True)
        assert_equal(real_v2_supported["verifier_assets"]["invalid_proof_vectors_present"], True)
        assert_equal(real_v2_supported["verifier_assets"]["valid_proof_vector_count"], 1)
        assert_equal(real_v2_supported["verifier_assets"]["invalid_proof_vector_count"], 4)
        assert_equal(real_v3_supported["batch_verifier_mode"], "groth16_bls12_381_poseidon_v3")
        assert_equal(real_v3_supported["verifier_backend"], "native_blst_groth16")
        assert_equal(real_v3_supported["supports_external_prover"], True)
        assert_equal(real_v3_supported["deposit_admission_mode"], "enabled_local_queue_consensus")
        assert_equal(real_v3_supported["derived_public_input_mode"], "helper_derives_queue_withdrawal_and_da_bindings")
        assert_equal(
            real_v3_supported["external_prover_request_mode"],
            "current_chainstate_bound_explicit_witness_vectors",
        )
        assert_equal(real_v3_supported["external_prover_requires_current_chainstate"], True)
        assert_equal(real_v3_supported["external_prover_requires_explicit_witness_vectors"], True)
        assert_equal(real_v3_supported["queue_binding_proven_in_circuit"], True)
        assert_equal(real_v3_supported["withdrawal_binding_proven_in_circuit"], True)
        assert_equal(real_v3_supported["data_binding_proven_in_circuit"], True)
        assert_equal(real_v3_supported["in_circuit_binding_blocker"], "none")
        assert_equal(real_v3_supported["committed_queue_witness_limit"], 2)
        assert_equal(real_v3_supported["committed_withdrawal_witness_limit"], 2)
        assert_equal(real_v3_supported["committed_data_chunk_witness_limit"], 2)
        assert_equal(
            real_v3_supported["batch_queue_binding_mode"],
            "bounded_in_circuit_committed_public_inputs_experimental",
        )
        assert_equal(
            real_v3_supported["batch_withdrawal_binding_mode"],
            "bounded_in_circuit_committed_public_input_experimental",
        )
        assert_equal(real_v3_supported["force_exit_request_mode"], "enabled_local_queue_consensus")
        assert_equal(real_v3_supported["verifier_assets"]["required"], True)
        assert_equal(real_v3_supported["verifier_assets"]["available"], True)
        assert_equal(real_v3_supported["verifier_assets"]["prover_assets_present"], self.real_v3_proving_key_path.exists())
        assert_equal(real_v3_supported["verifier_assets"]["backend_ready"], True)
        assert_equal(real_v3_supported["verifier_assets"]["native_backend_available"], True)
        assert_equal(real_v3_supported["verifier_assets"]["native_backend_self_test_passed"], True)
        assert_equal(real_v3_supported["verifier_assets"]["profile_manifest_parsed"], True)
        assert_equal(real_v3_supported["verifier_assets"]["profile_manifest_name_matches"], True)
        assert_equal(real_v3_supported["verifier_assets"]["profile_manifest_backend_matches"], True)
        assert_equal(real_v3_supported["verifier_assets"]["profile_manifest_key_layout_matches"], True)
        assert_equal(real_v3_supported["verifier_assets"]["profile_manifest_tuple_matches"], True)
        assert_equal(real_v3_supported["verifier_assets"]["profile_manifest_public_inputs_match"], True)
        assert_equal(real_v3_supported["verifier_assets"]["groth16_commitment_extension_matches_profile"], True)
        assert_equal(real_v3_supported["verifier_assets"]["profile_manifest_name"], "groth16_bls12_381_poseidon_v3")
        assert_equal(real_v3_supported["verifier_assets"]["profile_manifest_backend"], "native_blst_groth16")
        assert_equal(real_v3_supported["verifier_assets"]["profile_manifest_public_input_count"], 16)
        assert_equal(real_v3_supported["verifier_assets"]["expected_groth16_commitment_extension_count"], 1)
        assert_equal(real_v3_supported["verifier_assets"]["verifying_key_groth16_commitment_extension_count"], 1)
        assert_equal(real_v3_supported["verifier_assets"]["valid_proof_vectors_present"], True)
        assert_equal(real_v3_supported["verifier_assets"]["invalid_proof_vectors_present"], True)
        assert_equal(real_v3_supported["verifier_assets"]["valid_proof_vector_count"], 1)
        assert_equal(real_v3_supported["verifier_assets"]["invalid_proof_vector_count"], 4)

        self.log.info("Replaying committed proof vectors through consensus.")
        valid_vector = load_json(self.valid_vector_path)
        mismatch_vector = load_json(self.invalid_mismatch_vector_path)
        corrupt_vector = load_json(self.invalid_corrupt_vector_path)
        native_valid_vector = load_json(self.native_valid_vector_path)
        native_mismatch_vector = load_json(self.native_invalid_mismatch_vector_path)
        native_corrupt_vector = load_json(self.native_invalid_corrupt_vector_path)
        real_valid_vector = load_json(self.real_valid_vector_path)
        real_v2_valid_vector = load_json(self.real_v2_valid_vector_path)
        real_v3_valid_vector = load_json(self.real_v3_valid_vector_path)
        real_mismatch_vector = load_json(self.real_invalid_mismatch_vector_path)
        real_v2_mismatch_vector = load_json(self.real_v2_invalid_mismatch_vector_path)
        real_v3_mismatch_vector = load_json(self.real_v3_invalid_mismatch_vector_path)
        real_queue_prefix_mismatch_vector = load_json(self.real_invalid_queue_prefix_mismatch_vector_path)
        real_v2_queue_prefix_mismatch_vector = load_json(self.real_v2_invalid_queue_prefix_mismatch_vector_path)
        real_v3_queue_prefix_mismatch_vector = load_json(self.real_v3_invalid_queue_prefix_mismatch_vector_path)
        real_withdrawal_root_mismatch_vector = load_json(self.real_invalid_withdrawal_root_mismatch_vector_path)
        real_v2_withdrawal_root_mismatch_vector = load_json(self.real_v2_invalid_withdrawal_root_mismatch_vector_path)
        real_v3_withdrawal_root_mismatch_vector = load_json(self.real_v3_invalid_withdrawal_root_mismatch_vector_path)
        real_corrupt_vector = load_json(self.real_invalid_corrupt_vector_path)
        real_v2_corrupt_vector = load_json(self.real_v2_invalid_corrupt_vector_path)
        real_v3_corrupt_vector = load_json(self.real_v3_invalid_corrupt_vector_path)
        assert_equal(valid_vector["expected_result"], "accept_in_demo_verifier")
        assert_equal(mismatch_vector["expected_result"], "reject")
        assert_equal(corrupt_vector["expected_result"], "reject")
        assert_equal(native_valid_vector["expected_result"], "accept_in_native_verifier")
        assert_equal(native_mismatch_vector["expected_result"], "reject")
        assert_equal(native_corrupt_vector["expected_result"], "reject")
        assert_equal(real_valid_vector["expected_result"], "accept_in_native_verifier")
        assert_equal(real_mismatch_vector["expected_result"], "reject")
        assert_equal(real_queue_prefix_mismatch_vector["expected_result"], "reject")
        assert_equal(real_withdrawal_root_mismatch_vector["expected_result"], "reject")
        assert_equal(real_corrupt_vector["expected_result"], "reject")
        assert_equal(real_v2_valid_vector["expected_result"], "accept_in_native_verifier")
        assert_equal(real_v2_mismatch_vector["expected_result"], "reject")
        assert_equal(real_v2_queue_prefix_mismatch_vector["expected_result"], "reject")
        assert_equal(real_v2_withdrawal_root_mismatch_vector["expected_result"], "reject")
        assert_equal(real_v2_corrupt_vector["expected_result"], "reject")
        assert_equal(real_v3_valid_vector["expected_result"], "accept_in_native_verifier")
        assert_equal(real_v3_mismatch_vector["expected_result"], "reject")
        assert_equal(real_v3_queue_prefix_mismatch_vector["expected_result"], "reject")
        assert_equal(real_v3_withdrawal_root_mismatch_vector["expected_result"], "reject")
        assert_equal(real_v3_corrupt_vector["expected_result"], "reject")

        self.log.info("Replaying the committed real vector through the external verify helper too.")
        real_verify_request = {
            "profile_name": "groth16_bls12_381_poseidon_v1",
            "artifact_dir": str(self.real_artifact_dir),
            "sidechain_id": int(real_valid_vector["public_inputs"]["sidechain_id"]),
            "public_inputs": {
                "batch_number": int(real_valid_vector["public_inputs"]["batch_number"]),
                "prior_state_root": real_valid_vector["public_inputs"]["prior_state_root"],
                "new_state_root": real_valid_vector["public_inputs"]["new_state_root"],
                "l1_message_root_before": real_valid_vector["public_inputs"]["l1_message_root_before"],
                "l1_message_root_after": real_valid_vector["public_inputs"]["l1_message_root_after"],
                "consumed_queue_messages": int(real_valid_vector["public_inputs"]["consumed_queue_messages"]),
                "queue_prefix_commitment": real_valid_vector["public_inputs"]["queue_prefix_commitment"],
                "withdrawal_root": real_valid_vector["public_inputs"]["withdrawal_root"],
                "data_root": real_valid_vector["public_inputs"]["data_root"],
                "data_size": int(real_valid_vector["public_inputs"]["data_size"]),
            },
            "proof_bytes_hex": real_valid_vector["proof_bytes_hex"],
        }
        real_verify_result = self.run_tool("verify", real_verify_request)
        assert_equal(real_verify_result["ok"], True)

        real_verify_mismatch_request = dict(real_verify_request)
        real_verify_mismatch_request["public_inputs"] = dict(real_verify_request["public_inputs"])
        real_verify_mismatch_request["public_inputs"]["new_state_root"] = real_mismatch_vector["public_inputs"]["new_state_root"]
        real_verify_mismatch_result = self.run_tool("verify", real_verify_mismatch_request)
        assert_equal(real_verify_mismatch_result["ok"], False)
        assert real_verify_mismatch_result["error"]

        self.log.info("Replaying the committed decomposed real vector through the external verify helper too.")
        real_v2_verify_request = {
            "profile_name": "groth16_bls12_381_poseidon_v2",
            "artifact_dir": str(self.real_v2_artifact_dir),
            "sidechain_id": int(real_v2_valid_vector["public_inputs"]["sidechain_id"]),
            "public_inputs": {
                "batch_number": int(real_v2_valid_vector["public_inputs"]["batch_number"]),
                "prior_state_root": real_v2_valid_vector["public_inputs"]["prior_state_root"],
                "new_state_root": real_v2_valid_vector["public_inputs"]["new_state_root"],
                "l1_message_root_before": combine_128_bit_limbs(
                    real_v2_valid_vector["public_inputs"]["l1_message_root_before_lo"],
                    real_v2_valid_vector["public_inputs"]["l1_message_root_before_hi"],
                ),
                "l1_message_root_after": combine_128_bit_limbs(
                    real_v2_valid_vector["public_inputs"]["l1_message_root_after_lo"],
                    real_v2_valid_vector["public_inputs"]["l1_message_root_after_hi"],
                ),
                "consumed_queue_messages": int(real_v2_valid_vector["public_inputs"]["consumed_queue_messages"]),
                "queue_prefix_commitment": combine_128_bit_limbs(
                    real_v2_valid_vector["public_inputs"]["queue_prefix_commitment_lo"],
                    real_v2_valid_vector["public_inputs"]["queue_prefix_commitment_hi"],
                ),
                "withdrawal_root": combine_128_bit_limbs(
                    real_v2_valid_vector["public_inputs"]["withdrawal_root_lo"],
                    real_v2_valid_vector["public_inputs"]["withdrawal_root_hi"],
                ),
                "data_root": combine_128_bit_limbs(
                    real_v2_valid_vector["public_inputs"]["data_root_lo"],
                    real_v2_valid_vector["public_inputs"]["data_root_hi"],
                ),
                "data_size": int(real_v2_valid_vector["public_inputs"]["data_size"]),
            },
            "proof_bytes_hex": real_v2_valid_vector["proof_bytes_hex"],
        }
        real_v2_verify_result = self.run_tool("verify", real_v2_verify_request)
        assert_equal(real_v2_verify_result["ok"], True)

        real_v2_verify_mismatch_request = dict(real_v2_verify_request)
        real_v2_verify_mismatch_request["public_inputs"] = dict(real_v2_verify_request["public_inputs"])
        real_v2_verify_mismatch_request["public_inputs"]["new_state_root"] = real_v2_mismatch_vector["public_inputs"]["new_state_root"]
        real_v2_verify_mismatch_result = self.run_tool("verify", real_v2_verify_mismatch_request)
        assert_equal(real_v2_verify_mismatch_result["ok"], False)
        assert real_v2_verify_mismatch_result["error"]

        self.log.info("Replaying the committed canonical v3 real vector through the external verify helper too.")
        real_v3_verify_request = {
            "profile_name": "groth16_bls12_381_poseidon_v3",
            "artifact_dir": str(self.real_v3_artifact_dir),
            "sidechain_id": int(real_v3_valid_vector["public_inputs"]["sidechain_id"]),
            "public_inputs": {
                "batch_number": int(real_v3_valid_vector["public_inputs"]["batch_number"]),
                "prior_state_root": real_v3_valid_vector["public_inputs"]["prior_state_root"],
                "new_state_root": real_v3_valid_vector["public_inputs"]["new_state_root"],
                "l1_message_root_before": combine_128_bit_limbs(
                    real_v3_valid_vector["public_inputs"]["l1_message_root_before_lo"],
                    real_v3_valid_vector["public_inputs"]["l1_message_root_before_hi"],
                ),
                "l1_message_root_after": combine_128_bit_limbs(
                    real_v3_valid_vector["public_inputs"]["l1_message_root_after_lo"],
                    real_v3_valid_vector["public_inputs"]["l1_message_root_after_hi"],
                ),
                "consumed_queue_messages": int(real_v3_valid_vector["public_inputs"]["consumed_queue_messages"]),
                "queue_prefix_commitment": combine_128_bit_limbs(
                    real_v3_valid_vector["public_inputs"]["queue_prefix_commitment_lo"],
                    real_v3_valid_vector["public_inputs"]["queue_prefix_commitment_hi"],
                ),
                "withdrawal_root": combine_128_bit_limbs(
                    real_v3_valid_vector["public_inputs"]["withdrawal_root_lo"],
                    real_v3_valid_vector["public_inputs"]["withdrawal_root_hi"],
                ),
                "data_root": combine_128_bit_limbs(
                    real_v3_valid_vector["public_inputs"]["data_root_lo"],
                    real_v3_valid_vector["public_inputs"]["data_root_hi"],
                ),
                "data_size": int(real_v3_valid_vector["public_inputs"]["data_size"]),
            },
            "proof_bytes_hex": real_v3_valid_vector["proof_bytes_hex"],
        }
        real_v3_verify_result = self.run_tool("verify", real_v3_verify_request)
        assert_equal(real_v3_verify_result["ok"], True)

        real_v3_verify_mismatch_request = dict(real_v3_verify_request)
        real_v3_verify_mismatch_request["public_inputs"] = dict(real_v3_verify_request["public_inputs"])
        real_v3_verify_mismatch_request["public_inputs"]["new_state_root"] = real_v3_mismatch_vector["public_inputs"]["new_state_root"]
        real_v3_verify_mismatch_result = self.run_tool("verify", real_v3_verify_mismatch_request)
        assert_equal(real_v3_verify_mismatch_result["ok"], False)
        assert real_v3_verify_mismatch_result["error"]
        refund_address = node.getnewaddress()
        native_toy_vectors_da_compatible = pad_field_hex(native_valid_vector["public_inputs"]["data_root"]) == ("00" * 32)

        if toy_external_backend_ready:
            vector_sidechain_id = int(valid_vector["public_inputs"]["sidechain_id"])
            vector_prior_state_root = pad_field_hex(valid_vector["public_inputs"]["prior_state_root"])
            vector_config = build_register_config(
                toy_supported,
                initial_state_root=vector_prior_state_root,
                initial_withdrawal_root=vector_prior_state_root,
            )
            node.sendvaliditysidechainregister(vector_sidechain_id, vector_config)
            node.generate(1)

            queued_entries = []
            for index in range(3):
                deposit_res = node.sendvaliditydeposit(
                    vector_sidechain_id,
                    hex_uint(0x3000 + index),
                    {"address": refund_address},
                    1,
                    index + 1,
                )
                queued_entries.append({
                    "queue_index": index,
                    "message_kind": 1,
                    "message_id": deposit_res["deposit_id"],
                    "message_hash": deposit_res["deposit_message_hash"],
                })
            node.generate(1)

            vector_sidechain = get_sidechain_info(node, vector_sidechain_id)
            assert_equal(vector_sidechain["queue_state"]["pending_message_count"], 3)

            valid_public_inputs = {
                "batch_number": int(valid_vector["public_inputs"]["batch_number"]),
                "prior_state_root": vector_prior_state_root,
                "new_state_root": pad_field_hex(valid_vector["public_inputs"]["new_state_root"]),
                "consumed_queue_messages": int(valid_vector["public_inputs"]["consumed_queue_messages"]),
                "withdrawal_root": pad_field_hex(valid_vector["public_inputs"]["withdrawal_root"]),
                "data_root": pad_field_hex(valid_vector["public_inputs"]["data_root"]),
                "data_size": 0,
            }
            mismatch_public_inputs = dict(valid_public_inputs)
            mismatch_public_inputs["new_state_root"] = pad_field_hex(mismatch_vector["public_inputs"]["new_state_root"])

            assert_raises_rpc_error_any(
                -8,
                ["pairing doesn't match", "invalid infinity point encoding"],
                node.sendvaliditybatch,
                vector_sidechain_id,
                mismatch_public_inputs,
                mismatch_vector["proof_bytes_hex"],
            )
            assert_raises_rpc_error_any(
                -8,
                ["pairing doesn't match", "invalid infinity point encoding"],
                node.sendvaliditybatch,
                vector_sidechain_id,
                valid_public_inputs,
                corrupt_vector["proof_bytes_hex"],
            )

            vector_batch_res = node.sendvaliditybatch(
                vector_sidechain_id,
                valid_public_inputs,
                valid_vector["proof_bytes_hex"],
            )
            assert_equal(vector_batch_res["auto_scaffold_proof"], False)
            assert_equal(vector_batch_res["auto_external_proof"], False)
            node.generate(1)

            vector_sidechain = get_sidechain_info(node, vector_sidechain_id)
            assert_equal(vector_sidechain["latest_batch_number"], valid_public_inputs["batch_number"])
            assert_equal(vector_sidechain["current_state_root"], valid_public_inputs["new_state_root"])
            assert_equal(vector_sidechain["current_withdrawal_root"], valid_public_inputs["withdrawal_root"])
            assert_equal(vector_sidechain["current_data_root"], valid_public_inputs["data_root"])
            assert_equal(vector_sidechain["queue_state"]["head_index"], 3)
            assert_equal(vector_sidechain["queue_state"]["pending_message_count"], 0)
            assert vector_sidechain["accepted_batches"][0]["proof_size"] > 0
        else:
            self.log.info("Skipping external toy verifier coverage because boost::process support is not built.")

        if native_toy_vectors_da_compatible:
            self.log.info("Replaying committed native blst proof vectors through the in-process verifier.")
            native_sidechain_id = int(native_valid_vector["public_inputs"]["sidechain_id"])
            native_prior_state_root = pad_field_hex(native_valid_vector["public_inputs"]["prior_state_root"])
            native_config = build_register_config(
                native_toy_supported,
                initial_state_root=native_prior_state_root,
                initial_withdrawal_root=native_prior_state_root,
            )
            node.sendvaliditysidechainregister(native_sidechain_id, native_config)
            node.generate(1)

            native_queued_entries = []
            for index in range(3):
                deposit_res = node.sendvaliditydeposit(
                    native_sidechain_id,
                    hex_uint(0x4000 + index),
                    {"address": refund_address},
                    1,
                    index + 1,
                )
                native_queued_entries.append({
                    "queue_index": index,
                    "message_kind": 1,
                    "message_id": deposit_res["deposit_id"],
                    "message_hash": deposit_res["deposit_message_hash"],
                })
            node.generate(1)

            native_sidechain = get_sidechain_info(node, native_sidechain_id)
            assert_equal(native_sidechain["queue_state"]["pending_message_count"], 3)
            native_l1_message_root_before = native_sidechain["queue_state"]["root"]
            native_l1_message_root_after = compute_consumed_queue_root(
                native_sidechain_id,
                native_l1_message_root_before,
                native_queued_entries,
            )

            native_valid_public_inputs = {
                "batch_number": int(native_valid_vector["public_inputs"]["batch_number"]),
                "prior_state_root": native_prior_state_root,
                "new_state_root": pad_field_hex(native_valid_vector["public_inputs"]["new_state_root"]),
                "l1_message_root_before": native_l1_message_root_before,
                "l1_message_root_after": native_l1_message_root_after,
                "consumed_queue_messages": int(native_valid_vector["public_inputs"]["consumed_queue_messages"]),
                "withdrawal_root": pad_field_hex(native_valid_vector["public_inputs"]["withdrawal_root"]),
                "data_root": pad_field_hex(native_valid_vector["public_inputs"]["data_root"]),
                "data_size": 0,
            }
            native_mismatch_public_inputs = dict(native_valid_public_inputs)
            native_mismatch_public_inputs["new_state_root"] = pad_field_hex(native_mismatch_vector["public_inputs"]["new_state_root"])

            assert_raises_rpc_error(
                -8,
                "Groth16 pairing doesn't match",
                node.sendvaliditybatch,
                native_sidechain_id,
                native_mismatch_public_inputs,
                native_mismatch_vector["proof_bytes_hex"],
            )
            assert_raises_rpc_error(
                -8,
                "Groth16 pairing doesn't match",
                node.sendvaliditybatch,
                native_sidechain_id,
                native_valid_public_inputs,
                native_corrupt_vector["proof_bytes_hex"],
            )

            native_batch_res = node.sendvaliditybatch(
                native_sidechain_id,
                native_valid_public_inputs,
                native_valid_vector["proof_bytes_hex"],
            )
            assert_equal(native_batch_res["auto_scaffold_proof"], False)
            assert_equal(native_batch_res["auto_external_proof"], False)
            assert_equal(native_batch_res["auto_proof_backend"], "none")
            node.generate(1)

            native_sidechain = get_sidechain_info(node, native_sidechain_id)
            assert_equal(native_sidechain["batch_verifier_mode"], "native_blst_groth16_toy_batch_transition_v1")
            assert_equal(native_sidechain["latest_batch_number"], native_valid_public_inputs["batch_number"])
            assert_equal(native_sidechain["current_state_root"], native_valid_public_inputs["new_state_root"])
            assert_equal(native_sidechain["current_withdrawal_root"], native_valid_public_inputs["withdrawal_root"])
            assert_equal(native_sidechain["current_data_root"], native_valid_public_inputs["data_root"])
            assert_equal(native_sidechain["queue_state"]["head_index"], 3)
            assert_equal(native_sidechain["queue_state"]["pending_message_count"], 0)
            assert native_sidechain["accepted_batches"][0]["proof_size"] > 0
        else:
            self.log.info("Skipping committed native toy proof-vector replay because the bundle predates DA root enforcement.")

        if toy_external_backend_ready:
            self.log.info("Registering a toy Groth16 profile sidechain and accepting an externally-proven batch.")
            sidechain_id = 12
            initial_state_root = hex_uint(1000)
            config = build_register_config(
                toy_supported,
                initial_state_root=initial_state_root,
                initial_withdrawal_root=hex_uint(1000),
            )
            node.sendvaliditysidechainregister(sidechain_id, config)
            node.generate(1)

            public_inputs = {
                "batch_number": sidechain_id + 1,
                "prior_state_root": initial_state_root,
                "new_state_root": initial_state_root,
                "l1_message_root_before": "00" * 32,
                "l1_message_root_after": "00" * 32,
                "consumed_queue_messages": 0,
                "withdrawal_root": hex_uint(1011),
                "data_root": "00" * 32,
                "data_size": 0,
            }

            batch_res = node.sendvaliditybatch(sidechain_id, public_inputs)
            assert_equal(batch_res["auto_scaffold_proof"], False)
            assert_equal(batch_res["auto_external_proof"], True)
            assert_equal(batch_res["auto_proof_backend"], "external_command")
            node.generate(1)

            sidechain = get_sidechain_info(node, sidechain_id)
            assert_equal(sidechain["latest_batch_number"], sidechain_id + 1)
            assert_equal(sidechain["current_state_root"], public_inputs["new_state_root"])
            assert_equal(sidechain["current_withdrawal_root"], public_inputs["withdrawal_root"])
            assert_equal(sidechain["current_data_root"], public_inputs["data_root"])
            assert sidechain["accepted_batches"][0]["proof_size"] > 0

            self.log.info("Generating a valid proof externally, corrupting it, and confirming verifier rejection.")
            invalid_sidechain_id = 13
            invalid_initial_state_root = hex_uint(2000)
            invalid_config = build_register_config(
                toy_supported,
                initial_state_root=invalid_initial_state_root,
                initial_withdrawal_root=hex_uint(2000),
            )
            node.sendvaliditysidechainregister(invalid_sidechain_id, invalid_config)
            node.generate(1)

            invalid_public_inputs = {
                "batch_number": invalid_sidechain_id + 1,
                "prior_state_root": invalid_initial_state_root,
                "new_state_root": invalid_initial_state_root,
                "l1_message_root_before": "00" * 32,
                "l1_message_root_after": "00" * 32,
                "consumed_queue_messages": 0,
                "withdrawal_root": hex_uint(2011),
                "data_root": "00" * 32,
                "data_size": 0,
            }
            request = {
                "profile_name": "gnark_groth16_toy_batch_transition_v1",
                "artifact_dir": str(self.artifact_root / "validitysidechain" / "gnark_groth16_toy_batch_transition_v1"),
                "sidechain_id": invalid_sidechain_id,
                "public_inputs": invalid_public_inputs,
            }
            proof_result = self.run_tool("prove", request)
            assert_equal(proof_result["ok"], True)
            proof_hex = proof_result["proof_bytes_hex"]
            corrupted_proof_hex = proof_hex[:-2] + ("00" if proof_hex[-2:] != "00" else "01")

            assert_raises_rpc_error_any(
                -8,
                ["pairing doesn't match", "invalid infinity point encoding"],
                node.sendvaliditybatch,
                invalid_sidechain_id,
                invalid_public_inputs,
                corrupted_proof_hex,
            )
        else:
            self.log.info("Skipping external auto-prover toy coverage because boost::process support is not built.")

        self.log.info("Replaying committed real proof vectors through the native verifier.")
        real_sidechain_id = int(real_valid_vector["public_inputs"]["sidechain_id"])
        real_prior_state_root = pad_field_hex(real_valid_vector["public_inputs"]["prior_state_root"])
        real_config = build_register_config(
            real_supported,
            initial_state_root=real_prior_state_root,
            initial_withdrawal_root="00" * 32,
        )
        node.sendvaliditysidechainregister(real_sidechain_id, real_config)
        node.generate(1)

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
                "txid": deposit_res["txid"],
                "message_kind": 1,
                "message_id": deposit_res["deposit_id"],
                "message_hash": deposit_res["deposit_message_hash"],
            })
        if real_queue_entries:
            real_queue_block_hash = node.generate(1)[0]
            real_queue_entries = order_queue_entries_by_block(node, real_queue_block_hash, real_queue_entries)

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
            "prior_state_root": real_prior_state_root,
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
        real_mismatch_public_inputs = dict(real_public_inputs)
        real_mismatch_public_inputs["new_state_root"] = pad_field_hex(real_mismatch_vector["public_inputs"]["new_state_root"])
        real_queue_prefix_mismatch_public_inputs = dict(real_public_inputs)
        real_queue_prefix_mismatch_public_inputs["queue_prefix_commitment"] = pad_field_hex(
            real_queue_prefix_mismatch_vector["public_inputs"]["queue_prefix_commitment"]
        )
        real_withdrawal_root_mismatch_public_inputs = dict(real_public_inputs)
        real_withdrawal_root_mismatch_public_inputs["withdrawal_root"] = pad_field_hex(
            real_withdrawal_root_mismatch_vector["public_inputs"]["withdrawal_root"]
        )
        oversized_real_public_inputs = dict(real_public_inputs)
        oversized_real_public_inputs["data_size"] = real_supported["max_batch_data_bytes_limit"] + 1
        real_chunk_bytes = [bytes.fromhex(chunk_hex) for chunk_hex in real_data_chunks]

        self.log.info("Rejecting missing or malformed DA on the real Groth16 profile before proof verification.")
        assert_raises_rpc_error(
            -8,
            "data chunks missing for non-zero data_size",
            node.sendvaliditybatch,
            real_sidechain_id,
            real_public_inputs,
            real_valid_vector["proof_bytes_hex"],
        )
        assert_raises_rpc_error(
            -8,
            "data size does not match published chunks",
            node.sendvaliditybatch,
            real_sidechain_id,
            real_public_inputs,
            real_valid_vector["proof_bytes_hex"],
            [real_data_chunks[0]],
        )
        assert_raises_rpc_error(
            -8,
            "data root does not match published chunks",
            node.sendvaliditybatch,
            real_sidechain_id,
            real_public_inputs,
            real_valid_vector["proof_bytes_hex"],
            list(reversed(real_data_chunks)),
        )
        assert_raises_rpc_error(
            -8,
            "data size exceeds configured limit",
            node.sendvaliditybatch,
            real_sidechain_id,
            oversized_real_public_inputs,
            real_valid_vector["proof_bytes_hex"],
            real_data_chunks,
        )
        malformed_real_script = build_commit_script(
            real_sidechain_id,
            real_public_inputs,
            bytes.fromhex(real_valid_vector["proof_bytes_hex"]),
            [
                encode_batch_data_chunk(1, len(real_chunk_bytes), real_chunk_bytes[1]),
                encode_batch_data_chunk(0, len(real_chunk_bytes), real_chunk_bytes[0]),
            ],
        )
        malformed_real_batch_hex = fund_and_sign_script_tx(node, malformed_real_script, 0)
        assert_raises_rpc_error(
            -26,
            "validitysidechain-batch-metadata-bad",
            node.sendrawtransaction,
            malformed_real_batch_hex,
        )
        inconsistent_count_real_script = build_commit_script(
            real_sidechain_id,
            real_public_inputs,
            bytes.fromhex(real_valid_vector["proof_bytes_hex"]),
            [
                encode_batch_data_chunk(0, len(real_chunk_bytes) + 1, real_chunk_bytes[0]),
                encode_batch_data_chunk(1, len(real_chunk_bytes), real_chunk_bytes[1]),
            ],
        )
        inconsistent_count_real_batch_hex = fund_and_sign_script_tx(node, inconsistent_count_real_script, 0)
        assert_raises_rpc_error(
            -26,
            "validitysidechain-batch-metadata-bad",
            node.sendrawtransaction,
            inconsistent_count_real_batch_hex,
        )

        assert_raises_rpc_error(
            -8,
            "Groth16",
            node.sendvaliditybatch,
            real_sidechain_id,
            real_mismatch_public_inputs,
            real_mismatch_vector["proof_bytes_hex"],
            real_data_chunks,
        )
        assert_raises_rpc_error(
            -8,
            "batch queue prefix commitment does not match consumed prefix",
            node.sendvaliditybatch,
            real_sidechain_id,
            real_queue_prefix_mismatch_public_inputs,
            real_queue_prefix_mismatch_vector["proof_bytes_hex"],
            real_data_chunks,
        )
        assert_raises_rpc_error(
            -8,
            "Groth16",
            node.sendvaliditybatch,
            real_sidechain_id,
            real_withdrawal_root_mismatch_public_inputs,
            real_withdrawal_root_mismatch_vector["proof_bytes_hex"],
            real_data_chunks,
        )
        assert_raises_rpc_error(
            -8,
            "Groth16",
            node.sendvaliditybatch,
            real_sidechain_id,
            real_public_inputs,
            real_corrupt_vector["proof_bytes_hex"],
            real_data_chunks,
        )

        real_auto_prover_ready = toy_external_backend_ready and real_supported["verifier_assets"]["prover_assets_present"]
        if real_auto_prover_ready:
            self.log.info("Rejecting unsupported multi-entry queue witness data before real auto-prover proof generation.")
            real_auto_queue_sidechain_id = 34
            real_auto_queue_initial_root = hex_uint(4100)
            real_auto_queue_config = build_register_config(
                real_supported,
                initial_state_root=real_auto_queue_initial_root,
                initial_withdrawal_root="00" * 32,
            )
            node.sendvaliditysidechainregister(real_auto_queue_sidechain_id, real_auto_queue_config)
            node.generate(1)
            first_real_auto_queue_deposit = node.sendvaliditydeposit(
                real_auto_queue_sidechain_id,
                hex_uint(0x5000),
                {"address": refund_address},
                Decimal("0.25"),
            )
            assert first_real_auto_queue_deposit["nonce"] >= 0
            node.generate(1)
            real_auto_queue_sidechain = get_sidechain_info(node, real_auto_queue_sidechain_id)
            assert_equal(real_auto_queue_sidechain["deposit_admission_mode"], "single_pending_entry_scalar_field_experimental")
            assert_equal(real_auto_queue_sidechain["queue_state"]["pending_message_count"], 1)
            assert_raises_rpc_error(
                -8,
                "experimental real profile currently supports at most one pending deposit queue entry",
                node.sendvaliditydeposit,
                real_auto_queue_sidechain_id,
                hex_uint(0x5001),
                {"address": refund_address},
                Decimal("0.25"),
            )
            unsupported_queue_public_inputs = {
                "batch_number": 1,
                "prior_state_root": real_auto_queue_initial_root,
                "new_state_root": hex_uint(4101),
                "l1_message_root_before": real_auto_queue_sidechain["queue_state"]["root"],
                "l1_message_root_after": real_auto_queue_sidechain["queue_state"]["root"],
                "consumed_queue_messages": 2,
                "withdrawal_root": "00" * 32,
                "data_root": "00" * 32,
                "data_size": 0,
            }
            assert_raises_rpc_error(
                -8,
                "experimental real profile supports at most one consumed queue entry for auto prover",
                node.sendvaliditybatch,
                real_auto_queue_sidechain_id,
                unsupported_queue_public_inputs,
            )
            self.log.info("Rejecting consumed force-exit queue entries before real auto-prover proof generation.")
            real_auto_force_exit_sidechain_id = 35
            real_auto_force_exit_initial_root = hex_uint(4200)
            real_auto_force_exit_config = build_register_config(
                real_supported,
                initial_state_root=real_auto_force_exit_initial_root,
                initial_withdrawal_root="00" * 32,
            )
            node.sendvaliditysidechainregister(real_auto_force_exit_sidechain_id, real_auto_force_exit_config)
            node.generate(1)
            real_auto_force_exit_sidechain = get_sidechain_info(node, real_auto_force_exit_sidechain_id)
            assert_equal(
                real_auto_force_exit_sidechain["force_exit_request_mode"],
                "disabled_pending_real_queue_entry_proof",
            )
            assert_equal(
                real_auto_force_exit_sidechain["batch_queue_binding_mode"],
                "local_prefix_consensus_single_deposit_entry_experimental",
            )
            assert_raises_rpc_error(
                -8,
                "force-exit requests are not implemented for this profile",
                node.sendforceexitrequest,
                real_auto_force_exit_sidechain_id,
                "77" * 32,
                "88" * 32,
                Decimal("0.25"),
                {"address": refund_address},
                1,
            )

            self.log.info("Rejecting mismatched withdrawal witness data before real auto-prover proof generation.")
            bad_real_withdrawal_public_inputs = dict(real_public_inputs)
            bad_real_withdrawal_public_inputs["withdrawal_leaves"] = [
                {
                    "withdrawal_id": leaf["withdrawal_id"],
                    "script": leaf["script"],
                    "amount": Decimal(leaf["amount"]) + Decimal("0.01") if index == 0 else Decimal(leaf["amount"]),
                }
                for index, leaf in enumerate(real_valid_vector.get("withdrawal_leaves", []))
            ]
            assert_raises_rpc_error(
                -8,
                "withdrawal_root does not match withdrawal_leaves witness",
                node.sendvaliditybatch,
                real_sidechain_id,
                bad_real_withdrawal_public_inputs,
                None,
                real_data_chunks,
            )
            self.log.info("Rejecting unsupported multi-leaf withdrawal witness data before real auto-prover proof generation.")
            multi_leaf_real_withdrawal_public_inputs = dict(real_public_inputs)
            multi_leaf_real_withdrawal_public_inputs["withdrawal_leaves"] = [
                {
                    "withdrawal_id": leaf["withdrawal_id"],
                    "script": leaf["script"],
                    "amount": Decimal(leaf["amount"]),
                }
                for leaf in real_valid_vector.get("withdrawal_leaves", [])
            ] + [{
                "withdrawal_id": "de" * 32,
                "script": build_script_destination(node),
                "amount": Decimal("0.01"),
            }]
            assert_raises_rpc_error(
                -8,
                "experimental real profile supports at most one withdrawal leaf witness for auto prover",
                node.sendvaliditybatch,
                real_sidechain_id,
                multi_leaf_real_withdrawal_public_inputs,
                None,
                real_data_chunks,
            )

            self.log.info("Auto-building a native-verified real-profile proof through the external prover.")
            real_batch_res = node.sendvaliditybatch(
                real_sidechain_id,
                real_public_inputs,
                None,
                real_data_chunks,
            )
            assert_equal(real_batch_res["auto_scaffold_proof"], False)
            assert_equal(real_batch_res["auto_external_proof"], True)
            assert_equal(real_batch_res["auto_proof_backend"], "external_command")
            node.generate(1)

            real_sidechain = get_sidechain_info(node, real_sidechain_id)
            assert_equal(real_sidechain["batch_verifier_mode"], "groth16_bls12_381_poseidon_v1")
            assert_equal(real_sidechain["latest_batch_number"], real_public_inputs["batch_number"])
            assert_equal(real_sidechain["current_state_root"], real_public_inputs["new_state_root"])
            assert_equal(real_sidechain["current_withdrawal_root"], real_public_inputs["withdrawal_root"])
            assert_equal(real_sidechain["current_data_root"], real_public_inputs["data_root"])
            assert_equal(real_sidechain["queue_state"]["head_index"], len(real_queue_entries))
            assert_equal(real_sidechain["queue_state"]["pending_message_count"], 0)
            assert real_sidechain["accepted_batches"][0]["proof_size"] > 0
            assert_equal(real_sidechain["accepted_batches"][0]["proof_parsed_as_groth16"], True)
            assert_equal(real_sidechain["accepted_batches"][0]["proof_commitment_extension_count"], 0)
            assert_equal(real_sidechain["accepted_batches"][0]["proof_commitment_extension_matches_profile"], True)
            assert_equal(real_sidechain["accepted_batches"][0]["published_data_chunk_count"], len(real_data_chunks))
            assert_equal(real_sidechain["accepted_batches"][0]["published_data_bytes"], real_public_inputs["data_size"])
        else:
            self.log.info("Skipping native real auto-prover coverage because the committed proving key is not available in-tree.")

        real_v2_auto_prover_ready = toy_external_backend_ready and real_v2_supported["verifier_assets"]["prover_assets_present"]
        if real_v2_auto_prover_ready:
            self.log.info("Auto-building a native-verified decomposed real-profile proof with multi-entry queue and multi-leaf withdrawals.")
            real_v2_auto_sidechain_id = 58
            real_v2_auto_initial_root = hex_uint(4300)
            real_v2_auto_config = build_register_config(
                real_v2_supported,
                initial_state_root=real_v2_auto_initial_root,
                initial_withdrawal_root="ff" * 32,
            )
            node.sendvaliditysidechainregister(real_v2_auto_sidechain_id, real_v2_auto_config)
            node.generate(1)

            real_v2_queue_entries = []
            for index in range(2):
                deposit_res = node.sendvaliditydeposit(
                    real_v2_auto_sidechain_id,
                    hex_uint(0x6100 + index),
                    {"address": refund_address},
                    Decimal("0.25") + (Decimal("0.05") * index),
                    index + 1,
                )
                real_v2_queue_entries.append({
                    "txid": deposit_res["txid"],
                    "message_kind": 1,
                    "message_id": deposit_res["deposit_id"],
                    "message_hash": deposit_res["deposit_message_hash"],
                })
            real_v2_queue_block_hash = node.generate(1)[0]
            real_v2_queue_entries = order_queue_entries_by_block(
                node,
                real_v2_queue_block_hash,
                real_v2_queue_entries,
            )

            real_v2_auto_sidechain = get_sidechain_info(node, real_v2_auto_sidechain_id)
            assert_equal(real_v2_auto_sidechain["queue_state"]["pending_message_count"], 2)

            real_v2_withdrawals_rpc = [
                {
                    "withdrawal_id": "91" * 32,
                    "script": build_script_destination(node),
                    "amount": Decimal("0.10"),
                },
                {
                    "withdrawal_id": "92" * 32,
                    "script": build_script_destination(node),
                    "amount": Decimal("0.15"),
                },
            ]
            real_v2_withdrawal_witness = [
                {
                    "withdrawal_id": withdrawal["withdrawal_id"],
                    "amount": str(withdrawal["amount"]),
                    "destination_commitment": compute_script_commitment(withdrawal["script"]),
                }
                for withdrawal in real_v2_withdrawals_rpc
            ]

            real_v2_derive_request = {
                "profile_name": "groth16_bls12_381_poseidon_v2",
                "artifact_dir": str(self.real_v2_artifact_dir),
                "sidechain_id": real_v2_auto_sidechain_id,
                "current_state_root": real_v2_auto_sidechain["current_state_root"],
                "current_withdrawal_root": real_v2_auto_sidechain["current_withdrawal_root"],
                "current_data_root": real_v2_auto_sidechain["current_data_root"],
                "current_l1_message_root": real_v2_auto_sidechain["queue_state"]["root"],
                "public_inputs": {
                    "batch_number": 1,
                    "prior_state_root": real_v2_auto_initial_root,
                    "new_state_root": "0",
                    "l1_message_root_before": real_v2_auto_sidechain["queue_state"]["root"],
                    "l1_message_root_after": "0",
                    "consumed_queue_messages": len(real_v2_queue_entries),
                    "queue_prefix_commitment": "0",
                    "withdrawal_root": "0",
                    "data_root": "0",
                    "data_size": 0,
                },
                "require_withdrawal_witness_on_root_change": True,
                "withdrawal_leaves_supplied": True,
                "consumed_queue_entries": real_v2_queue_entries,
                "withdrawal_leaves": real_v2_withdrawal_witness,
                "data_chunks_hex": [],
            }
            real_v2_derived = self.run_tool("derive", real_v2_derive_request)
            assert_equal(real_v2_derived["ok"], True)
            assert_equal(
                real_v2_derived["public_inputs"]["l1_message_root_after"],
                compute_consumed_queue_root(
                    real_v2_auto_sidechain_id,
                    real_v2_auto_sidechain["queue_state"]["root"],
                    real_v2_queue_entries,
                ),
            )
            assert_equal(
                real_v2_derived["public_inputs"]["queue_prefix_commitment"],
                compute_queue_prefix_commitment(
                    real_v2_auto_sidechain_id,
                    real_v2_queue_entries,
                ),
            )
            assert_equal(
                real_v2_derived["public_inputs"]["withdrawal_root"],
                compute_withdrawal_root(real_v2_withdrawals_rpc),
            )
            assert_equal(real_v2_derived["public_inputs"]["data_root"], compute_data_root([]))

            missing_real_v2_context_request = dict(real_v2_derive_request)
            del missing_real_v2_context_request["current_state_root"]
            missing_real_v2_context = self.run_tool("derive", missing_real_v2_context_request)
            assert_equal(missing_real_v2_context["ok"], False)
            assert "current_state_root is required for legacy v2 proof requests" in missing_real_v2_context["error"]

            real_v2_preserve_request = {
                "profile_name": "groth16_bls12_381_poseidon_v2",
                "artifact_dir": str(self.real_v2_artifact_dir),
                "sidechain_id": real_v2_auto_sidechain_id,
                "current_state_root": real_v2_auto_sidechain["current_state_root"],
                "current_withdrawal_root": real_v2_auto_sidechain["current_withdrawal_root"],
                "current_data_root": real_v2_auto_sidechain["current_data_root"],
                "current_l1_message_root": real_v2_auto_sidechain["queue_state"]["root"],
                "public_inputs": {
                    "batch_number": 1,
                    "prior_state_root": real_v2_auto_initial_root,
                    "new_state_root": "0",
                    "l1_message_root_before": real_v2_auto_sidechain["queue_state"]["root"],
                    "l1_message_root_after": "0",
                    "consumed_queue_messages": len(real_v2_queue_entries),
                    "queue_prefix_commitment": "0",
                    "withdrawal_root": real_v2_auto_sidechain["current_withdrawal_root"],
                    "data_root": "0",
                    "data_size": 0,
                },
                "require_withdrawal_witness_on_root_change": True,
                "withdrawal_leaves_supplied": False,
                "consumed_queue_entries": real_v2_queue_entries,
                "withdrawal_leaves": [],
                "data_chunks_hex": [],
            }
            real_v2_preserve_derived = self.run_tool("derive", real_v2_preserve_request)
            assert_equal(real_v2_preserve_derived["ok"], True)
            assert_equal(
                real_v2_preserve_derived["public_inputs"]["withdrawal_root"],
                real_v2_auto_sidechain["current_withdrawal_root"],
            )

            real_v2_empty_withdrawal_request = dict(real_v2_preserve_request)
            real_v2_empty_withdrawal_request["public_inputs"] = dict(real_v2_preserve_request["public_inputs"])
            real_v2_empty_withdrawal_request["public_inputs"]["withdrawal_root"] = compute_withdrawal_root([])
            real_v2_empty_withdrawal_request["withdrawal_leaves_supplied"] = True
            real_v2_empty_withdrawal_request["withdrawal_leaves"] = []
            real_v2_empty_withdrawal_derived = self.run_tool("derive", real_v2_empty_withdrawal_request)
            assert_equal(real_v2_empty_withdrawal_derived["ok"], True)
            assert_equal(
                real_v2_empty_withdrawal_derived["public_inputs"]["withdrawal_root"],
                compute_withdrawal_root([]),
            )

            real_v2_public_inputs = dict(real_v2_derived["public_inputs"])
            for field_name in (
                "prior_state_root",
                "new_state_root",
                "l1_message_root_before",
                "l1_message_root_after",
                "queue_prefix_commitment",
                "withdrawal_root",
                "data_root",
            ):
                real_v2_public_inputs[field_name] = pad_field_hex(real_v2_public_inputs[field_name])
            real_v2_public_inputs["withdrawal_leaves"] = [
                {
                    "withdrawal_id": withdrawal["withdrawal_id"],
                    "script": withdrawal["script"],
                    "amount": withdrawal["amount"],
                }
                for withdrawal in real_v2_withdrawals_rpc
            ]

            bad_real_v2_public_inputs = dict(real_v2_public_inputs)
            bad_real_v2_public_inputs["withdrawal_leaves"] = [
                {
                    "withdrawal_id": withdrawal["withdrawal_id"],
                    "script": withdrawal["script"],
                    "amount": withdrawal["amount"] + (Decimal("0.01") if index == 1 else Decimal("0.00")),
                }
                for index, withdrawal in enumerate(real_v2_withdrawals_rpc)
            ]
            assert_raises_rpc_error(
                -8,
                "withdrawal_root does not match withdrawal_leaves witness",
                node.sendvaliditybatch,
                real_v2_auto_sidechain_id,
                bad_real_v2_public_inputs,
            )

            real_v2_batch_res = node.sendvaliditybatch(
                real_v2_auto_sidechain_id,
                {
                    "batch_number": real_v2_public_inputs["batch_number"],
                    "new_state_root": real_v2_public_inputs["new_state_root"],
                    "consumed_queue_messages": real_v2_public_inputs["consumed_queue_messages"],
                    "withdrawal_leaves": real_v2_public_inputs["withdrawal_leaves"],
                },
            )
            assert_equal(real_v2_batch_res["auto_scaffold_proof"], False)
            assert_equal(real_v2_batch_res["auto_external_proof"], True)
            assert_equal(real_v2_batch_res["auto_proof_backend"], "external_command")
            node.generate(1)

            real_v2_auto_sidechain = get_sidechain_info(node, real_v2_auto_sidechain_id)
            assert_equal(real_v2_auto_sidechain["batch_verifier_mode"], "groth16_bls12_381_poseidon_v2")
            assert_equal(real_v2_auto_sidechain["latest_batch_number"], 1)
            assert_equal(real_v2_auto_sidechain["current_state_root"], real_v2_public_inputs["new_state_root"])
            assert_equal(real_v2_auto_sidechain["current_withdrawal_root"], real_v2_public_inputs["withdrawal_root"])
            assert_equal(real_v2_auto_sidechain["queue_state"]["head_index"], len(real_v2_queue_entries))
            assert_equal(real_v2_auto_sidechain["queue_state"]["pending_message_count"], 0)
            assert real_v2_auto_sidechain["accepted_batches"][0]["proof_size"] > 0
            assert_equal(real_v2_auto_sidechain["accepted_batches"][0]["proof_parsed_as_groth16"], True)
            assert_equal(real_v2_auto_sidechain["accepted_batches"][0]["proof_commitment_extension_count"], 0)
            assert_equal(real_v2_auto_sidechain["accepted_batches"][0]["proof_commitment_extension_matches_profile"], True)
        else:
            self.log.info("Skipping decomposed real auto-prover coverage because the committed proving key is not available in-tree.")

        real_v3_auto_prover_ready = toy_external_backend_ready and real_v3_supported["verifier_assets"]["prover_assets_present"]
        if real_v3_auto_prover_ready:
            self.log.info("Auto-building a native-verified canonical v3 real-profile proof with bounded queue, withdrawal, and data witnesses.")
            real_v3_auto_sidechain_id = 59
            real_v3_auto_initial_root = hex_uint(4400)
            real_v3_auto_initial_withdrawal_root = "ab" * 32
            real_v3_auto_config = build_register_config(
                real_v3_supported,
                initial_state_root=real_v3_auto_initial_root,
                initial_withdrawal_root=real_v3_auto_initial_withdrawal_root,
            )
            node.sendvaliditysidechainregister(real_v3_auto_sidechain_id, real_v3_auto_config)
            node.generate(1)

            real_v3_queue_entries = []
            for index in range(2):
                deposit_res = node.sendvaliditydeposit(
                    real_v3_auto_sidechain_id,
                    hex_uint(0x6200 + index),
                    {"address": refund_address},
                    Decimal("0.20") + (Decimal("0.05") * index),
                    index + 1,
                )
                real_v3_queue_entries.append({
                    "txid": deposit_res["txid"],
                    "message_kind": 1,
                    "message_id": deposit_res["deposit_id"],
                    "message_hash": deposit_res["deposit_message_hash"],
                })
            real_v3_queue_block_hash = node.generate(1)[0]
            real_v3_queue_entries = order_queue_entries_by_block(
                node,
                real_v3_queue_block_hash,
                real_v3_queue_entries,
            )

            real_v3_auto_sidechain = get_sidechain_info(node, real_v3_auto_sidechain_id)
            assert_equal(real_v3_auto_sidechain["queue_state"]["pending_message_count"], 2)

            real_v3_data_chunks = ["61" * 64, "2d6461"]
            real_v3_data_chunk_bytes = [bytes.fromhex(chunk) for chunk in real_v3_data_chunks]
            real_v3_preserve_request = {
                "profile_name": "groth16_bls12_381_poseidon_v3",
                "artifact_dir": str(self.real_v3_artifact_dir),
                "sidechain_id": real_v3_auto_sidechain_id,
                "current_state_root": real_v3_auto_sidechain["current_state_root"],
                "current_withdrawal_root": real_v3_auto_sidechain["current_withdrawal_root"],
                "current_data_root": real_v3_auto_sidechain["current_data_root"],
                "current_l1_message_root": real_v3_auto_sidechain["queue_state"]["root"],
                "public_inputs": {
                    "batch_number": 1,
                    "prior_state_root": real_v3_auto_initial_root,
                    "new_state_root": "0",
                    "l1_message_root_before": real_v3_auto_sidechain["queue_state"]["root"],
                    "l1_message_root_after": "0",
                    "consumed_queue_messages": len(real_v3_queue_entries),
                    "queue_prefix_commitment": "0",
                    "withdrawal_root": real_v3_auto_sidechain["current_withdrawal_root"],
                    "data_root": "0",
                    "data_size": 0,
                },
                "require_withdrawal_witness_on_root_change": True,
                "withdrawal_leaves_supplied": False,
                "consumed_queue_entries": real_v3_queue_entries,
                "withdrawal_leaves": [],
                "data_chunks_hex": real_v3_data_chunks,
            }
            real_v3_preserve_derived = self.run_tool("derive", real_v3_preserve_request)
            assert_equal(real_v3_preserve_derived["ok"], True)
            assert_equal(
                real_v3_preserve_derived["public_inputs"]["withdrawal_root"],
                real_v3_auto_sidechain["current_withdrawal_root"],
            )
            assert_equal(
                real_v3_preserve_derived["public_inputs"]["l1_message_root_after"],
                compute_consumed_queue_root(
                    real_v3_auto_sidechain_id,
                    real_v3_auto_sidechain["queue_state"]["root"],
                    real_v3_queue_entries,
                ),
            )
            assert_equal(
                real_v3_preserve_derived["public_inputs"]["queue_prefix_commitment"],
                compute_queue_prefix_commitment(
                    real_v3_auto_sidechain_id,
                    real_v3_queue_entries,
                ),
            )
            assert_equal(
                real_v3_preserve_derived["public_inputs"]["data_root"],
                compute_data_root(real_v3_data_chunk_bytes),
            )
            assert_equal(
                real_v3_preserve_derived["public_inputs"]["data_size"],
                sum(len(chunk) for chunk in real_v3_data_chunk_bytes),
            )

            real_v3_withdrawals_rpc = [
                {
                    "withdrawal_id": "a1" * 32,
                    "script": build_script_destination(node),
                    "amount": Decimal("0.11"),
                },
                {
                    "withdrawal_id": "a2" * 32,
                    "script": build_script_destination(node),
                    "amount": Decimal("0.14"),
                },
            ]
            real_v3_withdrawal_witness = [
                {
                    "withdrawal_id": withdrawal["withdrawal_id"],
                    "amount": str(withdrawal["amount"]),
                    "destination_commitment": compute_script_commitment(withdrawal["script"]),
                }
                for withdrawal in real_v3_withdrawals_rpc
            ]

            real_v3_derive_request = {
                "profile_name": "groth16_bls12_381_poseidon_v3",
                "artifact_dir": str(self.real_v3_artifact_dir),
                "sidechain_id": real_v3_auto_sidechain_id,
                "current_state_root": real_v3_auto_sidechain["current_state_root"],
                "current_withdrawal_root": real_v3_auto_sidechain["current_withdrawal_root"],
                "current_data_root": real_v3_auto_sidechain["current_data_root"],
                "current_l1_message_root": real_v3_auto_sidechain["queue_state"]["root"],
                "public_inputs": {
                    "batch_number": 1,
                    "prior_state_root": real_v3_auto_initial_root,
                    "new_state_root": "0",
                    "l1_message_root_before": real_v3_auto_sidechain["queue_state"]["root"],
                    "l1_message_root_after": "0",
                    "consumed_queue_messages": len(real_v3_queue_entries),
                    "queue_prefix_commitment": "0",
                    "withdrawal_root": "0",
                    "data_root": "0",
                    "data_size": 0,
                },
                "require_withdrawal_witness_on_root_change": True,
                "withdrawal_leaves_supplied": True,
                "consumed_queue_entries": real_v3_queue_entries,
                "withdrawal_leaves": real_v3_withdrawal_witness,
                "data_chunks_hex": real_v3_data_chunks,
            }
            real_v3_derived = self.run_tool("derive", real_v3_derive_request)
            assert_equal(real_v3_derived["ok"], True)
            assert_equal(
                real_v3_derived["public_inputs"]["l1_message_root_after"],
                compute_consumed_queue_root(
                    real_v3_auto_sidechain_id,
                    real_v3_auto_sidechain["queue_state"]["root"],
                    real_v3_queue_entries,
                ),
            )
            assert_equal(
                real_v3_derived["public_inputs"]["queue_prefix_commitment"],
                compute_queue_prefix_commitment(
                    real_v3_auto_sidechain_id,
                    real_v3_queue_entries,
                ),
            )
            assert_equal(
                real_v3_derived["public_inputs"]["withdrawal_root"],
                compute_withdrawal_root(real_v3_withdrawals_rpc),
            )
            assert_equal(
                real_v3_derived["public_inputs"]["data_root"],
                compute_data_root(real_v3_data_chunk_bytes),
            )
            assert_equal(
                real_v3_derived["public_inputs"]["data_size"],
                sum(len(chunk) for chunk in real_v3_data_chunk_bytes),
            )

            missing_real_v3_context_request = dict(real_v3_derive_request)
            del missing_real_v3_context_request["current_state_root"]
            missing_real_v3_context = self.run_tool("derive", missing_real_v3_context_request)
            assert_equal(missing_real_v3_context["ok"], False)
            assert "current_state_root is required for canonical v3 proof requests" in missing_real_v3_context["error"]

            real_v3_public_inputs = dict(real_v3_derived["public_inputs"])
            for field_name in (
                "prior_state_root",
                "new_state_root",
                "l1_message_root_before",
                "l1_message_root_after",
                "queue_prefix_commitment",
                "withdrawal_root",
                "data_root",
            ):
                real_v3_public_inputs[field_name] = pad_field_hex(real_v3_public_inputs[field_name])
            real_v3_public_inputs["withdrawal_leaves"] = [
                {
                    "withdrawal_id": withdrawal["withdrawal_id"],
                    "script": withdrawal["script"],
                    "amount": withdrawal["amount"],
                }
                for withdrawal in real_v3_withdrawals_rpc
            ]

            bad_real_v3_public_inputs = dict(real_v3_public_inputs)
            bad_real_v3_public_inputs["withdrawal_leaves"] = [
                {
                    "withdrawal_id": withdrawal["withdrawal_id"],
                    "script": withdrawal["script"],
                    "amount": withdrawal["amount"] + (Decimal("0.01") if index == 1 else Decimal("0.00")),
                }
                for index, withdrawal in enumerate(real_v3_withdrawals_rpc)
            ]
            assert_raises_rpc_error(
                -8,
                "withdrawal_root does not match withdrawal_leaves witness",
                node.sendvaliditybatch,
                real_v3_auto_sidechain_id,
                {
                    "batch_number": real_v3_public_inputs["batch_number"],
                    "new_state_root": real_v3_public_inputs["new_state_root"],
                    "consumed_queue_messages": real_v3_public_inputs["consumed_queue_messages"],
                    "withdrawal_root": real_v3_public_inputs["withdrawal_root"],
                    "withdrawal_leaves": bad_real_v3_public_inputs["withdrawal_leaves"],
                },
                None,
                real_v3_data_chunks,
            )

            slow_node = get_rpc_proxy(node.url, 0, timeout=900, coveragedir=node.coverage_dir)
            real_v3_batch_res = slow_node.sendvaliditybatch(
                real_v3_auto_sidechain_id,
                {
                    "batch_number": real_v3_public_inputs["batch_number"],
                    "new_state_root": real_v3_public_inputs["new_state_root"],
                    "consumed_queue_messages": real_v3_public_inputs["consumed_queue_messages"],
                    "withdrawal_leaves": real_v3_public_inputs["withdrawal_leaves"],
                },
                None,
                real_v3_data_chunks,
            )
            assert_equal(real_v3_batch_res["auto_scaffold_proof"], False)
            assert_equal(real_v3_batch_res["auto_external_proof"], True)
            assert_equal(real_v3_batch_res["auto_proof_backend"], "external_command")
            node.generate(1)

            real_v3_auto_sidechain = get_sidechain_info(node, real_v3_auto_sidechain_id)
            assert_equal(real_v3_auto_sidechain["batch_verifier_mode"], "groth16_bls12_381_poseidon_v3")
            assert_equal(real_v3_auto_sidechain["latest_batch_number"], 1)
            assert_equal(real_v3_auto_sidechain["current_state_root"], real_v3_public_inputs["new_state_root"])
            assert_equal(real_v3_auto_sidechain["current_withdrawal_root"], real_v3_public_inputs["withdrawal_root"])
            assert_equal(real_v3_auto_sidechain["current_data_root"], real_v3_public_inputs["data_root"])
            assert_equal(real_v3_auto_sidechain["queue_state"]["head_index"], len(real_v3_queue_entries))
            assert_equal(real_v3_auto_sidechain["queue_state"]["pending_message_count"], 0)
            assert real_v3_auto_sidechain["accepted_batches"][0]["proof_size"] > 0
            assert_equal(real_v3_auto_sidechain["accepted_batches"][0]["proof_parsed_as_groth16"], True)
            assert_equal(real_v3_auto_sidechain["accepted_batches"][0]["proof_commitment_extension_count"], 1)
            assert_equal(real_v3_auto_sidechain["accepted_batches"][0]["proof_commitment_extension_matches_profile"], True)
            assert_equal(real_v3_auto_sidechain["accepted_batches"][0]["published_data_chunk_count"], len(real_v3_data_chunks))
            assert_equal(real_v3_auto_sidechain["accepted_batches"][0]["published_data_bytes"], real_v3_public_inputs["data_size"])
        else:
            self.log.info("Skipping canonical v3 real auto-prover coverage because the committed proving key is not available in-tree.")


if __name__ == "__main__":
    ValiditySidechainToyProofProfileTest().main()
