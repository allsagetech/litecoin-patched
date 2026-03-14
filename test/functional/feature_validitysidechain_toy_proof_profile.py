#!/usr/bin/env python3
# Copyright (c) 2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from pathlib import Path
from unittest import SkipTest
import json
import os
import shlex
import shutil
import subprocess
import sys

from test_framework.messages import hash256, ser_uint256
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


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


def load_json(path):
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


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


def shell_join(argv):
    args = [str(arg) for arg in argv]
    if os.name == "nt":
        return subprocess.list2cmdline(args)
    return shlex.join(args)


class ValiditySidechainToyProofProfileTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

        self.repo_root = Path(__file__).resolve().parents[2]
        self.zk_demo_dir = self.repo_root / "contrib" / "validitysidechain-zk-demo"
        self.zk_runner = self.zk_demo_dir / "run_tool.py"
        self.artifact_root = self.repo_root / "artifacts"
        self.toy_artifact_dir = self.artifact_root / "validitysidechain" / "gnark_groth16_toy_batch_transition_v1"
        self.valid_vector_path = self.toy_artifact_dir / "valid" / "valid_proof.json"
        self.invalid_mismatch_vector_path = self.toy_artifact_dir / "invalid" / "public_input_mismatch.json"
        self.invalid_corrupt_vector_path = self.toy_artifact_dir / "invalid" / "corrupt_proof.json"
        self.have_go = shutil.which("go") is not None

        base_args = ["-acceptnonstdtxn=1"]
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
        assert_equal(toy_supported["batch_verifier_mode"], "gnark_groth16_toy_batch_transition_v1")
        assert_equal(toy_supported["verifier_backend"], "external_gnark_command")
        assert_equal(toy_supported["supports_external_prover"], True)
        assert_equal(toy_supported["verifier_assets"]["required"], True)
        assert_equal(toy_supported["verifier_assets"]["available"], True)
        assert_equal(toy_supported["verifier_assets"]["prover_assets_present"], True)
        assert_equal(toy_supported["verifier_assets"]["backend_ready"], True)
        assert_equal(toy_supported["verifier_assets"]["verifier_command_configured"], True)
        assert_equal(toy_supported["verifier_assets"]["prover_command_configured"], True)

        self.log.info("Replaying committed proof vectors through consensus.")
        valid_vector = load_json(self.valid_vector_path)
        mismatch_vector = load_json(self.invalid_mismatch_vector_path)
        corrupt_vector = load_json(self.invalid_corrupt_vector_path)
        assert_equal(valid_vector["expected_result"], "accept_in_demo_verifier")
        assert_equal(mismatch_vector["expected_result"], "reject")
        assert_equal(corrupt_vector["expected_result"], "reject")

        vector_sidechain_id = 7
        vector_prior_state_root = pad_field_hex(valid_vector["public_inputs"]["prior_state_root"])
        vector_config = build_register_config(
            toy_supported,
            initial_state_root=vector_prior_state_root,
            initial_withdrawal_root=vector_prior_state_root,
        )
        node.sendvaliditysidechainregister(vector_sidechain_id, vector_config)
        node.generate(1)

        refund_address = node.getnewaddress()
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
        l1_message_root_before = vector_sidechain["queue_state"]["root"]
        l1_message_root_after = compute_consumed_queue_root(
            vector_sidechain_id,
            l1_message_root_before,
            queued_entries,
        )

        valid_public_inputs = {
            "batch_number": int(valid_vector["public_inputs"]["batch_number"]),
            "prior_state_root": vector_prior_state_root,
            "new_state_root": pad_field_hex(valid_vector["public_inputs"]["new_state_root"]),
            "l1_message_root_before": l1_message_root_before,
            "l1_message_root_after": l1_message_root_after,
            "consumed_queue_messages": int(valid_vector["public_inputs"]["consumed_queue_messages"]),
            "withdrawal_root": pad_field_hex(valid_vector["public_inputs"]["withdrawal_root"]),
            "data_root": pad_field_hex(valid_vector["public_inputs"]["data_root"]),
            "data_size": 0,
        }
        mismatch_public_inputs = dict(valid_public_inputs)
        mismatch_public_inputs["new_state_root"] = pad_field_hex(mismatch_vector["public_inputs"]["new_state_root"])

        assert_raises_rpc_error(
            -26,
            "pairing doesn't match",
            node.sendvaliditybatch,
            vector_sidechain_id,
            mismatch_public_inputs,
            mismatch_vector["proof_bytes_hex"],
        )
        assert_raises_rpc_error(
            -26,
            "pairing doesn't match",
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
        assert_equal(vector_sidechain["latest_batch_number"], 8)
        assert_equal(vector_sidechain["current_state_root"], valid_public_inputs["new_state_root"])
        assert_equal(vector_sidechain["current_withdrawal_root"], valid_public_inputs["withdrawal_root"])
        assert_equal(vector_sidechain["current_data_root"], valid_public_inputs["data_root"])
        assert_equal(vector_sidechain["queue_state"]["head_index"], 3)
        assert_equal(vector_sidechain["queue_state"]["pending_message_count"], 0)
        assert vector_sidechain["accepted_batches"][0]["proof_size"] > 0

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
            "data_root": hex_uint(1028),
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
            "data_root": hex_uint(2028),
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

        assert_raises_rpc_error(
            -26,
            "pairing doesn't match",
            node.sendvaliditybatch,
            invalid_sidechain_id,
            invalid_public_inputs,
            corrupted_proof_hex,
        )


if __name__ == "__main__":
    ValiditySidechainToyProofProfileTest().main()
