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
