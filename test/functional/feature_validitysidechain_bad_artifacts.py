#!/usr/bin/env python3
# Copyright (c) 2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from pathlib import Path
import json
import shutil

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


def load_json(path):
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def pad_field_hex(raw_value):
    return raw_value.lower().rjust(64, "0")


def build_probe_public_inputs(batch_number, current_state_root, current_withdrawal_root):
    zero_root = "00" * 32
    return {
        "batch_number": batch_number,
        "prior_state_root": current_state_root,
        "new_state_root": current_state_root,
        "l1_message_root_before": zero_root,
        "l1_message_root_after": zero_root,
        "consumed_queue_messages": 0,
        "queue_prefix_commitment": zero_root,
        "withdrawal_root": current_withdrawal_root,
        "data_root": zero_root,
        "data_size": 0,
    }


class ValiditySidechainBadArtifactsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

        self.repo_root = Path(__file__).resolve().parents[2]
        self.source_artifact_root = self.repo_root / "artifacts"
        self.toy_source_dir = self.source_artifact_root / "validitysidechain" / "gnark_groth16_toy_batch_transition_v1"
        self.native_toy_source_dir = self.source_artifact_root / "validitysidechain" / "native_blst_groth16_toy_batch_transition_v1"
        self.real_source_dir = self.source_artifact_root / "validitysidechain" / "groth16_bls12_381_poseidon_v1"
        self.valid_vector_path = self.toy_source_dir / "valid" / "valid_proof.json"
        self.native_valid_vector_path = self.native_toy_source_dir / "valid" / "valid_proof.json"
        self.real_valid_vector_path = self.real_source_dir / "valid" / "valid_proof.json"

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        if not self.toy_source_dir.exists():
            self.skipTest("toy artifact directory is missing")
        if not self.valid_vector_path.exists():
            self.skipTest("toy valid proof vector is missing")
        if not self.native_toy_source_dir.exists():
            self.skipTest("native toy artifact directory is missing")
        if not self.native_valid_vector_path.exists():
            self.skipTest("native toy valid proof vector is missing")
        if not self.real_source_dir.exists():
            self.skipTest("real artifact directory is missing")
        if not self.real_valid_vector_path.exists():
            self.skipTest("real valid proof vector is missing")

    def rewrite_manifest(self, artifact_root, profile_name, mutate_fn):
        manifest_path = artifact_root / "validitysidechain" / profile_name / "profile.json"
        manifest = load_json(manifest_path)
        mutate_fn(manifest)
        with manifest_path.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(manifest, handle, indent=2)
            handle.write("\n")

    def prepare_artifact_root(self, name):
        target_root = Path(self.options.tmpdir) / name
        if target_root.exists():
            shutil.rmtree(target_root)
        shutil.copytree(self.source_artifact_root, target_root)
        return target_root

    def restart_with_artifacts(self, artifact_root):
        self.restart_node(0, extra_args=[
            "-acceptnonstdtxn=1",
            f"-validityartifactsdir={artifact_root}",
        ])

    def assert_broken_profile_rejects_batches(self, node, profile_name, vector_path, sidechain_id, expected_status, broken_field):
        supported = get_supported_profile(node, profile_name)
        assert_equal(supported["verifier_assets"]["required"], True)
        assert_equal(supported["verifier_assets"]["available"], False)
        assert_equal(supported["verifier_assets"]["backend_ready"], False)
        assert_equal(supported["verifier_assets"]["status"], expected_status)
        assert_equal(supported["verifier_assets"][broken_field], False)

        valid_vector = load_json(vector_path)
        config = build_register_config(
            supported,
            initial_state_root=pad_field_hex(valid_vector["public_inputs"]["prior_state_root"]),
            initial_withdrawal_root="10" * 32,
        )
        probe_public_inputs = build_probe_public_inputs(
            int(valid_vector["public_inputs"]["batch_number"]),
            config["initial_state_root"],
            config["initial_withdrawal_root"],
        )
        node.sendvaliditysidechainregister(sidechain_id, config)
        node.generate(1)
        assert_raises_rpc_error(
            -8,
            expected_status,
            node.sendvaliditybatch,
            sidechain_id,
            probe_public_inputs,
            valid_vector["proof_bytes_hex"],
        )

    def run_test(self):
        node = self.nodes[0]
        node.generatetoaddress(101, node.getnewaddress())

        self.log.info("Restarting against a toy artifact bundle with a mismatched consensus tuple.")
        tuple_root = self.prepare_artifact_root("bad_artifacts_tuple")
        self.rewrite_manifest(
            tuple_root,
            "gnark_groth16_toy_batch_transition_v1",
            lambda manifest: manifest["consensus_tuple"].__setitem__("public_input_version", 99),
        )
        self.restart_with_artifacts(tuple_root)
        self.assert_broken_profile_rejects_batches(
            self.nodes[0],
            "gnark_groth16_toy_batch_transition_v1",
            self.valid_vector_path,
            31,
            "profile manifest consensus tuple does not match supported profile",
            "profile_manifest_tuple_matches",
        )

        self.log.info("Restarting against a toy artifact bundle with a mismatched public-input layout.")
        public_inputs_root = self.prepare_artifact_root("bad_artifacts_public_inputs")

        def mutate_public_inputs(manifest):
            manifest["public_inputs"] = [
                "sidechain_id",
                "batch_number",
                "prior_state_root",
                "new_state_root",
                "withdrawal_root",
                "data_root",
            ]

        self.rewrite_manifest(
            public_inputs_root,
            "gnark_groth16_toy_batch_transition_v1",
            mutate_public_inputs,
        )
        self.restart_with_artifacts(public_inputs_root)
        self.assert_broken_profile_rejects_batches(
            self.nodes[0],
            "gnark_groth16_toy_batch_transition_v1",
            self.valid_vector_path,
            32,
            "profile manifest public inputs do not match supported profile",
            "profile_manifest_public_inputs_match",
        )

        self.log.info("Restarting against a native toy artifact bundle with a mismatched consensus tuple.")
        native_tuple_root = self.prepare_artifact_root("bad_artifacts_native_tuple")
        self.rewrite_manifest(
            native_tuple_root,
            "native_blst_groth16_toy_batch_transition_v1",
            lambda manifest: manifest["consensus_tuple"].__setitem__("public_input_version", 99),
        )
        self.restart_with_artifacts(native_tuple_root)
        self.assert_broken_profile_rejects_batches(
            self.nodes[0],
            "native_blst_groth16_toy_batch_transition_v1",
            self.native_valid_vector_path,
            33,
            "profile manifest consensus tuple does not match supported profile",
            "profile_manifest_tuple_matches",
        )

        self.log.info("Restarting against a native toy artifact bundle with a mismatched public-input layout.")
        native_public_inputs_root = self.prepare_artifact_root("bad_artifacts_native_public_inputs")

        self.rewrite_manifest(
            native_public_inputs_root,
            "native_blst_groth16_toy_batch_transition_v1",
            mutate_public_inputs,
        )
        self.restart_with_artifacts(native_public_inputs_root)
        self.assert_broken_profile_rejects_batches(
            self.nodes[0],
            "native_blst_groth16_toy_batch_transition_v1",
            self.native_valid_vector_path,
            34,
            "profile manifest public inputs do not match supported profile",
            "profile_manifest_public_inputs_match",
        )

        self.log.info("Restarting against a real artifact bundle with a mismatched consensus tuple.")
        real_tuple_root = self.prepare_artifact_root("bad_artifacts_real_tuple")
        self.rewrite_manifest(
            real_tuple_root,
            "groth16_bls12_381_poseidon_v1",
            lambda manifest: manifest["consensus_tuple"].__setitem__("public_input_version", 99),
        )
        self.restart_with_artifacts(real_tuple_root)
        self.assert_broken_profile_rejects_batches(
            self.nodes[0],
            "groth16_bls12_381_poseidon_v1",
            self.real_valid_vector_path,
            35,
            "profile manifest consensus tuple does not match supported profile",
            "profile_manifest_tuple_matches",
        )

        self.log.info("Restarting against a real artifact bundle with a mismatched public-input layout.")
        real_public_inputs_root = self.prepare_artifact_root("bad_artifacts_real_public_inputs")
        self.rewrite_manifest(
            real_public_inputs_root,
            "groth16_bls12_381_poseidon_v1",
            mutate_public_inputs,
        )
        self.restart_with_artifacts(real_public_inputs_root)
        self.assert_broken_profile_rejects_batches(
            self.nodes[0],
            "groth16_bls12_381_poseidon_v1",
            self.real_valid_vector_path,
            36,
            "profile manifest public inputs do not match supported profile",
            "profile_manifest_public_inputs_match",
        )


if __name__ == "__main__":
    ValiditySidechainBadArtifactsTest().main()
