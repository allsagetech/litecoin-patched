#!/usr/bin/env python3
# Copyright (c) 2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.
"""Exercise canonical vs migration-only validity-sidechain registration policy."""

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


def get_supported_profile(node, profile_name):
    info = node.getvaliditysidechaininfo()
    for supported in info["supported_proof_configs"]:
        if supported["profile_name"] == profile_name:
            return supported
    raise AssertionError(f"missing supported proof profile {profile_name}")


class ValiditySidechainRegistrationPolicyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [
            ["-acceptnonstdtxn=1"],
            ["-acceptnonstdtxn=1", "-validityallowmigrationprofiles=1"],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def _should_enable_validity_migration_profiles(self):
        return False

    def run_test(self):
        node_plain, node_opt_in = self.nodes
        node_plain.generatetoaddress(101, node_plain.getnewaddress())
        node_opt_in.generatetoaddress(101, node_opt_in.getnewaddress())
        self.sync_all()

        info = node_plain.getvaliditysidechaininfo()
        assert_equal(info["canonical_profile_name"], "groth16_bls12_381_poseidon_v2")
        assert_equal(info["migration_profile_registration_requires_opt_in"], True)

        canonical = get_supported_profile(node_plain, "groth16_bls12_381_poseidon_v2")
        migration = get_supported_profile(node_plain, "scaffold_onchain_da_v1")
        assert_equal(canonical["registration_default_allowed"], True)
        assert_equal(canonical["registration_requires_explicit_opt_in"], False)
        assert_equal(migration["registration_default_allowed"], False)
        assert_equal(migration["registration_requires_explicit_opt_in"], True)

        self.log.info("Canonical v2 registration should work without any migration-profile opt-in.")
        canonical_res = node_plain.sendvaliditysidechainregister(41, build_register_config(canonical))
        assert_equal(canonical_res["sidechain_id"], 41)
        assert_equal(canonical_res["canonical_target"], True)
        assert_equal(canonical_res["migration_only"], False)
        assert_equal(canonical_res["profile_lifecycle"], "canonical_target")
        node_plain.generate(1)
        self.sync_all()

        self.log.info("Migration-only registration should fail without the explicit node opt-in.")
        assert_raises_rpc_error(
            -8,
            "retained only for migration/testing",
            node_plain.sendvaliditysidechainregister,
            42,
            build_register_config(migration),
        )

        self.log.info("Migration-only registration should succeed when the node opts in explicitly.")
        migration_res = node_opt_in.sendvaliditysidechainregister(42, build_register_config(migration))
        assert_equal(migration_res["sidechain_id"], 42)
        assert_equal(migration_res["canonical_target"], False)
        assert_equal(migration_res["migration_only"], True)
        assert_equal(migration_res["profile_lifecycle"], "scaffold_migration")


if __name__ == "__main__":
    ValiditySidechainRegistrationPolicyTest().main()
