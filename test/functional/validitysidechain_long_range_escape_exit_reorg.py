#!/usr/bin/env python3
# Copyright (c) 2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from decimal import Decimal
import struct

from test_framework.messages import hash256, ser_uint256, uint256_from_str
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


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


def get_supported_profile(node, profile_name):
    info = node.getvaliditysidechaininfo()
    for supported in info["supported_proof_configs"]:
        if supported["profile_name"] == profile_name:
            return supported
    raise AssertionError(f"missing supported proof profile {profile_name}")


def get_sidechain(info, sidechain_id):
    for sidechain in info["sidechains"]:
        if sidechain["id"] == sidechain_id:
            return sidechain
    return None


def amount_to_sats(amount):
    return int(amount * Decimal("100000000"))


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


def compute_escape_exit_root(exits):
    encoded_leaves = []
    for exit_leaf in exits:
        encoded_leaves.append(
            ser_uint256(int(exit_leaf["exit_id"], 16)) +
            amount_to_sats(exit_leaf["amount"]).to_bytes(8, "little") +
            ser_uint256(int(get_destination_commitment(exit_leaf), 16))
        )
    return compute_merkle_root(encoded_leaves, b"VSCE\x02", b"VSCE\x03", b"VSCE\x01")


def build_internal_merkle_proof(encoded_leaves, leaf_magic, node_magic, leaf_index):
    assert leaf_index < len(encoded_leaves)

    level = [hash256_uint256(leaf_magic + leaf) for leaf in encoded_leaves]
    siblings = []
    index = leaf_index
    while len(level) > 1:
        sibling_index = index - 1 if index & 1 else min(index + 1, len(level) - 1)
        siblings.append(f"{level[sibling_index]:064x}")

        next_level = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else level[i]
            next_level.append(hash256_uint256(node_magic + ser_uint256(left) + ser_uint256(right)))
        level = next_level
        index >>= 1

    return siblings, f"{level[0]:064x}"


def encode_balance_leaf(balance):
    return (
        ser_uint256(int(balance["asset_id"], 16)) +
        amount_to_sats(balance["balance"]).to_bytes(8, "little")
    )


def build_balance_proof(balances, leaf_index):
    encoded_leaves = [encode_balance_leaf(balance) for balance in balances]
    sibling_hashes, root = build_internal_merkle_proof(encoded_leaves, b"VSCS\x01", b"VSCS\x02", leaf_index)
    balance = balances[leaf_index]
    return {
        "asset_id": balance["asset_id"],
        "balance": balance["balance"],
        "leaf_index": leaf_index,
        "leaf_count": len(balances),
        "sibling_hashes": sibling_hashes,
    }, root


def encode_account_state_leaf(account):
    return (
        ser_uint256(int(account["account_id"], 16)) +
        ser_uint256(int(account["spend_key_commitment"], 16)) +
        ser_uint256(int(account["balance_root"], 16)) +
        int(account["account_nonce"]).to_bytes(8, "little") +
        int(account["last_forced_exit_nonce"]).to_bytes(8, "little")
    )


def build_account_state_proof(accounts, leaf_index):
    encoded_leaves = [encode_account_state_leaf(account) for account in accounts]
    sibling_hashes, root = build_internal_merkle_proof(encoded_leaves, b"VSCS\x03", b"VSCS\x04", leaf_index)
    account = accounts[leaf_index]
    return {
        "account_id": account["account_id"],
        "spend_key_commitment": account["spend_key_commitment"],
        "balance_root": account["balance_root"],
        "account_nonce": account["account_nonce"],
        "last_forced_exit_nonce": account["last_forced_exit_nonce"],
        "leaf_index": leaf_index,
        "leaf_count": len(accounts),
        "sibling_hashes": sibling_hashes,
    }, root


def compute_escape_exit_state_claim_key(sidechain_id, claim):
    payload = (
        b"VSCE\x04" +
        bytes([sidechain_id]) +
        ser_uint256(int(claim["account_proof"]["account_id"], 16)) +
        ser_uint256(int(claim["exit_asset_id"], 16)) +
        int(claim["required_account_nonce"]).to_bytes(8, "little") +
        int(claim["required_last_forced_exit_nonce"]).to_bytes(8, "little")
    )
    return f"{hash256_uint256(payload):064x}"


def compute_escape_exit_state_id(sidechain_id, claim):
    payload = (
        b"VSCE\x05" +
        ser_uint256(int(compute_escape_exit_state_claim_key(sidechain_id, claim), 16)) +
        amount_to_sats(claim["amount"]).to_bytes(8, "little") +
        ser_uint256(int(get_destination_commitment(claim), 16))
    )
    return f"{hash256_uint256(payload):064x}"


def build_script_destination(node):
    return node.getaddressinfo(node.getnewaddress())["scriptPubKey"]


class ValiditySidechainLongRangeEscapeExitReorg(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.common_args = ["-acceptnonstdtxn=1", "-persistmempool=0"]
        self.extra_args = [self.common_args, self.common_args]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        n0 = self.nodes[0]
        n1 = self.nodes[1]

        n0.generatetoaddress(110, n0.getnewaddress())
        self.sync_blocks()
        n0.sendtoaddress(n1.getnewaddress(), Decimal("5.0"))
        n0.generatetoaddress(1, n0.getnewaddress())
        self.sync_blocks()

        legacy_sidechain_id = 65
        legacy_supported = get_supported_profile(n0, "scaffold_onchain_da_v1")
        legacy_exit = {
            "exit_id": "88" * 32,
            "amount": Decimal("0.35"),
            "script": build_script_destination(n0),
        }
        legacy_exit["destination_commitment"] = compute_script_commitment(legacy_exit["script"])
        legacy_config = build_register_config(
            legacy_supported,
            compute_escape_exit_root([legacy_exit]),
        )

        state_sidechain_id = 66
        toy_supported = get_supported_profile(n0, "gnark_groth16_toy_batch_transition_v1")
        state_balance_leaves = [{
            "asset_id": "99" * 32,
            "balance": Decimal("0.40"),
        }]
        state_balance_proof, state_balance_root = build_balance_proof(state_balance_leaves, 0)
        state_accounts = [{
            "account_id": "aa" * 32,
            "spend_key_commitment": "bb" * 32,
            "balance_root": state_balance_root,
            "account_nonce": 5,
            "last_forced_exit_nonce": 1,
        }]
        state_account_proof, state_root = build_account_state_proof(state_accounts, 0)
        state_claim = {
            "exit_asset_id": state_balance_leaves[0]["asset_id"],
            "script": build_script_destination(n0),
            "amount": Decimal("0.35"),
            "required_account_nonce": state_accounts[0]["account_nonce"],
            "required_last_forced_exit_nonce": state_accounts[0]["last_forced_exit_nonce"],
            "account_proof": state_account_proof,
            "balance_proof": state_balance_proof,
        }
        state_claim["exit_id"] = compute_escape_exit_state_id(
            state_sidechain_id,
            state_claim,
        )
        state_config = build_register_config(toy_supported, state_root)

        self.log.info("Build shared legacy and state-proof sidechain history before the split.")
        n0.sendvaliditysidechainregister(legacy_sidechain_id, legacy_config)
        n0.generatetoaddress(1, n0.getnewaddress())
        self.sync_blocks()
        legacy_registration_height = get_sidechain(
            n0.getvaliditysidechaininfo(),
            legacy_sidechain_id,
        )["registration_height"]

        n0.sendvaliditydeposit(
            legacy_sidechain_id,
            "33" * 32,
            {"address": n0.getnewaddress()},
            Decimal("1.0"),
            7,
            "44" * 32,
        )
        n0.generatetoaddress(1, n0.getnewaddress())
        self.sync_blocks()

        n0.sendvaliditysidechainregister(state_sidechain_id, state_config)
        n0.generatetoaddress(1, n0.getnewaddress())
        self.sync_blocks()
        state_registration_height = get_sidechain(
            n0.getvaliditysidechaininfo(),
            state_sidechain_id,
        )["registration_height"]

        n0.sendvaliditydeposit(
            state_sidechain_id,
            "cc" * 32,
            {"address": n0.getnewaddress()},
            Decimal("0.40"),
            9,
            "dd" * 32,
        )
        n0.generatetoaddress(1, n0.getnewaddress())
        self.sync_blocks()

        target_height = max(
            legacy_registration_height + legacy_config["escape_hatch_delay"],
            state_registration_height + state_config["escape_hatch_delay"],
        )
        current_height = n0.getblockcount()
        if current_height < target_height:
            n0.generatetoaddress(target_height - current_height, n0.getnewaddress())
            self.sync_blocks()

        self.disconnect_nodes(0, 1)

        self.log.info("Execute both escape-exit variants on node0, then extend that losing fork with extra blocks.")
        legacy_sidechain_n0 = get_sidechain(n0.getvaliditysidechaininfo(), legacy_sidechain_id)
        assert legacy_sidechain_n0 is not None
        legacy_escape_entries = [{
            "exit_id": legacy_exit["exit_id"],
            "script": legacy_exit["script"],
            "amount": legacy_exit["amount"],
        }]
        legacy_escape_res = n0.sendescapeexit(
            legacy_sidechain_id,
            legacy_sidechain_n0["current_state_root"],
            legacy_escape_entries,
        )
        legacy_escape_txid = legacy_escape_res["txid"]
        n0.generatetoaddress(1, n0.getnewaddress())

        state_escape_res = n0.sendescapeexit(
            state_sidechain_id,
            state_root,
            [state_claim],
        )
        state_escape_txid = state_escape_res["txid"]
        n0.generatetoaddress(1, n0.getnewaddress())
        n0.generatetoaddress(4, n0.getnewaddress())

        info_n0 = n0.getvaliditysidechaininfo()
        legacy_n0 = get_sidechain(info_n0, legacy_sidechain_id)
        state_n0 = get_sidechain(info_n0, state_sidechain_id)
        assert legacy_n0 is not None
        assert state_n0 is not None
        recompute_fallbacks = int(info_n0["state_cache"]["recompute_fallbacks"])
        assert_equal(legacy_n0["executed_escape_exit_count"], 1)
        assert_equal(state_n0["executed_escape_exit_count"], 1)
        assert_equal(legacy_n0["escrow_balance"], amount_to_sats(Decimal("0.65")))
        assert_equal(state_n0["escrow_balance"], amount_to_sats(Decimal("0.05")))

        self.log.info("Mine a deeper competing fork on node1 that omits both escape exits entirely.")
        blocks_needed = (n0.getblockcount() - n1.getblockcount()) + 1
        n1.generatetoaddress(blocks_needed, n1.getnewaddress())

        self.connect_nodes(0, 1)
        self.sync_blocks()

        info_after = n0.getvaliditysidechaininfo()
        legacy_after = get_sidechain(info_after, legacy_sidechain_id)
        state_after = get_sidechain(info_after, state_sidechain_id)
        assert legacy_after is not None
        assert state_after is not None
        assert_equal(int(info_after["state_cache"]["recompute_fallbacks"]), recompute_fallbacks)
        assert_equal(legacy_after["executed_escape_exit_count"], 0)
        assert_equal(state_after["executed_escape_exit_count"], 0)
        assert_equal(legacy_after["escrow_balance"], amount_to_sats(Decimal("1.0")))
        assert_equal(state_after["escrow_balance"], amount_to_sats(Decimal("0.40")))

        self.restart_node(0, extra_args=self.common_args)
        n0 = self.nodes[0]
        self.connect_nodes(0, 1)
        self.sync_blocks()

        info_after_restart = n0.getvaliditysidechaininfo()
        legacy_after_restart = get_sidechain(info_after_restart, legacy_sidechain_id)
        state_after_restart = get_sidechain(info_after_restart, state_sidechain_id)
        assert legacy_after_restart is not None
        assert state_after_restart is not None
        assert_equal(int(info_after_restart["state_cache"]["recompute_fallbacks"]), recompute_fallbacks)
        assert_equal(legacy_after_restart["executed_escape_exit_count"], 0)
        assert_equal(state_after_restart["executed_escape_exit_count"], 0)
        assert_equal(legacy_after_restart["escrow_balance"], amount_to_sats(Decimal("1.0")))
        assert_equal(state_after_restart["escrow_balance"], amount_to_sats(Decimal("0.40")))

        self.log.info("Restore or re-submit both escape exits after the long-range reorg.")
        mempool = n0.getrawmempool()
        if legacy_escape_txid in mempool:
            self.log.info("The original legacy escape-exit transaction was restored to mempool after the reorg.")
        else:
            legacy_escape_res = n0.sendescapeexit(
                legacy_sidechain_id,
                legacy_after_restart["current_state_root"],
                legacy_escape_entries,
            )
            legacy_escape_txid = legacy_escape_res["txid"]
        assert legacy_escape_txid in n0.getrawmempool()
        n0.generatetoaddress(1, n0.getnewaddress())

        mempool = n0.getrawmempool()
        if state_escape_txid in mempool:
            self.log.info("The original state-proof escape-exit transaction was restored to mempool after the reorg.")
        else:
            state_tx = n0.gettransaction(state_escape_txid)
            if state_tx["confirmations"] > 0:
                self.log.info("The original state-proof escape-exit transaction was restored and mined with the previous block.")
            else:
                state_escape_res = n0.sendescapeexit(
                    state_sidechain_id,
                    state_root,
                    [state_claim],
                )
                state_escape_txid = state_escape_res["txid"]
        if n0.gettransaction(state_escape_txid)["confirmations"] <= 0:
            assert state_escape_txid in n0.getrawmempool()
            n0.generatetoaddress(1, n0.getnewaddress())
        self.sync_blocks()

        final_info = n0.getvaliditysidechaininfo()
        final_legacy = get_sidechain(final_info, legacy_sidechain_id)
        final_state = get_sidechain(final_info, state_sidechain_id)
        assert final_legacy is not None
        assert final_state is not None
        assert_equal(final_legacy["executed_escape_exit_count"], 1)
        assert_equal(final_state["executed_escape_exit_count"], 1)
        assert_equal(final_legacy["escrow_balance"], amount_to_sats(Decimal("0.65")))
        assert_equal(final_state["escrow_balance"], amount_to_sats(Decimal("0.05")))


if __name__ == "__main__":
    ValiditySidechainLongRangeEscapeExitReorg().main()
