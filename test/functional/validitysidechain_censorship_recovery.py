#!/usr/bin/env python3
# Copyright (c) 2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from decimal import Decimal
import struct

from test_framework.messages import hash256, ser_uint256, uint256_from_str
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


class ValiditySidechainCensorshipRecovery(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.generatetoaddress(101, node.getnewaddress())

        scaffold_supported = get_supported_profile(node, "scaffold_onchain_da_v1")
        native_toy_supported = get_supported_profile(node, "native_blst_groth16_toy_batch_transition_v1")

        self.log.info("A live sequencer cannot censor a matured force-exit request forever.")
        live_sidechain_id = 40
        live_config = build_register_config(scaffold_supported, "11" * 32, "22" * 32)
        node.sendvaliditysidechainregister(live_sidechain_id, live_config)
        node.generatetoaddress(1, node.getnewaddress())

        node.sendvaliditydeposit(
            live_sidechain_id,
            "33" * 32,
            {"address": node.getnewaddress()},
            Decimal("1.00"),
            7,
            "44" * 32,
        )
        node.generatetoaddress(1, node.getnewaddress())

        node.sendforceexitrequest(
            live_sidechain_id,
            "55" * 32,
            "66" * 32,
            Decimal("0.50"),
            {"address": node.getnewaddress()},
            9,
        )
        node.generatetoaddress(1, node.getnewaddress())
        request_height = node.getblockcount()

        target_height = request_height + live_config["force_inclusion_delay"]
        if node.getblockcount() < target_height:
            node.generatetoaddress(target_height - node.getblockcount(), node.getnewaddress())

        live_sidechain = get_sidechain(node.getvaliditysidechaininfo(), live_sidechain_id)
        assert live_sidechain is not None
        assert_equal(live_sidechain["queue_state"]["pending_message_count"], 2)
        assert_equal(live_sidechain["queue_state"]["matured_force_exit_count"], 1)

        assert_raises_rpc_error(
            -8,
            "batch must consume all matured force-exit requests in reachable queue prefix",
            node.sendvaliditybatch,
            live_sidechain_id,
            {
                "batch_number": 1,
                "new_state_root": live_sidechain["current_state_root"],
                "consumed_queue_messages": 0,
            },
        )

        batch_res = node.sendvaliditybatch(
            live_sidechain_id,
            {
                "batch_number": 1,
                "new_state_root": live_sidechain["current_state_root"],
                "consumed_queue_messages": 2,
            },
        )
        assert_equal(batch_res["auto_scaffold_proof"], True)
        node.generatetoaddress(1, node.getnewaddress())

        live_sidechain = get_sidechain(node.getvaliditysidechaininfo(), live_sidechain_id)
        assert live_sidechain is not None
        assert_equal(live_sidechain["latest_batch_number"], 1)
        assert_equal(live_sidechain["queue_state"]["head_index"], 2)
        assert_equal(live_sidechain["queue_state"]["pending_message_count"], 0)
        assert_equal(live_sidechain["queue_state"]["pending_force_exit_count"], 0)
        assert_equal(live_sidechain["queue_state"]["matured_force_exit_count"], 0)
        assert_equal(live_sidechain["accepted_batches"][0]["consumed_queue_messages"], 2)

        self.log.info("A halted sequencer still leaves users with an escape-exit path.")
        halt_sidechain_id = 41
        balance_leaves = [
            {
                "asset_id": "aa" * 32,
                "balance": Decimal("0.18"),
            },
        ]
        balance_proof, balance_root = build_balance_proof(balance_leaves, 0)
        accounts = [
            {
                "account_id": "bb" * 32,
                "spend_key_commitment": "cc" * 32,
                "balance_root": balance_root,
                "account_nonce": 5,
                "last_forced_exit_nonce": 2,
            },
        ]
        account_proof, state_root = build_account_state_proof(accounts, 0)
        halt_config = build_register_config(native_toy_supported, state_root, "00" * 32)
        node.sendvaliditysidechainregister(halt_sidechain_id, halt_config)
        node.generatetoaddress(1, node.getnewaddress())

        node.sendvaliditydeposit(
            halt_sidechain_id,
            "dd" * 32,
            {"address": node.getnewaddress()},
            Decimal("0.18"),
        )
        node.generatetoaddress(1, node.getnewaddress())

        claim = {
            "exit_asset_id": balance_leaves[0]["asset_id"],
            "script": build_script_destination(node),
            "amount": Decimal("0.18"),
            "required_account_nonce": accounts[0]["account_nonce"],
            "required_last_forced_exit_nonce": accounts[0]["last_forced_exit_nonce"],
            "account_proof": account_proof,
            "balance_proof": balance_proof,
        }
        claim["exit_id"] = compute_escape_exit_state_id(halt_sidechain_id, claim)

        assert_raises_rpc_error(
            -8,
            "escape hatch delay not reached",
            node.sendescapeexit,
            halt_sidechain_id,
            state_root,
            [claim],
        )

        node.generatetoaddress(halt_config["escape_hatch_delay"], node.getnewaddress())

        halt_sidechain = get_sidechain(node.getvaliditysidechaininfo(), halt_sidechain_id)
        assert halt_sidechain is not None
        assert_equal(halt_sidechain["current_state_root"], state_root)
        assert_equal(halt_sidechain["escrow_balance"], amount_to_sats(Decimal("0.18")))

        escape_res = node.sendescapeexit(halt_sidechain_id, state_root, [claim])
        assert_equal(escape_res["state_root_reference"], state_root)
        assert_equal(escape_res["exit_count"], 1)
        node.generatetoaddress(1, node.getnewaddress())

        halt_sidechain = get_sidechain(node.getvaliditysidechaininfo(), halt_sidechain_id)
        assert halt_sidechain is not None
        assert_equal(halt_sidechain["executed_escape_exit_count"], 1)
        assert_equal(halt_sidechain["escrow_balance"], 0)


if __name__ == '__main__':
    ValiditySidechainCensorshipRecovery().main()
