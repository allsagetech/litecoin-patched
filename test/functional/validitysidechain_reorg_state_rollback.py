#!/usr/bin/env python3
# Copyright (c) 2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from decimal import Decimal
import struct

from test_framework.messages import hash256, ser_uint256, uint256_from_str
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


def compute_withdrawal_root(withdrawals):
    encoded_leaves = []
    for withdrawal in withdrawals:
        encoded_leaves.append(
            ser_uint256(int(withdrawal["withdrawal_id"], 16)) +
            amount_to_sats(withdrawal["amount"]).to_bytes(8, "little") +
            ser_uint256(int(get_destination_commitment(withdrawal), 16))
        )
    return compute_merkle_root(encoded_leaves, b"VSCW\x02", b"VSCW\x03", b"VSCW\x01")


def encode_withdrawal_leaf(withdrawal):
    return (
        ser_uint256(int(withdrawal["withdrawal_id"], 16)) +
        amount_to_sats(withdrawal["amount"]).to_bytes(8, "little") +
        ser_uint256(int(get_destination_commitment(withdrawal), 16))
    )


def build_withdrawal_proof(withdrawals, leaf_index):
    assert leaf_index < len(withdrawals)

    level = [hash256_uint256(b"VSCW\x02" + encode_withdrawal_leaf(withdrawal)) for withdrawal in withdrawals]
    siblings = []
    index = leaf_index
    while len(level) > 1:
        sibling_index = index - 1 if index & 1 else min(index + 1, len(level) - 1)
        siblings.append(f"{level[sibling_index]:064x}")

        next_level = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else level[i]
            next_level.append(hash256_uint256(b"VSCW\x03" + ser_uint256(left) + ser_uint256(right)))
        level = next_level
        index >>= 1

    return {
        "leaf_index": leaf_index,
        "leaf_count": len(withdrawals),
        "sibling_hashes": siblings,
    }


def build_verified_withdrawal_proof_entry(withdrawals, leaf_index):
    withdrawal = withdrawals[leaf_index]
    return {
        "withdrawal_id": withdrawal["withdrawal_id"],
        "script": withdrawal["script"],
        "amount": withdrawal["amount"],
        "proof": build_withdrawal_proof(withdrawals, leaf_index),
    }


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


class ValiditySidechainReorgStateRollback(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [
            ["-acceptnonstdtxn=1"],
            ["-acceptnonstdtxn=1"],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        n0 = self.nodes[0]
        n1 = self.nodes[1]

        n0.generatetoaddress(110, n0.getnewaddress())
        self.sync_blocks()

        withdrawals = [
            {
                "withdrawal_id": "77" * 32,
                "amount": Decimal("0.40"),
                "script": build_script_destination(n0),
            }
        ]
        escape_exits = [
            {
                "exit_id": "88" * 32,
                "amount": Decimal("0.35"),
                "script": build_script_destination(n0),
            }
        ]
        for withdrawal in withdrawals:
            withdrawal["destination_commitment"] = compute_script_commitment(withdrawal["script"])
        for exit_leaf in escape_exits:
            exit_leaf["destination_commitment"] = compute_script_commitment(exit_leaf["script"])

        sidechain_id = 23
        supported = get_supported_profile(n0, "scaffold_onchain_da_v1")
        config = build_register_config(
            supported,
            compute_escape_exit_root(escape_exits),
            compute_withdrawal_root(withdrawals),
        )
        withdrawal_proof_entries = [
            build_verified_withdrawal_proof_entry(withdrawals, i)
            for i in range(len(withdrawals))
        ]

        state_proof_sidechain_id = 24
        toy_supported = get_supported_profile(n0, "gnark_groth16_toy_batch_transition_v1")
        state_balance_leaves = [
            {
                "asset_id": "99" * 32,
                "balance": Decimal("0.35"),
            }
        ]
        state_balance_proof, state_balance_root = build_balance_proof(state_balance_leaves, 0)
        state_accounts = [
            {
                "account_id": "aa" * 32,
                "spend_key_commitment": "bb" * 32,
                "balance_root": state_balance_root,
                "account_nonce": 5,
                "last_forced_exit_nonce": 1,
            }
        ]
        state_account_proof, state_root = build_account_state_proof(state_accounts, 0)
        state_proof_claim = {
            "exit_asset_id": state_balance_leaves[0]["asset_id"],
            "script": build_script_destination(n0),
            "amount": Decimal("0.35"),
            "required_account_nonce": state_accounts[0]["account_nonce"],
            "required_last_forced_exit_nonce": state_accounts[0]["last_forced_exit_nonce"],
            "account_proof": state_account_proof,
            "balance_proof": state_balance_proof,
        }
        state_proof_claim["exit_id"] = compute_escape_exit_state_id(
            state_proof_sidechain_id,
            state_proof_claim,
        )
        state_proof_config = build_register_config(
            toy_supported,
            state_root,
            "00" * 32,
        )

        self.log.info("Building common validity-sidechain history on both nodes.")
        n0.sendvaliditysidechainregister(sidechain_id, config)
        n0.generatetoaddress(1, n0.getnewaddress())
        self.sync_blocks()

        n0.sendvaliditydeposit(
            sidechain_id,
            "33" * 32,
            {"address": n0.getnewaddress()},
            Decimal("1.0"),
            7,
        )
        n0.generatetoaddress(1, n0.getnewaddress())
        self.sync_blocks()

        n0.sendvaliditysidechainregister(state_proof_sidechain_id, state_proof_config)
        n0.generatetoaddress(1, n0.getnewaddress())
        self.sync_blocks()
        state_proof_registration_height = get_sidechain(
            n0.getvaliditysidechaininfo(),
            state_proof_sidechain_id,
        )["registration_height"]

        n0.sendvaliditydeposit(
            state_proof_sidechain_id,
            "cc" * 32,
            {"address": n0.getnewaddress()},
            Decimal("0.35"),
            9,
        )
        n0.generatetoaddress(1, n0.getnewaddress())
        self.sync_blocks()

        self.disconnect_nodes(0, 1)

        self.log.info("On node0 only, accept a batch and execute verified withdrawals plus escape exits.")
        sidechain = get_sidechain(n0.getvaliditysidechaininfo(), sidechain_id)
        assert sidechain is not None
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
        batch_res = n0.sendvaliditybatch(sidechain_id, public_inputs)
        batch_txid = batch_res["txid"]
        n0.generatetoaddress(1, n0.getnewaddress())
        batch_height = n0.getblockcount()

        verified_withdrawal_res = n0.sendverifiedwithdrawals(sidechain_id, 1, withdrawal_proof_entries)
        verified_withdrawal_txid = verified_withdrawal_res["txid"]
        n0.generatetoaddress(1, n0.getnewaddress())

        escape_height = batch_height + config["escape_hatch_delay"]
        state_proof_escape_height = state_proof_registration_height + state_proof_config["escape_hatch_delay"]
        current_height = n0.getblockcount()
        target_height = max(escape_height, state_proof_escape_height)
        if current_height < target_height:
            n0.generatetoaddress(target_height - current_height, n0.getnewaddress())

        escape_exit_rpc_entries = [
            {
                "exit_id": exit_leaf["exit_id"],
                "script": exit_leaf["script"],
                "amount": exit_leaf["amount"],
            }
            for exit_leaf in escape_exits
        ]
        sidechain = get_sidechain(n0.getvaliditysidechaininfo(), sidechain_id)
        assert sidechain is not None
        escape_exit_res = n0.sendescapeexit(sidechain_id, sidechain["current_state_root"], escape_exit_rpc_entries)
        escape_exit_txid = escape_exit_res["txid"]
        n0.generatetoaddress(1, n0.getnewaddress())

        state_proof_escape_res = n0.sendescapeexit(
            state_proof_sidechain_id,
            state_root,
            [state_proof_claim],
        )
        state_proof_escape_txid = state_proof_escape_res["txid"]
        n0.generatetoaddress(1, n0.getnewaddress())

        info_n0 = n0.getvaliditysidechaininfo()
        sidechain_n0 = get_sidechain(info_n0, sidechain_id)
        state_proof_sidechain_n0 = get_sidechain(info_n0, state_proof_sidechain_id)
        assert sidechain_n0 is not None
        assert state_proof_sidechain_n0 is not None
        recompute_fallbacks = int(info_n0["state_cache"]["recompute_fallbacks"])
        assert_equal(sidechain_n0["latest_batch_number"], 1)
        assert_equal(len(sidechain_n0["accepted_batches"]), 1)
        assert_equal(sidechain_n0["executed_withdrawal_count"], len(withdrawals))
        assert_equal(sidechain_n0["executed_escape_exit_count"], len(escape_exits))
        assert_equal(sidechain_n0["escrow_balance"], amount_to_sats(Decimal("0.25")))
        assert_equal(state_proof_sidechain_n0["executed_escape_exit_count"], 1)
        assert_equal(state_proof_sidechain_n0["escrow_balance"], 0)

        self.log.info("Mine a longer competing fork on node1 that omits the batch, withdrawal execution, and both escape-exit variants.")
        blocks_needed = (n0.getblockcount() - n1.getblockcount()) + 1
        n1.generatetoaddress(blocks_needed, n1.getnewaddress())

        self.connect_nodes(0, 1)
        self.sync_blocks()

        self.log.info("After reorg, the sidechain state and state-proof escape-exit replay state must roll back.")
        info_n0_after = n0.getvaliditysidechaininfo()
        info_n1_after = n1.getvaliditysidechaininfo()
        sidechain_n0_after = get_sidechain(info_n0_after, sidechain_id)
        sidechain_n1_after = get_sidechain(info_n1_after, sidechain_id)
        state_proof_sidechain_n0_after = get_sidechain(info_n0_after, state_proof_sidechain_id)
        state_proof_sidechain_n1_after = get_sidechain(info_n1_after, state_proof_sidechain_id)
        assert sidechain_n0_after is not None
        assert sidechain_n1_after is not None
        assert state_proof_sidechain_n0_after is not None
        assert state_proof_sidechain_n1_after is not None
        assert_equal(int(info_n0_after["state_cache"]["recompute_fallbacks"]), recompute_fallbacks)
        assert_equal(sidechain_n0_after["latest_batch_number"], 0)
        assert_equal(sidechain_n1_after["latest_batch_number"], 0)
        assert_equal(sidechain_n0_after["accepted_batches"], [])
        assert_equal(sidechain_n1_after["accepted_batches"], [])
        assert_equal(sidechain_n0_after["executed_withdrawal_count"], 0)
        assert_equal(sidechain_n1_after["executed_withdrawal_count"], 0)
        assert_equal(sidechain_n0_after["executed_escape_exit_count"], 0)
        assert_equal(sidechain_n1_after["executed_escape_exit_count"], 0)
        assert_equal(sidechain_n0_after["escrow_balance"], 100000000)
        assert_equal(sidechain_n1_after["escrow_balance"], 100000000)
        assert_equal(sidechain_n0_after["queue_state"]["pending_message_count"], 1)
        assert_equal(sidechain_n1_after["queue_state"]["pending_message_count"], 1)
        assert_equal(state_proof_sidechain_n0_after["executed_escape_exit_count"], 0)
        assert_equal(state_proof_sidechain_n1_after["executed_escape_exit_count"], 0)
        assert_equal(state_proof_sidechain_n0_after["escrow_balance"], amount_to_sats(Decimal("0.35")))
        assert_equal(state_proof_sidechain_n1_after["escrow_balance"], amount_to_sats(Decimal("0.35")))

        self.restart_node(0, extra_args=["-acceptnonstdtxn=1"])
        n0 = self.nodes[0]
        info_after_restart = n0.getvaliditysidechaininfo()
        sidechain_after_restart = get_sidechain(info_after_restart, sidechain_id)
        state_proof_sidechain_after_restart = get_sidechain(info_after_restart, state_proof_sidechain_id)
        assert sidechain_after_restart is not None
        assert state_proof_sidechain_after_restart is not None
        assert_equal(int(info_after_restart["state_cache"]["recompute_fallbacks"]), recompute_fallbacks)
        assert_equal(sidechain_after_restart["latest_batch_number"], 0)
        assert_equal(sidechain_after_restart["accepted_batches"], [])
        assert_equal(sidechain_after_restart["executed_withdrawal_count"], 0)
        assert_equal(sidechain_after_restart["executed_escape_exit_count"], 0)
        assert_equal(sidechain_after_restart["escrow_balance"], 100000000)
        assert_equal(state_proof_sidechain_after_restart["executed_escape_exit_count"], 0)
        assert_equal(state_proof_sidechain_after_restart["escrow_balance"], amount_to_sats(Decimal("0.35")))

        self.log.info("Re-submitting the same batch, explicit withdrawal proofs, and both escape-exit variants after reorg should succeed.")
        sidechain_after_restart = get_sidechain(n0.getvaliditysidechaininfo(), sidechain_id)
        public_inputs["prior_state_root"] = sidechain_after_restart["current_state_root"]
        public_inputs["new_state_root"] = sidechain_after_restart["current_state_root"]
        public_inputs["l1_message_root_before"] = sidechain_after_restart["queue_state"]["root"]
        public_inputs["l1_message_root_after"] = sidechain_after_restart["queue_state"]["root"]
        public_inputs["withdrawal_root"] = sidechain_after_restart["current_withdrawal_root"]
        public_inputs["data_root"] = sidechain_after_restart["current_data_root"]
        mempool = n0.getrawmempool()
        if batch_txid in mempool:
            self.log.info("The original batch transaction was restored to mempool after the reorg.")
        else:
            batch_res = n0.sendvaliditybatch(sidechain_id, public_inputs)
            batch_txid = batch_res["txid"]
        assert batch_txid in n0.getrawmempool()
        n0.generatetoaddress(1, n0.getnewaddress())
        batch_height = n0.getblockcount()

        mempool = n0.getrawmempool()
        if verified_withdrawal_txid in mempool:
            self.log.info("The original verified-withdrawal transaction was restored to mempool after the reorg.")
        else:
            verified_withdrawal_res = n0.sendverifiedwithdrawals(sidechain_id, 1, withdrawal_proof_entries)
            verified_withdrawal_txid = verified_withdrawal_res["txid"]
        assert verified_withdrawal_txid in n0.getrawmempool()
        n0.generatetoaddress(1, n0.getnewaddress())

        escape_height = batch_height + config["escape_hatch_delay"]
        state_proof_escape_height = state_proof_registration_height + state_proof_config["escape_hatch_delay"]
        current_height = n0.getblockcount()
        target_height = max(escape_height, state_proof_escape_height)
        if current_height < target_height:
            n0.generatetoaddress(target_height - current_height, n0.getnewaddress())

        sidechain_after_restart = get_sidechain(n0.getvaliditysidechaininfo(), sidechain_id)
        assert sidechain_after_restart is not None
        mempool = n0.getrawmempool()
        if escape_exit_txid in mempool:
            self.log.info("The original escape-exit transaction was restored to mempool after the reorg.")
        else:
            escape_exit_res = n0.sendescapeexit(
                sidechain_id,
                sidechain_after_restart["current_state_root"],
                escape_exit_rpc_entries,
            )
            escape_exit_txid = escape_exit_res["txid"]
        assert escape_exit_txid in n0.getrawmempool()
        n0.generatetoaddress(1, n0.getnewaddress())

        mempool = n0.getrawmempool()
        if state_proof_escape_txid in mempool:
            self.log.info("The original state-proof escape-exit transaction was restored to mempool after the reorg.")
        else:
            state_proof_escape_res = n0.sendescapeexit(
                state_proof_sidechain_id,
                state_root,
                [state_proof_claim],
            )
            state_proof_escape_txid = state_proof_escape_res["txid"]
        assert state_proof_escape_txid in n0.getrawmempool()
        n0.generatetoaddress(1, n0.getnewaddress())

        final_sidechain = get_sidechain(n0.getvaliditysidechaininfo(), sidechain_id)
        final_state_proof_sidechain = get_sidechain(n0.getvaliditysidechaininfo(), state_proof_sidechain_id)
        assert final_sidechain is not None
        assert final_state_proof_sidechain is not None
        assert_equal(final_sidechain["latest_batch_number"], 1)
        assert_equal(len(final_sidechain["accepted_batches"]), 1)
        assert_equal(final_sidechain["executed_withdrawal_count"], len(withdrawals))
        assert_equal(final_sidechain["executed_escape_exit_count"], len(escape_exits))
        assert_equal(final_sidechain["escrow_balance"], amount_to_sats(Decimal("0.25")))
        assert_equal(final_state_proof_sidechain["executed_escape_exit_count"], 1)
        assert_equal(final_state_proof_sidechain["escrow_balance"], 0)


if __name__ == "__main__":
    ValiditySidechainReorgStateRollback().main()
