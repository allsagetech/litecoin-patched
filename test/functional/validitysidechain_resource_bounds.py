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


def encode_withdrawal_leaf(withdrawal):
    return (
        ser_uint256(int(withdrawal["withdrawal_id"], 16)) +
        amount_to_sats(withdrawal["amount"]).to_bytes(8, "little") +
        ser_uint256(int(get_destination_commitment(withdrawal), 16))
    )


def compute_withdrawal_root(withdrawals):
    return compute_merkle_root(
        [encode_withdrawal_leaf(withdrawal) for withdrawal in withdrawals],
        b"VSCW\x02",
        b"VSCW\x03",
        b"VSCW\x01",
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


def compute_data_root(chunks):
    payload = bytearray(b"VSCR\x01")
    payload.extend(struct.pack("<I", len(chunks)))
    for chunk in chunks:
        payload.extend(struct.pack("<I", len(chunk)))
        payload.extend(chunk)
    return f"{hash256_uint256(bytes(payload)):064x}"


def build_script_destination(node):
    return node.getaddressinfo(node.getnewaddress())["scriptPubKey"]


class ValiditySidechainResourceBounds(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.generatetoaddress(101, node.getnewaddress())

        self.log.info("Accepting the exact queue-consumption limit of 1024 pending deposit messages.")
        scaffold_supported = get_supported_profile(node, "scaffold_onchain_da_v1")
        queue_sidechain_id = 42
        queue_config = build_register_config(scaffold_supported, "11" * 32, "22" * 32)
        node.sendvaliditysidechainregister(queue_sidechain_id, queue_config)
        node.generate(1)

        refund_address = node.getnewaddress()
        queue_message_limit = 1024
        deposit_amount = Decimal("0.001")
        deposits_per_block = 20
        for deposit_index in range(queue_message_limit):
            node.sendvaliditydeposit(
                queue_sidechain_id,
                f"{deposit_index + 1:064x}",
                {"address": refund_address},
                deposit_amount,
            )
            if (deposit_index + 1) % deposits_per_block == 0 or deposit_index + 1 == queue_message_limit:
                node.generate(1)

        queue_sidechain = get_sidechain(node.getvaliditysidechaininfo(), queue_sidechain_id)
        assert queue_sidechain is not None
        assert_equal(queue_sidechain["queue_state"]["pending_message_count"], queue_message_limit)
        assert_equal(queue_sidechain["queue_state"]["pending_deposit_count"], queue_message_limit)
        assert_equal(queue_sidechain["queue_state"]["head_index"], 0)
        assert_equal(queue_sidechain["escrow_balance"], amount_to_sats(deposit_amount * queue_message_limit))

        batch_res = node.sendvaliditybatch(
            queue_sidechain_id,
            {
                "batch_number": 1,
                "new_state_root": queue_sidechain["current_state_root"],
                "consumed_queue_messages": queue_message_limit,
            },
        )
        assert_equal(batch_res["auto_scaffold_proof"], True)
        node.generate(1)

        queue_sidechain = get_sidechain(node.getvaliditysidechaininfo(), queue_sidechain_id)
        assert queue_sidechain is not None
        assert_equal(queue_sidechain["latest_batch_number"], 1)
        assert_equal(queue_sidechain["accepted_batches"][0]["consumed_queue_messages"], queue_message_limit)
        assert_equal(queue_sidechain["queue_state"]["pending_message_count"], 0)
        assert_equal(queue_sidechain["queue_state"]["pending_deposit_count"], 0)
        assert_equal(queue_sidechain["queue_state"]["head_index"], queue_message_limit)

        self.log.info("Accepting the exact DA payload and chunk-count limits in one transition batch.")
        transition_supported = get_supported_profile(node, "scaffold_transition_da_v1")
        da_sidechain_id = 43
        da_config = build_register_config(transition_supported, "33" * 32, "44" * 32)
        node.sendvaliditysidechainregister(da_sidechain_id, da_config)
        node.generate(1)

        da_chunks = [bytes([chunk_index % 251 + 1]) * 256 for chunk_index in range(256)]
        assert_equal(sum(len(chunk) for chunk in da_chunks), da_config["max_batch_data_bytes"])

        da_public_inputs = {
            "batch_number": 1,
            "new_state_root": "55" * 32,
            "consumed_queue_messages": 0,
            "withdrawal_root": "66" * 32,
            "data_root": compute_data_root(da_chunks),
            "data_size": da_config["max_batch_data_bytes"],
        }
        da_batch_res = node.sendvaliditybatch(
            da_sidechain_id,
            da_public_inputs,
            None,
            [chunk.hex() for chunk in da_chunks],
        )
        assert_equal(da_batch_res["auto_scaffold_proof"], True)
        node.generate(1)

        da_sidechain = get_sidechain(node.getvaliditysidechaininfo(), da_sidechain_id)
        assert da_sidechain is not None
        assert_equal(da_sidechain["latest_batch_number"], 1)
        assert_equal(da_sidechain["current_state_root"], da_public_inputs["new_state_root"])
        assert_equal(da_sidechain["current_withdrawal_root"], da_public_inputs["withdrawal_root"])
        assert_equal(da_sidechain["current_data_root"], da_public_inputs["data_root"])
        assert_equal(da_sidechain["accepted_batches"][0]["data_size"], da_public_inputs["data_size"])
        assert_equal(da_sidechain["accepted_batches"][0]["published_data_chunk_count"], len(da_chunks))
        assert_equal(da_sidechain["accepted_batches"][0]["published_data_bytes"], da_public_inputs["data_size"])

        self.log.info("Accepting the exact verified-withdrawal execution fanout limit of 128 proofs.")
        withdrawal_sidechain_id = 44
        withdrawal_count_limit = 128
        withdrawal_amount = Decimal("0.01")
        withdrawals = []
        for withdrawal_index in range(withdrawal_count_limit):
            script = build_script_destination(node)
            withdrawals.append({
                "withdrawal_id": f"{withdrawal_index + 1:064x}",
                "amount": withdrawal_amount,
                "script": script,
                "destination_commitment": compute_script_commitment(script),
            })

        withdrawal_root = compute_withdrawal_root(withdrawals)
        withdrawal_config = build_register_config(scaffold_supported, "77" * 32, withdrawal_root)
        node.sendvaliditysidechainregister(withdrawal_sidechain_id, withdrawal_config)
        node.generate(1)

        total_withdrawal_amount = withdrawal_amount * withdrawal_count_limit
        node.sendvaliditydeposit(
            withdrawal_sidechain_id,
            "88" * 32,
            {"address": node.getnewaddress()},
            total_withdrawal_amount,
        )
        node.generate(1)

        withdrawal_sidechain = get_sidechain(node.getvaliditysidechaininfo(), withdrawal_sidechain_id)
        assert withdrawal_sidechain is not None
        assert_equal(withdrawal_sidechain["escrow_balance"], amount_to_sats(total_withdrawal_amount))

        no_op_batch_res = node.sendvaliditybatch(
            withdrawal_sidechain_id,
            {
                "batch_number": 1,
                "new_state_root": withdrawal_sidechain["current_state_root"],
                "consumed_queue_messages": 0,
            },
        )
        assert_equal(no_op_batch_res["auto_scaffold_proof"], True)
        node.generate(1)

        withdrawal_proof_entries = [
            build_verified_withdrawal_proof_entry(withdrawals, leaf_index)
            for leaf_index in range(withdrawal_count_limit)
        ]
        execution_res = node.sendverifiedwithdrawals(withdrawal_sidechain_id, 1, withdrawal_proof_entries)
        assert_equal(execution_res["withdrawal_count"], withdrawal_count_limit)
        assert_equal(execution_res["withdrawal_root"], withdrawal_root)
        node.generate(1)

        withdrawal_sidechain = get_sidechain(node.getvaliditysidechaininfo(), withdrawal_sidechain_id)
        assert withdrawal_sidechain is not None
        assert_equal(withdrawal_sidechain["executed_withdrawal_count"], withdrawal_count_limit)
        assert_equal(withdrawal_sidechain["escrow_balance"], 0)


if __name__ == '__main__':
    ValiditySidechainResourceBounds().main()
