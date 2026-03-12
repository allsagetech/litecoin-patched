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


def get_sidechain_info(node, sidechain_id):
    info = node.getvaliditysidechaininfo()
    for sidechain in info["sidechains"]:
        if sidechain["id"] == sidechain_id:
            return sidechain
    raise AssertionError(f"missing sidechain {sidechain_id} in getvaliditysidechaininfo")


def amount_to_sats(amount):
    return int(amount * Decimal("100000000"))


def hash256_uint256(payload):
    return uint256_from_str(hash256(payload))


def compute_script_commitment(script_hex):
    return f"{hash256_uint256(bytes.fromhex(script_hex)):064x}"


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


def build_script_destination(node):
    address = node.getnewaddress()
    return node.getaddressinfo(address)["scriptPubKey"]


class ValiditySidechainWalletTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        mining_address = node.getnewaddress()
        node.generatetoaddress(101, mining_address)

        supported = node.getvaliditysidechaininfo()["supported_proof_configs"][0]

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


if __name__ == "__main__":
    ValiditySidechainWalletTest().main()
