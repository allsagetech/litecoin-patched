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


def get_sidechain(node, sidechain_id):
    info = node.getvaliditysidechaininfo()
    for sidechain in info["sidechains"]:
        if sidechain["id"] == sidechain_id:
            return sidechain
    raise AssertionError(f"missing sidechain {sidechain_id}")


def get_supported_profile(node, profile_name):
    info = node.getvaliditysidechaininfo()
    for supported in info["supported_proof_configs"]:
        if supported["profile_name"] == profile_name:
            return supported
    raise AssertionError(f"missing supported proof profile {profile_name}")


def amount_to_sats(amount):
    return int(amount * Decimal("100000000"))


def build_script_destination(node):
    address = node.getnewaddress()
    return node.getaddressinfo(address)["scriptPubKey"]


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


class ValiditySidechainMempoolConflicts(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def run_test(self):
        node = self.nodes[0]
        node.generatetoaddress(110, node.getnewaddress())

        supported = get_supported_profile(node, "scaffold_onchain_da_v1")
        sidechain_id = 19

        withdrawals = [
            {
                "withdrawal_id": "11" * 32,
                "amount": Decimal("0.25"),
                "script": build_script_destination(node),
            },
            {
                "withdrawal_id": "22" * 32,
                "amount": Decimal("0.50"),
                "script": build_script_destination(node),
            },
        ]
        for withdrawal in withdrawals:
            withdrawal["destination_commitment"] = compute_script_commitment(withdrawal["script"])

        escape_exits = [
            {
                "exit_id": "33" * 32,
                "amount": Decimal("0.20"),
                "script": build_script_destination(node),
            },
            {
                "exit_id": "44" * 32,
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

        self.log.info("Rejecting duplicate REGISTER in mempool for the same validity sidechain id.")
        register_res = node.sendvaliditysidechainregister(sidechain_id, config)
        assert register_res["txid"] in node.getrawmempool()
        conflicting_config = dict(config)
        conflicting_config["initial_state_root"] = "55" * 32
        assert_raises_rpc_error(
            -26,
            "dc-register-duplicate-sidechain-mempool",
            node.sendvaliditysidechainregister,
            sidechain_id,
            conflicting_config,
        )
        node.generate(1)

        refund_one = {"address": node.getnewaddress()}
        refund_two = {"address": node.getnewaddress()}
        deposit_one_amount = Decimal("1.25")
        deposit_two_amount = Decimal("1.25")
        deposit_one_destination = "66" * 32
        deposit_two_destination = "77" * 32
        deposit_one_nonce = 7
        deposit_two_nonce = 8
        deposit_one_id = "88" * 32
        deposit_two_id = "99" * 32

        self.log.info("Rejecting duplicate DEPOSIT in mempool for the same deposit id.")
        deposit_one_res = node.sendvaliditydeposit(
            sidechain_id,
            deposit_one_destination,
            refund_one,
            deposit_one_amount,
            deposit_one_nonce,
            deposit_one_id,
        )
        assert deposit_one_res["txid"] in node.getrawmempool()
        assert_raises_rpc_error(
            -26,
            "validitysidechain-deposit-duplicate-mempool",
            node.sendvaliditydeposit,
            sidechain_id,
            deposit_one_destination,
            refund_one,
            deposit_one_amount,
            deposit_one_nonce,
            deposit_one_id,
        )
        node.generate(1)
        deposit_one_height = node.getblockcount()

        node.sendvaliditydeposit(
            sidechain_id,
            deposit_two_destination,
            refund_two,
            deposit_two_amount,
            deposit_two_nonce,
            deposit_two_id,
        )
        node.generate(1)

        self.log.info("Rejecting duplicate REQUEST_FORCE_EXIT in mempool for the same request hash.")
        force_exit_args = (
            sidechain_id,
            "aa" * 32,
            "bb" * 32,
            Decimal("0.50"),
            {"address": node.getnewaddress()},
            9,
        )
        force_exit_res = node.sendforceexitrequest(*force_exit_args)
        assert force_exit_res["txid"] in node.getrawmempool()
        assert_raises_rpc_error(
            -26,
            "validitysidechain-force-exit-duplicate-mempool",
            node.sendforceexitrequest,
            *force_exit_args,
        )
        node.generate(1)

        sidechain = get_sidechain(node, sidechain_id)
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

        self.log.info("Rejecting duplicate COMMIT_VALIDITY_BATCH in mempool for the same sidechain and batch number.")
        batch_res = node.sendvaliditybatch(sidechain_id, public_inputs)
        assert batch_res["txid"] in node.getrawmempool()
        assert_raises_rpc_error(
            -26,
            "validitysidechain-batch-duplicate-mempool",
            node.sendvaliditybatch,
            sidechain_id,
            public_inputs,
        )
        node.generate(1)
        batch_height = node.getblockcount()

        withdrawal_rpc_entries = [
            {
                "withdrawal_id": withdrawal["withdrawal_id"],
                "script": withdrawal["script"],
                "amount": withdrawal["amount"],
            }
            for withdrawal in withdrawals
        ]
        self.log.info("Rejecting duplicate EXECUTE_VERIFIED_WITHDRAWALS in mempool for the same withdrawal ids.")
        verified_withdrawal_res = node.sendverifiedwithdrawals(sidechain_id, 1, withdrawal_rpc_entries)
        assert verified_withdrawal_res["txid"] in node.getrawmempool()
        assert_raises_rpc_error(
            -26,
            "validitysidechain-execute-duplicate-withdrawal-mempool",
            node.sendverifiedwithdrawals,
            sidechain_id,
            1,
            withdrawal_rpc_entries,
        )
        node.generate(1)

        reclaim_height = deposit_one_height + config["deposit_reclaim_delay"]
        second_reclaim_height = reclaim_height + 1
        escape_height = batch_height + config["escape_hatch_delay"]
        current_height = node.getblockcount()
        target_height = max(reclaim_height, second_reclaim_height, escape_height)
        if current_height < target_height:
            node.generate(target_height - current_height)

        sidechain = get_sidechain(node, sidechain_id)
        assert_equal(sidechain["queue_state"]["reclaimable_deposit_count"], 2)
        assert_equal(sidechain["current_state_root"], config["initial_state_root"])

        escape_exit_rpc_entries = [
            {
                "exit_id": exit_leaf["exit_id"],
                "script": exit_leaf["script"],
                "amount": exit_leaf["amount"],
            }
            for exit_leaf in escape_exits
        ]
        self.log.info("Rejecting duplicate EXECUTE_ESCAPE_EXIT in mempool for the same escape-exit ids.")
        escape_exit_res = node.sendescapeexit(
            sidechain_id,
            sidechain["current_state_root"],
            escape_exit_rpc_entries,
        )
        assert escape_exit_res["txid"] in node.getrawmempool()
        assert_raises_rpc_error(
            -26,
            "validitysidechain-escape-exit-duplicate-mempool",
            node.sendescapeexit,
            sidechain_id,
            sidechain["current_state_root"],
            escape_exit_rpc_entries,
        )
        node.generate(1)

        reclaim_deposit = {
            "deposit_id": deposit_one_id,
            "amount": deposit_one_amount,
            "destination_commitment": deposit_one_destination,
            "nonce": deposit_one_nonce,
        }
        self.log.info("Rejecting duplicate RECLAIM_STALE_DEPOSIT in mempool for the same deposit id.")
        reclaim_res = node.sendstaledepositreclaim(sidechain_id, reclaim_deposit, refund_one)
        assert_equal(reclaim_res["deposit_id"], deposit_one_id)
        assert reclaim_res["txid"] in node.getrawmempool()
        assert_raises_rpc_error(
            -26,
            "validitysidechain-reclaim-duplicate-mempool",
            node.sendstaledepositreclaim,
            sidechain_id,
            reclaim_deposit,
            refund_one,
        )
        node.generate(1)

        final_sidechain = get_sidechain(node, sidechain_id)
        assert_equal(final_sidechain["executed_withdrawal_count"], len(withdrawals))
        assert_equal(final_sidechain["executed_escape_exit_count"], len(escape_exits))
        assert_equal(final_sidechain["queue_state"]["head_index"], 1)
        assert_equal(final_sidechain["queue_state"]["pending_message_count"], 2)
        assert_equal(final_sidechain["queue_state"]["pending_deposit_count"], 1)
        assert_equal(final_sidechain["queue_state"]["pending_force_exit_count"], 1)
        assert_equal(final_sidechain["queue_state"]["reclaimable_deposit_count"], 1)
        assert_equal(final_sidechain["escrow_balance"], 0)


if __name__ == "__main__":
    ValiditySidechainMempoolConflicts().main()
