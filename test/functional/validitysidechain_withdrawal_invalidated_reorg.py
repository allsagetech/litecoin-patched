#!/usr/bin/env python3
# Copyright (c) 2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from decimal import Decimal
import struct

from test_framework.messages import hash256, ser_uint256, uint256_from_str
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


def build_register_config(supported, initial_withdrawal_root):
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


def build_script_destination(node):
    return node.getaddressinfo(node.getnewaddress())["scriptPubKey"]


class ValiditySidechainWithdrawalInvalidatedReorg(BitcoinTestFramework):
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

        sidechain_id = 53
        supported = get_supported_profile(n0, "scaffold_onchain_da_v1")
        withdrawals = [{
            "withdrawal_id": "77" * 32,
            "amount": Decimal("0.40"),
            "script": build_script_destination(n0),
        }]
        withdrawals[0]["destination_commitment"] = compute_script_commitment(withdrawals[0]["script"])
        config = build_register_config(supported, compute_withdrawal_root(withdrawals))

        self.log.info("Building common sidechain history with funded escrow and the target withdrawal root.")
        n0.sendvaliditysidechainregister(sidechain_id, config)
        n0.generatetoaddress(1, n0.getnewaddress())
        self.sync_blocks()

        n0.sendvaliditydeposit(
            sidechain_id,
            "33" * 32,
            {"address": n0.getnewaddress()},
            Decimal("1.0"),
            7,
            "44" * 32,
        )
        n0.generatetoaddress(1, n0.getnewaddress())
        self.sync_blocks()

        self.disconnect_nodes(0, 1)

        self.log.info("Mine batch-plus-withdrawal execution on node0.")
        sidechain_n0 = get_sidechain(n0.getvaliditysidechaininfo(), sidechain_id)
        assert sidechain_n0 is not None
        public_inputs = {
            "batch_number": 1,
            "prior_state_root": sidechain_n0["current_state_root"],
            "new_state_root": sidechain_n0["current_state_root"],
            "l1_message_root_before": sidechain_n0["queue_state"]["root"],
            "l1_message_root_after": sidechain_n0["queue_state"]["root"],
            "consumed_queue_messages": 0,
            "withdrawal_root": sidechain_n0["current_withdrawal_root"],
            "data_root": sidechain_n0["current_data_root"],
            "data_size": 0,
        }
        batch_result_n0 = n0.sendvaliditybatch(sidechain_id, public_inputs)
        batch_txid_n0 = batch_result_n0["txid"]
        n0.generatetoaddress(1, n0.getnewaddress())

        withdrawal_rpc_entries = [{
            "withdrawal_id": withdrawals[0]["withdrawal_id"],
            "script": withdrawals[0]["script"],
            "amount": withdrawals[0]["amount"],
        }]
        execute_result_n0 = n0.sendverifiedwithdrawals(sidechain_id, 1, withdrawal_rpc_entries)
        execute_txid_n0 = execute_result_n0["txid"]
        n0.generatetoaddress(1, n0.getnewaddress())

        self.log.info("Mine the same logical batch and withdrawal execution on node1, then extend that fork.")
        sidechain_n1 = get_sidechain(n1.getvaliditysidechaininfo(), sidechain_id)
        assert sidechain_n1 is not None
        batch_result_n1 = n1.sendvaliditybatch(sidechain_id, public_inputs)
        batch_txid_n1 = batch_result_n1["txid"]
        n1.generatetoaddress(1, n1.getnewaddress())

        execute_result_n1 = n1.sendverifiedwithdrawals(sidechain_id, 1, withdrawal_rpc_entries)
        execute_txid_n1 = execute_result_n1["txid"]
        n1.generatetoaddress(1, n1.getnewaddress())

        blocks_needed = (n0.getblockcount() - n1.getblockcount()) + 1
        if blocks_needed > 0:
            n1.generatetoaddress(blocks_needed, n1.getnewaddress())

        self.connect_nodes(0, 1)
        self.sync_blocks()

        self.log.info("After reorg, the losing-fork batch and withdrawal execution must stay out of mempool because the winning fork already finalized them.")
        info_n0_after = n0.getvaliditysidechaininfo()
        sidechain_after = get_sidechain(info_n0_after, sidechain_id)
        assert sidechain_after is not None
        assert batch_txid_n0 not in n0.getrawmempool()
        assert execute_txid_n0 not in n0.getrawmempool()
        assert batch_txid_n1 not in n0.getrawmempool()
        assert execute_txid_n1 not in n0.getrawmempool()
        assert_equal(sidechain_after["latest_batch_number"], 1)
        assert_equal(len(sidechain_after["accepted_batches"]), 1)
        assert_equal(sidechain_after["executed_withdrawal_count"], 1)
        assert_equal(sidechain_after["queue_state"]["pending_message_count"], 1)
        assert_equal(sidechain_after["escrow_balance"], amount_to_sats(Decimal("0.60")))

        assert_raises_rpc_error(
            -26,
            "batch number is not strictly monotonic",
            n0.sendvaliditybatch,
            sidechain_id,
            public_inputs,
        )
        assert_raises_rpc_error(
            -26,
            "withdrawal id already executed",
            n0.sendverifiedwithdrawals,
            sidechain_id,
            1,
            withdrawal_rpc_entries,
        )

        self.restart_node(0, extra_args=self.common_args)
        n0 = self.nodes[0]
        info_after_restart = n0.getvaliditysidechaininfo()
        sidechain_after_restart = get_sidechain(info_after_restart, sidechain_id)
        assert sidechain_after_restart is not None
        assert batch_txid_n0 not in n0.getrawmempool()
        assert execute_txid_n0 not in n0.getrawmempool()
        assert_equal(sidechain_after_restart["latest_batch_number"], 1)
        assert_equal(len(sidechain_after_restart["accepted_batches"]), 1)
        assert_equal(sidechain_after_restart["executed_withdrawal_count"], 1)
        assert_equal(sidechain_after_restart["escrow_balance"], amount_to_sats(Decimal("0.60")))

        assert_raises_rpc_error(
            -26,
            "batch number is not strictly monotonic",
            n0.sendvaliditybatch,
            sidechain_id,
            public_inputs,
        )
        assert_raises_rpc_error(
            -26,
            "withdrawal id already executed",
            n0.sendverifiedwithdrawals,
            sidechain_id,
            1,
            withdrawal_rpc_entries,
        )


if __name__ == "__main__":
    ValiditySidechainWithdrawalInvalidatedReorg().main()
