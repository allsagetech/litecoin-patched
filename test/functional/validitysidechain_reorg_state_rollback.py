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


def build_script_destination(node):
    return node.getaddressinfo(node.getnewaddress())["scriptPubKey"]


def get_sidechain(info, sidechain_id):
    for sidechain in info["sidechains"]:
        if sidechain["id"] == sidechain_id:
            return sidechain
    return None


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
        supported = n0.getvaliditysidechaininfo()["supported_proof_configs"][0]
        config = build_register_config(
            supported,
            compute_escape_exit_root(escape_exits),
            compute_withdrawal_root(withdrawals),
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

        withdrawal_rpc_entries = [
            {
                "withdrawal_id": withdrawal["withdrawal_id"],
                "script": withdrawal["script"],
                "amount": withdrawal["amount"],
            }
            for withdrawal in withdrawals
        ]
        verified_withdrawal_res = n0.sendverifiedwithdrawals(sidechain_id, 1, withdrawal_rpc_entries)
        verified_withdrawal_txid = verified_withdrawal_res["txid"]
        n0.generatetoaddress(1, n0.getnewaddress())

        escape_height = batch_height + config["escape_hatch_delay"]
        current_height = n0.getblockcount()
        if current_height < escape_height:
            n0.generatetoaddress(escape_height - current_height, n0.getnewaddress())

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

        info_n0 = n0.getvaliditysidechaininfo()
        sidechain_n0 = get_sidechain(info_n0, sidechain_id)
        assert sidechain_n0 is not None
        recompute_fallbacks = int(info_n0["state_cache"]["recompute_fallbacks"])
        assert_equal(sidechain_n0["latest_batch_number"], 1)
        assert_equal(len(sidechain_n0["accepted_batches"]), 1)
        assert_equal(sidechain_n0["executed_withdrawal_count"], len(withdrawals))
        assert_equal(sidechain_n0["executed_escape_exit_count"], len(escape_exits))
        assert_equal(sidechain_n0["escrow_balance"], amount_to_sats(Decimal("0.25")))

        self.log.info("Mine a longer competing fork on node1 that omits the batch, withdrawal execution, and escape exits.")
        blocks_needed = (n0.getblockcount() - n1.getblockcount()) + 1
        n1.generatetoaddress(blocks_needed, n1.getnewaddress())

        self.connect_nodes(0, 1)
        self.sync_blocks()

        self.log.info("After reorg, the sidechain should remain but accepted-batch, withdrawal, and escape-exit state must roll back.")
        info_n0_after = n0.getvaliditysidechaininfo()
        info_n1_after = n1.getvaliditysidechaininfo()
        sidechain_n0_after = get_sidechain(info_n0_after, sidechain_id)
        sidechain_n1_after = get_sidechain(info_n1_after, sidechain_id)
        assert sidechain_n0_after is not None
        assert sidechain_n1_after is not None
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

        self.restart_node(0, extra_args=["-acceptnonstdtxn=1"])
        n0 = self.nodes[0]
        info_after_restart = n0.getvaliditysidechaininfo()
        sidechain_after_restart = get_sidechain(info_after_restart, sidechain_id)
        assert sidechain_after_restart is not None
        assert_equal(int(info_after_restart["state_cache"]["recompute_fallbacks"]), recompute_fallbacks)
        assert_equal(sidechain_after_restart["latest_batch_number"], 0)
        assert_equal(sidechain_after_restart["accepted_batches"], [])
        assert_equal(sidechain_after_restart["executed_withdrawal_count"], 0)
        assert_equal(sidechain_after_restart["executed_escape_exit_count"], 0)
        assert_equal(sidechain_after_restart["escrow_balance"], 100000000)

        self.log.info("Re-submitting the same batch, withdrawal execution, and escape exits after reorg should succeed.")
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
            verified_withdrawal_res = n0.sendverifiedwithdrawals(sidechain_id, 1, withdrawal_rpc_entries)
            verified_withdrawal_txid = verified_withdrawal_res["txid"]
        assert verified_withdrawal_txid in n0.getrawmempool()
        n0.generatetoaddress(1, n0.getnewaddress())

        escape_height = batch_height + config["escape_hatch_delay"]
        current_height = n0.getblockcount()
        if current_height < escape_height:
            n0.generatetoaddress(escape_height - current_height, n0.getnewaddress())

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

        final_sidechain = get_sidechain(n0.getvaliditysidechaininfo(), sidechain_id)
        assert final_sidechain is not None
        assert_equal(final_sidechain["latest_batch_number"], 1)
        assert_equal(len(final_sidechain["accepted_batches"]), 1)
        assert_equal(final_sidechain["executed_withdrawal_count"], len(withdrawals))
        assert_equal(final_sidechain["executed_escape_exit_count"], len(escape_exits))
        assert_equal(final_sidechain["escrow_balance"], amount_to_sats(Decimal("0.25")))


if __name__ == "__main__":
    ValiditySidechainReorgStateRollback().main()
