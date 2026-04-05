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


def build_noop_batch(sidechain, batch_number):
    return {
        "batch_number": batch_number,
        "prior_state_root": sidechain["current_state_root"],
        "new_state_root": sidechain["current_state_root"],
        "l1_message_root_before": sidechain["queue_state"]["root"],
        "l1_message_root_after": sidechain["queue_state"]["root"],
        "consumed_queue_messages": 0,
        "withdrawal_root": sidechain["current_withdrawal_root"],
        "data_root": sidechain["current_data_root"],
        "data_size": 0,
    }


def build_script_destination(node):
    return node.getaddressinfo(node.getnewaddress())["scriptPubKey"]


class ValiditySidechainLongRangeBatchReorg(BitcoinTestFramework):
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

        supported = get_supported_profile(n0, "scaffold_onchain_da_v1")
        sidechain_id = 45
        withdrawal_amount = Decimal("0.30")
        deposit_amount = Decimal("1.00")
        withdrawals = [
            {
                "withdrawal_id": "91" * 32,
                "amount": withdrawal_amount,
                "script": build_script_destination(n0),
            }
        ]
        for withdrawal in withdrawals:
            withdrawal["destination_commitment"] = compute_script_commitment(withdrawal["script"])
        withdrawal_proof_entries = [
            build_verified_withdrawal_proof_entry(withdrawals, i)
            for i in range(len(withdrawals))
        ]

        config = build_register_config(
            supported,
            "11" * 32,
            compute_withdrawal_root(withdrawals),
        )

        self.log.info("Build common registration and deposit history on both nodes.")
        n0.sendvaliditysidechainregister(sidechain_id, config)
        n0.generatetoaddress(1, n0.getnewaddress())
        self.sync_blocks()

        n0.sendvaliditydeposit(
            sidechain_id,
            "22" * 32,
            {"address": n0.getnewaddress()},
            deposit_amount,
            7,
        )
        n0.generatetoaddress(1, n0.getnewaddress())
        self.sync_blocks()

        self.disconnect_nodes(0, 1)

        self.log.info("On node0 only, accept a longer losing-fork batch history and execute withdrawals at the end.")
        losing_fork_batch_txids = []
        batch_count = 4
        for batch_number in range(1, batch_count + 1):
            sidechain = get_sidechain(n0.getvaliditysidechaininfo(), sidechain_id)
            assert sidechain is not None
            batch_res = n0.sendvaliditybatch(sidechain_id, build_noop_batch(sidechain, batch_number))
            losing_fork_batch_txids.append(batch_res["txid"])
            n0.generatetoaddress(1, n0.getnewaddress())

        withdrawal_res = n0.sendverifiedwithdrawals(sidechain_id, batch_count, withdrawal_proof_entries)
        losing_fork_withdrawal_txid = withdrawal_res["txid"]
        n0.generatetoaddress(1, n0.getnewaddress())

        info_n0 = n0.getvaliditysidechaininfo()
        sidechain_n0 = get_sidechain(info_n0, sidechain_id)
        assert sidechain_n0 is not None
        recompute_fallbacks = int(info_n0["state_cache"]["recompute_fallbacks"])
        assert_equal(sidechain_n0["latest_batch_number"], batch_count)
        assert_equal(len(sidechain_n0["accepted_batches"]), batch_count)
        assert_equal(sidechain_n0["executed_withdrawal_count"], len(withdrawals))
        assert_equal(sidechain_n0["escrow_balance"], amount_to_sats(deposit_amount - withdrawal_amount))
        assert_equal(sidechain_n0["queue_state"]["pending_message_count"], 1)
        assert info_n0["state_cache"]["snapshots_written"] >= 1

        self.log.info("Mine a longer competing fork on node1 that omits the entire losing-fork batch history.")
        blocks_needed = (n0.getblockcount() - n1.getblockcount()) + 1
        n1.generatetoaddress(blocks_needed, n1.getnewaddress())

        self.connect_nodes(0, 1)
        self.sync_blocks()

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
        assert_equal(sidechain_n0_after["escrow_balance"], amount_to_sats(deposit_amount))
        assert_equal(sidechain_n1_after["escrow_balance"], amount_to_sats(deposit_amount))
        assert_equal(sidechain_n0_after["queue_state"]["pending_message_count"], 1)
        assert_equal(sidechain_n1_after["queue_state"]["pending_message_count"], 1)

        self.restart_node(0, extra_args=["-acceptnonstdtxn=1", "-persistmempool=0"])
        n0 = self.nodes[0]
        self.connect_nodes(0, 1)
        self.sync_blocks()

        info_after_restart = n0.getvaliditysidechaininfo()
        sidechain_after_restart = get_sidechain(info_after_restart, sidechain_id)
        assert sidechain_after_restart is not None
        assert_equal(int(info_after_restart["state_cache"]["recompute_fallbacks"]), recompute_fallbacks)
        assert_equal(sidechain_after_restart["latest_batch_number"], 0)
        assert_equal(sidechain_after_restart["accepted_batches"], [])
        assert_equal(sidechain_after_restart["executed_withdrawal_count"], 0)
        assert_equal(sidechain_after_restart["escrow_balance"], amount_to_sats(deposit_amount))
        assert_equal(sidechain_after_restart["queue_state"]["pending_message_count"], 1)
        assert_equal(n0.getrawmempool(), [])

        self.log.info("Re-submit the same longer batch history and withdrawal flow after restart.")
        replay_batch_txids = []
        for batch_number in range(1, batch_count + 1):
            sidechain = get_sidechain(n0.getvaliditysidechaininfo(), sidechain_id)
            assert sidechain is not None
            batch_res = n0.sendvaliditybatch(sidechain_id, build_noop_batch(sidechain, batch_number))
            replay_batch_txids.append(batch_res["txid"])
            n0.generatetoaddress(1, n0.getnewaddress())

        replay_withdrawal_res = n0.sendverifiedwithdrawals(sidechain_id, batch_count, withdrawal_proof_entries)
        replay_withdrawal_txid = replay_withdrawal_res["txid"]
        n0.generatetoaddress(1, n0.getnewaddress())
        self.sync_blocks()

        final_info = n0.getvaliditysidechaininfo()
        final_sidechain = get_sidechain(final_info, sidechain_id)
        assert final_sidechain is not None
        assert_equal(final_sidechain["latest_batch_number"], batch_count)
        assert_equal(len(final_sidechain["accepted_batches"]), batch_count)
        assert_equal(final_sidechain["accepted_batches"][-1]["batch_number"], batch_count)
        assert_equal(final_sidechain["executed_withdrawal_count"], len(withdrawals))
        assert_equal(final_sidechain["escrow_balance"], amount_to_sats(deposit_amount - withdrawal_amount))
        assert_equal(final_sidechain["queue_state"]["pending_message_count"], 1)
        assert all(len(txid) == 64 for txid in losing_fork_batch_txids)
        assert len(losing_fork_withdrawal_txid) == 64
        assert all(len(txid) == 64 for txid in replay_batch_txids)
        assert len(replay_withdrawal_txid) == 64


if __name__ == "__main__":
    ValiditySidechainLongRangeBatchReorg().main()
