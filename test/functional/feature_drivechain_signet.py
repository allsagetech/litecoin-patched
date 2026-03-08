#!/usr/bin/env python3
# Copyright (c) 2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.
"""Smoke-test drivechain RPC/state flow on signet."""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


def get_drivechain_status(node) -> str:
    info = node.getblockchaininfo()
    softforks = info.get("softforks", {})

    if isinstance(softforks, dict):
        drivechain = softforks.get("drivechain")
        if isinstance(drivechain, dict):
            bip9 = drivechain.get("bip9")
            if isinstance(bip9, dict) and "status" in bip9:
                return bip9["status"]
            if "status" in drivechain:
                return drivechain["status"]
            if "active" in drivechain:
                return "active" if drivechain["active"] else "inactive"

    if isinstance(softforks, list):
        for entry in softforks:
            if not isinstance(entry, dict) or entry.get("id") != "drivechain":
                continue
            bip9 = entry.get("bip9")
            if isinstance(bip9, dict) and "status" in bip9:
                return bip9["status"]
            if "status" in entry:
                return entry["status"]
            if "active" in entry:
                return "active" if entry["active"] else "inactive"

    node.getdrivechaininfo()
    return "active"


def get_sidechain(info, sidechain_id: int):
    for sidechain in info["sidechains"]:
        if int(sidechain["id"]) == sidechain_id:
            return sidechain
    return None


class DrivechainSignetSmokeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.chain = "signet"
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.rpc_timeout = 240
        self.extra_args = [["-signetchallenge=51"]]

    def skip_test_if_missing_module(self):
        pass

    def run_test(self):
        node = self.nodes[0]

        self.log.info("mine spendable signet balance")
        mine_addr = node.getnewaddress()
        node.generatetoaddress(101, mine_addr, 10_000_000)

        status = get_drivechain_status(node)
        assert_equal(status, "active")

        owner_addr = node.getnewaddress()
        register = node.senddrivechainregister(owner_addr)
        sidechain_id = int(register["sidechain_id"])
        assert_equal(sidechain_id, 0)
        node.generatetoaddress(1, mine_addr, 10_000_000)

        deposit_payload = "00" * 32
        bundle_hash = "11" * 32

        node.senddrivechaindeposit(sidechain_id, deposit_payload, [Decimal("1.0")], False)
        node.generatetoaddress(1, mine_addr, 10_000_000)

        node.senddrivechainbundle(sidechain_id, bundle_hash, owner_addr)
        node.generatetoaddress(1, mine_addr, 10_000_000)

        dcinfo = node.getdrivechaininfo()
        sidechain = get_sidechain(dcinfo, sidechain_id)
        assert sidechain is not None

        assert_equal(sidechain["is_active"], True)
        assert_equal(sidechain["escrow_balance"], 100_000_000)
        assert_equal(sidechain["owner_auth_required"], True)
        assert_equal(len(sidechain["bundles"]), 1)

        bundle = sidechain["bundles"][0]
        assert_equal(bundle["hash"], bundle_hash)
        assert_equal(bundle["approved"], False)
        assert_equal(bundle["executed"], False)


if __name__ == "__main__":
    DrivechainSignetSmokeTest().main()
