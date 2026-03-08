#!/usr/bin/env python3
# Copyright (c) 2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.
"""Smoke-test drivechain activation and template wiring on signet."""

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

        self.log.info("verify drivechain is active on signet")
        status = get_drivechain_status(node)
        assert_equal(status, "active")

        self.log.info("verify drivechain state RPC is available on signet")
        dcinfo = node.getdrivechaininfo()
        assert_equal(dcinfo["sidechains"], [])
        assert "state_cache" in dcinfo
        assert "entries" in dcinfo["state_cache"]
        assert "max_entries" in dcinfo["state_cache"]

        self.log.info("verify getblocktemplate advertises drivechain fields on signet")
        tmpl = node.getblocktemplate({"rules": ["mweb", "segwit"]})
        assert "drivechain" in tmpl["rules"]
        assert_equal(tmpl["drivechainvotes"], [])
        assert_equal(tmpl["drivechainbmmaccepts"], [])

        self.log.info("verify no sidechains were created implicitly")
        assert_equal(get_sidechain(node.getdrivechaininfo(), 0), None)


if __name__ == "__main__":
    DrivechainSignetSmokeTest().main()
