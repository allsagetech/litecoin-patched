#!/usr/bin/env python3
# Copyright (c) 2025-2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


def _get_sidechain(info: dict, scid: int):
    for sc in info.get("sidechains", []):
        if sc.get("id") == scid:
            return sc
    return None


class DrivechainReorgCacheMetricsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [[], []]

    def run_test(self):
        n0 = self.nodes[0]
        n1 = self.nodes[1]

        scid = 1
        payload = "00" * 32
        bundle_hash = "33" * 32

        n0.generate(101)
        self.sync_blocks()

        before = n0.getdrivechaininfo()["state_cache"]
        before_hits = int(before["hits"])
        before_recompute = int(before["recompute_fallbacks"])

        self.disconnect_nodes(0, 1)

        owner_privkey = n0.getnewaddress()
        n0.senddrivechainregister(owner_privkey, scid, Decimal("1.0"))
        n0.generate(1)

        n0.senddrivechaindeposit(scid, payload, [Decimal("1.0")])
        n0.generate(1)
        n0.senddrivechainbundle(scid, bundle_hash, owner_privkey)
        n0.generate(1)

        info_fork_a = n0.getdrivechaininfo()
        assert _get_sidechain(info_fork_a, scid) is not None

        # Mine a longer competing chain to force a reorg.
        n1.generate(6)

        self.connect_nodes(0, 1)
        self.sync_blocks()

        after_info = n0.getdrivechaininfo()
        assert_equal(after_info["sidechains"], [])

        after = after_info["state_cache"]
        after_hits = int(after["hits"])
        after_recompute = int(after["recompute_fallbacks"])

        # Guardrail: reorg should restore from cache (hit) and avoid expensive fallback recompute.
        assert after_hits > before_hits
        assert_equal(after_recompute, before_recompute)


if __name__ == "__main__":
    DrivechainReorgCacheMetricsTest().main()
