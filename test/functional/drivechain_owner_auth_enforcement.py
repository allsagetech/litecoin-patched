#!/usr/bin/env python3
# Copyright (c) 2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from decimal import Decimal

from test_framework.messages import hash256
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error


def get_sidechain(node, scid: int):
    info = node.getdrivechaininfo()
    for sidechain in info["sidechains"]:
        if int(sidechain["id"]) == scid:
            return sidechain
    return None


def get_single_key_pubkey_hex(node, address: str) -> str:
    info = node.getaddressinfo(address)
    if "pubkey" in info:
        return info["pubkey"]
    return info["embedded"]["pubkey"]


class DrivechainOwnerAuthEnforcement(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def run_test(self):
        node = self.nodes[0]
        scid = 21
        bundle_hash = "33" * 32
        max_escrow_amount = Decimal("2.0")
        max_bundle_withdrawal = Decimal("1.25")

        node.generatetoaddress(110, node.getnewaddress())

        owner_addr_a = node.getnewaddress(address_type="p2sh-segwit")
        owner_addr_b = node.getnewaddress(address_type="p2sh-segwit")
        owner_pubkey_a = bytes.fromhex(get_single_key_pubkey_hex(node, owner_addr_a))
        owner_pubkey_b = bytes.fromhex(get_single_key_pubkey_hex(node, owner_addr_b))
        owner_key_hash_pairs = sorted(
            [
                (hash256(owner_pubkey_a).hex(), bytes.fromhex(hash256(owner_pubkey_a).hex())[::-1].hex()),
                (hash256(owner_pubkey_b).hex(), bytes.fromhex(hash256(owner_pubkey_b).hex())[::-1].hex()),
            ],
            key=lambda item: item[0],
        )
        owner_key_hashes_payload = [item[0] for item in owner_key_hash_pairs]
        owner_key_hashes_rpc = [item[1] for item in owner_key_hash_pairs]

        wrong_addr = node.getnewaddress(address_type="p2sh-segwit")

        node.senddrivechainregister(
            [owner_addr_a, owner_addr_b],
            scid,
            Decimal("1.0"),
            False,
            2,
            max_escrow_amount,
            max_bundle_withdrawal,
        )
        node.generatetoaddress(1, node.getnewaddress())

        node.senddrivechaindeposit(scid, owner_key_hashes_payload[0], [Decimal("1.0")])
        node.generatetoaddress(1, node.getnewaddress())

        sidechain = get_sidechain(node, scid)
        assert sidechain is not None
        assert sidechain["owner_auth_required"] is True
        assert sidechain["auth_threshold"] == 2
        assert sidechain["owner_key_hashes"] == owner_key_hashes_rpc
        assert sidechain["owner_key_hashes_payload"] == owner_key_hashes_payload
        assert sidechain["max_escrow_amount"] == int(max_escrow_amount * 100_000_000)
        assert sidechain["max_bundle_withdrawal"] == int(max_bundle_withdrawal * 100_000_000)
        assert "owner_key_hash" not in sidechain
        assert "owner_key_hash_payload" not in sidechain

        assert_raises_rpc_error(
            -8,
            "owner_addresses are required for registered sidechains with owner auth",
            node.senddrivechainbundle,
            scid,
            bundle_hash,
        )

        assert_raises_rpc_error(
            -8,
            "owner_addresses do not satisfy the registered auth_threshold",
            node.senddrivechainbundle,
            scid,
            bundle_hash,
            owner_addr_a,
        )

        assert_raises_rpc_error(
            -8,
            "owner_addresses contain a key that is not part of the registered owner policy",
            node.senddrivechainbundle,
            scid,
            bundle_hash,
            [owner_addr_a, wrong_addr],
        )

        txid = node.senddrivechainbundle(scid, bundle_hash, [owner_addr_b, owner_addr_a])
        assert txid

        node.generatetoaddress(1, node.getnewaddress())
        sidechain = get_sidechain(node, scid)
        assert sidechain is not None
        bundles = sidechain["bundles"]
        assert any(bundle["hash"] == bundle_hash for bundle in bundles)


if __name__ == "__main__":
    DrivechainOwnerAuthEnforcement().main()
