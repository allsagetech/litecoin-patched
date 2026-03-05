#!/usr/bin/env python3
# Copyright (c) 2026 AllSageTech, LLC
# Distributed under the MIT software license, see COPYING.

from decimal import Decimal

from test_framework.address import base58_to_byte
from test_framework.authproxy import JSONRPCException
from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.key import SECP256K1, SECP256K1_G, SECP256K1_ORDER
from test_framework.messages import CTransaction, CTxOut, FromHex, hash256
from test_framework.script import CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, modinv


def make_drivechain_script(sidechain_id: int, payload_hex: str, tag: int, auth_sig: bytes = None) -> CScript:
    payload = bytes.fromhex(payload_hex)[::-1]
    assert len(payload) == 32
    raw = bytes([0x6A, 0xB4, 0x01, sidechain_id, 0x20]) + payload + bytes([0x01, tag])
    if auth_sig is not None:
        assert len(auth_sig) == 65
        raw += bytes([0x41]) + auth_sig
    return CScript(raw)


def decode_wif_privkey(wif: str):
    payload, version = base58_to_byte(wif)
    assert version in (128, 239)
    if len(payload) == 33 and payload[-1] == 0x01:
        return payload[:32], True
    if len(payload) == 32:
        return payload, False
    raise AssertionError("unexpected WIF payload length")


def compute_bundle_auth_message(scid: int, bundle_hash_hex: str) -> bytes:
    # C++: "DCBA\x01" || scid || bundle_hash(uint256 internal bytes)
    preimage = b"DCBA\x01" + bytes([scid]) + bytes.fromhex(bundle_hash_hex)[::-1]
    return hash256(preimage)


def sign_compact_recoverable(secret_bytes: bytes, msg_hash: bytes, compressed: bool) -> bytes:
    secret = int.from_bytes(secret_bytes, "big")
    assert 1 <= secret < SECP256K1_ORDER
    z = int.from_bytes(msg_hash, "big")

    for counter in range(1, 1024):
        k = int.from_bytes(hash256(secret_bytes + msg_hash + counter.to_bytes(4, byteorder="big")), "big") % SECP256K1_ORDER
        if k == 0:
            continue

        R = SECP256K1.affine(SECP256K1.mul([(SECP256K1_G, k)]))
        if R is None:
            continue

        r_full = R[0]
        r = r_full % SECP256K1_ORDER
        if r == 0:
            continue

        s = (modinv(k, SECP256K1_ORDER) * (z + r * secret)) % SECP256K1_ORDER
        if s == 0:
            continue

        recid = (1 if (R[1] & 1) else 0) | (2 if r_full >= SECP256K1_ORDER else 0)
        if s > (SECP256K1_ORDER // 2):
            s = SECP256K1_ORDER - s
            recid ^= 1

        header = 27 + recid + (4 if compressed else 0)
        return bytes([header]) + r.to_bytes(32, "big") + s.to_bytes(32, "big")

    raise AssertionError("failed to create compact signature")


def submit_block(node, *, extra_coinbase_vouts=None, txids=None, tx_hexes=None):
    if extra_coinbase_vouts is None:
        extra_coinbase_vouts = []
    if txids is None:
        txids = []
    if tx_hexes is None:
        tx_hexes = []

    tip = node.getbestblockhash()
    height = node.getblockcount() + 1
    ntime = node.getblockheader(tip)["time"] + 1

    coinbase = create_coinbase(height)
    for vout in extra_coinbase_vouts:
        coinbase.vout.append(vout)
    coinbase.rehash()

    block = create_block(int(tip, 16), coinbase, ntime, version=0x20000000)
    for txid in txids:
        try:
            txhex = node.getrawtransaction(txid)
        except JSONRPCException:
            txhex = node.gettransaction(txid)["hex"]
        tx = FromHex(CTransaction(), txhex)
        tx.rehash()
        block.vtx.append(tx)
    for tx_hex in tx_hexes:
        tx = FromHex(CTransaction(), tx_hex)
        tx.rehash()
        block.vtx.append(tx)

    block.hashMerkleRoot = block.calc_merkle_root()
    add_witness_commitment(block)
    block.solve()
    return node.submitblock(block.serialize().hex())


def mine_empty(node, nblocks: int):
    for _ in range(nblocks):
        assert_equal(submit_block(node), None)


def mine_votes(node, *, scid: int, bundle_hash_hex: str, nblocks: int):
    vote_spk = make_drivechain_script(scid, bundle_hash_hex, 0x02)
    vote_out = CTxOut(0, vote_spk)
    for _ in range(nblocks):
        assert_equal(submit_block(node, extra_coinbase_vouts=[vote_out]), None)


def get_bundle(node, scid: int, bundle_hash_hex: str):
    info = node.getdrivechaininfo()
    for sc in info["sidechains"]:
        if sc["id"] != scid:
            continue
        for bundle in sc["bundles"]:
            if bundle["hash"] == bundle_hash_hex:
                return bundle
    return None


def make_bundle_hash(node, scid: int, withdrawals):
    preimage = bytearray()
    preimage.append(scid)
    preimage.extend(len(withdrawals).to_bytes(4, byteorder="little"))
    for w in withdrawals:
        script_hex = w.get("script")
        if script_hex is None:
            script_hex = node.getaddressinfo(w["address"])["scriptPubKey"]
        script = bytes.fromhex(script_hex)

        amount_sat = int(w["amount"] * 100_000_000)
        preimage.extend(amount_sat.to_bytes(8, byteorder="little", signed=False))
        preimage.append(len(script))
        preimage.extend(script)

    return hash256(bytes(preimage))[::-1].hex()


def create_funded_signed_tx_hex(node, script: CScript, amount: Decimal) -> str:
    tx = CTransaction()
    tx.vin = []
    tx.vout = [CTxOut(int(amount * 100_000_000), script)]
    funded = node.fundrawtransaction(tx.serialize().hex())["hex"]
    return node.signrawtransactionwithwallet(funded)["hex"]


class DrivechainCheckConnectAlignment(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def run_test(self):
        n = self.nodes[0]
        n.generatetoaddress(110, n.getnewaddress())

        scid = 1
        withdrawals = [{"address": n.getnewaddress(), "amount": Decimal("0.2")}]
        bundle1 = make_bundle_hash(n, scid, withdrawals)
        bundle2 = "22" * 32

        owner_privkey = n.dumpprivkey(n.getnewaddress())
        n.senddrivechainregister(owner_privkey, scid, Decimal("1.0"))
        n.generatetoaddress(1, n.getnewaddress())

        n.senddrivechaindeposit(scid, "00" * 32, [Decimal("1.0")])
        n.generatetoaddress(1, n.getnewaddress())

        n.senddrivechainbundle(scid, bundle1, Decimal("0.1"), False, owner_privkey)
        n.generatetoaddress(1, n.getnewaddress())

        bundle = get_bundle(n, scid, bundle1)
        assert bundle is not None
        vote_start = int(bundle["vote_start_height"])
        vote_end = int(bundle["vote_end_height"])
        approval_height = int(bundle["approval_height"])
        executable_height = int(bundle["executable_height"])

        cur_h = n.getblockcount()
        if cur_h < vote_start:
            mine_empty(n, vote_start - cur_h - 1)

        while n.getblockcount() < vote_end:
            mine_votes(n, scid=scid, bundle_hash_hex=bundle1, nblocks=1)

        bundle = get_bundle(n, scid, bundle1)
        assert bundle is not None
        assert_equal(bundle["approved"], False)

        assert_equal(submit_block(n), None)
        bundle = get_bundle(n, scid, bundle1)
        assert bundle is not None
        assert_equal(n.getblockcount(), approval_height)
        assert_equal(bundle["approved"], True)

        cur_h = n.getblockcount()
        if cur_h < executable_height:
            mine_empty(n, executable_height - cur_h)

        exec_txid = n.senddrivechainexecute(scid, bundle1, withdrawals, True)
        owner_secret, owner_compressed = decode_wif_privkey(owner_privkey)
        auth_msg = compute_bundle_auth_message(scid, bundle2)
        auth_sig = sign_compact_recoverable(owner_secret, auth_msg, owner_compressed)
        commit2_spk = make_drivechain_script(scid, bundle2, 0x01, auth_sig)
        tx2_hex = create_funded_signed_tx_hex(n, commit2_spk, Decimal("0.1"))

        # EXECUTE first, then a new commit in the same block. This guards
        # alignment between pre-check and state-transition logic.
        assert_equal(submit_block(n, txids=[exec_txid], tx_hexes=[tx2_hex]), None)

        bundle1_after = get_bundle(n, scid, bundle1)
        assert bundle1_after is not None
        assert_equal(bundle1_after["executed"], True)

        bundle2_after = get_bundle(n, scid, bundle2)
        assert bundle2_after is not None
        assert_equal(bundle2_after["approved"], False)
        assert_equal(bundle2_after["executed"], False)


if __name__ == "__main__":
    DrivechainCheckConnectAlignment().main()
