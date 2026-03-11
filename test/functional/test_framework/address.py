#!/usr/bin/env python3
# Copyright (c) 2016-2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Encode and decode Bitcoin addresses.

- base58 P2PKH and P2SH addresses.
- bech32 segwit v0 P2WPKH and P2WSH addresses."""

import enum
import importlib
from io import BytesIO
import sys
import unittest

from .script import hash256, hash160, sha256, CScript, OP_0
from .segwit_addr import encode_segwit_address
from .util import assert_equal, hex_str_to_bytes

ADDRESS_BCRT1_UNSPENDABLE = 'rltc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqe9kxtl'
ADDRESS_BCRT1_UNSPENDABLE_DESCRIPTOR = 'addr(rltc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqe9kxtl)#xm6azk0m'
# Coins sent to this address can be spent with a witness stack of just OP_TRUE
ADDRESS_BCRT1_P2WSH_OP_TRUE = 'rltc1qft5p2uhsdcdc3l2ua4ap5qqfg4pjaqlp250x7us7a8qqhrxrxfsqc6h8ge'


class AddressType(enum.Enum):
    bech32 = 'bech32'
    p2sh_segwit = 'p2sh-segwit'
    legacy = 'legacy'  # P2PKH


chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def byte_to_base58(b, version):
    result = ''
    str = b.hex()
    str = chr(version).encode('latin-1').hex() + str
    checksum = hash256(hex_str_to_bytes(str)).hex()
    str += checksum[:8]
    value = int('0x' + str, 0)
    while value > 0:
        result = chars[value % 58] + result
        value //= 58
    while (str[:2] == '00'):
        result = chars[0] + result
        str = str[2:]
    return result


def base58_to_byte(s):
    """Converts a base58-encoded string to its data and version.

    Throws if the base58 checksum is invalid."""
    if not s:
        return b''
    n = 0
    for c in s:
        n *= 58
        assert c in chars
        digit = chars.index(c)
        n += digit
    h = '%x' % n
    if len(h) % 2:
        h = '0' + h
    res = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    pad = 0
    for c in s:
        if c == chars[0]:
            pad += 1
        else:
            break
    res = b'\x00' * pad + res

    # Assert if the checksum is invalid
    assert_equal(hash256(res[:-4])[:4], res[-4:])

    return res[1:-4], int(res[0])


def keyhash_to_p2pkh(hash, main=False):
    assert len(hash) == 20
    version = 0 if main else 111
    return byte_to_base58(hash, version)

def scripthash_to_p2sh(hash, main=False):
    assert len(hash) == 20
    version = 5 if main else 58
    return byte_to_base58(hash, version)

def key_to_p2pkh(key, main=False):
    key = check_key(key)
    return keyhash_to_p2pkh(hash160(key), main)

def script_to_p2sh(script, main=False):
    script = check_script(script)
    return scripthash_to_p2sh(hash160(script), main)

def key_to_p2sh_p2wpkh(key, main=False):
    key = check_key(key)
    p2shscript = CScript([OP_0, hash160(key)])
    return script_to_p2sh(p2shscript, main)

def program_to_witness(version, program, main=False):
    if (type(program) is str):
        program = hex_str_to_bytes(program)
    assert 0 <= version <= 16
    assert 2 <= len(program) <= 40
    assert version > 0 or len(program) in [20, 32]
    return encode_segwit_address("ltc" if main else "rltc", version, program)

def script_to_p2wsh(script, main=False):
    script = check_script(script)
    return program_to_witness(0, sha256(script), main)

def key_to_p2wpkh(key, main=False):
    key = check_key(key)
    return program_to_witness(0, hash160(key), main)

def script_to_p2sh_p2wsh(script, main=False):
    script = check_script(script)
    p2shscript = CScript([OP_0, sha256(script)])
    return script_to_p2sh(p2shscript, main)

def check_key(key):
    if (type(key) is str):
        key = hex_str_to_bytes(key)  # Assuming this is hex string
    if (type(key) is bytes and (len(key) == 33 or len(key) == 65)):
        return key
    assert False

def check_script(script):
    if (type(script) is str):
        script = hex_str_to_bytes(script)  # Assuming this is hex string
    if (type(script) is bytes or type(script) is CScript):
        return script
    assert False


class TestFrameworkScript(unittest.TestCase):
    def test_messages_import_without_litecoin_scrypt(self):
        original_messages = sys.modules.pop("test_framework.messages", None)
        try:
            messages = importlib.import_module("test_framework.messages")
            self.assertTrue(hasattr(messages, "CBlockHeader"))
        finally:
            sys.modules.pop("test_framework.messages", None)
            if original_messages is not None:
                sys.modules["test_framework.messages"] = original_messages

    def test_messages_calc_sha256_matches_known_scrypt_vector(self):
        messages = importlib.import_module("test_framework.messages")
        header = messages.CBlockHeader()
        header.deserialize(BytesIO(bytes.fromhex(
            "020000004c1271c211717198227392b029a64a7971931d351b387bb80db027f270411e398a07046f7d4a08dd815412a8712f874a7ebf0507e3878bd24e20a3b73fd750a667d2f451eac7471b00de6659"
        )))
        header.calc_sha256()
        self.assertEqual(
            f"{header.scrypt256:064x}",
            "00000000002bef4107f882f6115e0b01f348d21195dacd3582aa2dabd7985806",
        )

    def test_mweb_header_from_json_uses_rpc_hash_without_blake3(self):
        messages = importlib.import_module("test_framework.messages")
        header = messages.MWEBHeader()
        header_json = {
            "hash": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "height": 7,
            "output_root": "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            "kernel_root": "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
            "leaf_root": "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
            "kernel_offset": "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "stealth_offset": "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
            "num_txos": 2,
            "num_kernels": 3,
        }
        header.from_json(header_json)
        self.assertEqual(header.hash, messages.Hash.from_rev_hex(header_json["hash"]))

    def test_mweb_header_equality_ignores_missing_blake3_hash(self):
        messages = importlib.import_module("test_framework.messages")
        header_json = {
            "hash": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "height": 7,
            "output_root": "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            "kernel_root": "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
            "leaf_root": "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
            "kernel_offset": "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "stealth_offset": "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
            "num_txos": 2,
            "num_kernels": 3,
        }

        header_from_rpc = messages.MWEBHeader()
        header_from_rpc.from_json(header_json)

        header_from_wire = messages.MWEBHeader()
        header_from_wire.deserialize(BytesIO(header_from_rpc.serialize()))

        self.assertIsNone(header_from_wire.hash)
        self.assertEqual(header_from_rpc, header_from_wire)

    def test_mweb_block_deserialize_without_blake3(self):
        messages = importlib.import_module("test_framework.messages")

        mweb_input = messages.MWEBInput()
        mweb_input.features = 0
        mweb_input.output_id = messages.Hash(1)
        mweb_input.commitment = 2
        mweb_input.output_pubkey = 3
        mweb_input.signature = 4

        output_message = messages.MWEBOutputMessage()
        output_message.features = 0

        mweb_output = messages.MWEBOutput()
        mweb_output.commitment = 5
        mweb_output.sender_pubkey = 6
        mweb_output.receiver_pubkey = 7
        mweb_output.message = output_message
        mweb_output.proof = b"\x00" * 675
        mweb_output.signature = 8

        mweb_kernel = messages.MWEBKernel()
        mweb_kernel.features = 0
        mweb_kernel.excess = 9
        mweb_kernel.signature = 10

        mweb_block = messages.MWEBBlock()
        mweb_block.body.inputs = [mweb_input]
        mweb_block.body.outputs = [mweb_output]
        mweb_block.body.kernels = [mweb_kernel]

        parsed = messages.MWEBBlock()
        parsed.deserialize(BytesIO(mweb_block.serialize()))

        self.assertIsNone(parsed.header.hash)
        self.assertIsNone(parsed.body.inputs[0].hash)
        self.assertIsNone(parsed.body.outputs[0].message.hash)
        self.assertIsNone(parsed.body.outputs[0].hash)
        self.assertIsNone(parsed.body.kernels[0].hash)

    def test_mweb_transaction_deserialize_without_blake3(self):
        messages = importlib.import_module("test_framework.messages")
        parsed = messages.MWEBTransaction()
        parsed.deserialize(BytesIO(messages.MWEBTransaction().serialize()))
        self.assertIsNone(parsed.hash)

    def test_mweb_compact_output_deserialize_without_blake3(self):
        messages = importlib.import_module("test_framework.messages")

        compact_output = messages.MWEBCompactOutput()
        compact_output.commitment = 1
        compact_output.sender_pubkey = 2
        compact_output.receiver_pubkey = 3
        compact_output.message.features = 0
        compact_output.proof_hash = messages.Hash(4)
        compact_output.signature = 5

        parsed = messages.MWEBCompactOutput()
        parsed.deserialize(BytesIO(compact_output.serialize()))
        self.assertIsNone(parsed.message.hash)
        self.assertIsNone(parsed.hash)

    def test_base58encodedecode(self):
        def check_base58(data, version):
            self.assertEqual(base58_to_byte(byte_to_base58(data, version)), (data, version))

        check_base58(bytes.fromhex('1f8ea1702a7bd4941bca0941b852c4bbfedb2e05'), 111)
        check_base58(bytes.fromhex('3a0b05f4d7f66c3ba7009f453530296c845cc9cf'), 111)
        check_base58(bytes.fromhex('41c1eaf111802559bad61b60d62b1f897c63928a'), 111)
        check_base58(bytes.fromhex('0041c1eaf111802559bad61b60d62b1f897c63928a'), 111)
        check_base58(bytes.fromhex('000041c1eaf111802559bad61b60d62b1f897c63928a'), 111)
        check_base58(bytes.fromhex('00000041c1eaf111802559bad61b60d62b1f897c63928a'), 111)
        check_base58(bytes.fromhex('1f8ea1702a7bd4941bca0941b852c4bbfedb2e05'), 0)
        check_base58(bytes.fromhex('3a0b05f4d7f66c3ba7009f453530296c845cc9cf'), 0)
        check_base58(bytes.fromhex('41c1eaf111802559bad61b60d62b1f897c63928a'), 0)
        check_base58(bytes.fromhex('0041c1eaf111802559bad61b60d62b1f897c63928a'), 0)
        check_base58(bytes.fromhex('000041c1eaf111802559bad61b60d62b1f897c63928a'), 0)
        check_base58(bytes.fromhex('00000041c1eaf111802559bad61b60d62b1f897c63928a'), 0)
