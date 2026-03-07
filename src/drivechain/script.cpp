// Copyright (c) 2025-2026 AllSageTech, LLC
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <drivechain/script.h>

#include <chainparams.h>
#include <hash.h>
#include <pubkey.h>
#include <script/script.h>
#include <script/script_error.h>
#include <algorithm>
#include <crypto/common.h>

namespace {

static constexpr unsigned char BMM_REQUEST_MAGIC[] = {0x00, 0xbf, 0x00};
static constexpr unsigned char BMM_ACCEPT_MAGIC[] = {0xd1, 0x61, 0x73, 0x68};
static constexpr unsigned char BUNDLE_AUTH_MAGIC[] = {'D', 'C', 'B', 'A', 0x01};
static constexpr unsigned char REGISTER_AUTH_MAGIC[] = {'D', 'C', 'R', 'A', 0x01};

static const uint256& GetDrivechainAuthDomain()
{
    // Bind owner-auth signatures to the active chain so a signature published on
    // one network cannot be replayed on another.
    return Params().GenesisBlock().GetHash();
}

static bool DecodeSinglePushAfterOpReturn(const CScript& scriptPubKey, std::vector<unsigned char>& out_payload)
{
    CScript::const_iterator pc = scriptPubKey.begin();
    opcodetype opcode;
    if (!scriptPubKey.GetOp(pc, opcode) || opcode != OP_RETURN) {
        return false;
    }

    std::vector<unsigned char> vch;
    if (!scriptPubKey.GetOp(pc, opcode, vch)) {
        return false;
    }
    if (pc != scriptPubKey.end()) {
        return false;
    }

    out_payload = std::move(vch);
    return true;
}

} // namespace

bool DecodeDrivechainScript(const CScript& scriptPubKey, DrivechainScriptInfo& out_info)
{
    // (provably unspendable):
    // [0]: OP_RETURN
    // [1]: OP_DRIVECHAIN
    // [2]: PUSHDATA(1)   -> sidechain_id
    // [3]: PUSHDATA(32)  -> payload (bundle_hash / etc)
    // [4]: PUSHDATA(1)   -> kind_tag
    // [5]: (EXECUTE only) PUSHDATA(4) -> n_withdrawals (LE32)
    // [5]: (BUNDLE_COMMIT/REGISTER optional) PUSHDATA(65) -> compact auth signature

    CScript::const_iterator pc = scriptPubKey.begin();
    opcodetype opcode;

    if (!scriptPubKey.GetOp(pc, opcode) || opcode != OP_RETURN) {
        return false;
    }

    if (!scriptPubKey.GetOp(pc, opcode) || opcode != OP_DRIVECHAIN) {
        return false;
    }

    std::vector<unsigned char> vch;

    if (!scriptPubKey.GetOp(pc, opcode, vch) || vch.size() != 1) {
        return false;
    }
    const uint8_t sidechain_id = vch[0];

    if (!scriptPubKey.GetOp(pc, opcode, vch) || vch.size() != 32) {
        return false;
    }
    uint256 payload;
    std::copy(vch.begin(), vch.end(), payload.begin());

    if (!scriptPubKey.GetOp(pc, opcode, vch) || vch.size() != 1) {
        return false;
    }
    const uint8_t tag = vch[0];

    DrivechainScriptInfo info;
    info.sidechain_id = sidechain_id;
    info.payload = payload;
    info.n_withdrawals = 0;
    info.auth_sig.clear();

    switch (tag) {
        case 0x00: info.kind = DrivechainScriptInfo::Kind::DEPOSIT;       break;
        case 0x01: info.kind = DrivechainScriptInfo::Kind::BUNDLE_COMMIT; break;
        case 0x02: info.kind = DrivechainScriptInfo::Kind::VOTE_YES;      break;
        case 0x03: info.kind = DrivechainScriptInfo::Kind::EXECUTE;       break;
        case 0x04: info.kind = DrivechainScriptInfo::Kind::VOTE_NO;       break;
        case 0x05: info.kind = DrivechainScriptInfo::Kind::REGISTER;      break;
        default:   info.kind = DrivechainScriptInfo::Kind::UNKNOWN;       break;
    }

    if (info.kind == DrivechainScriptInfo::Kind::UNKNOWN) {
        return false;
    }

    if (info.kind == DrivechainScriptInfo::Kind::EXECUTE) {
        if (!scriptPubKey.GetOp(pc, opcode, vch) || vch.size() != 4) {
            return false;
        }
        info.n_withdrawals = ReadLE32(vch.data());
        if (info.n_withdrawals == 0) {
            return false;
        }
    } else if ((info.kind == DrivechainScriptInfo::Kind::BUNDLE_COMMIT ||
                info.kind == DrivechainScriptInfo::Kind::REGISTER) &&
               pc != scriptPubKey.end()) {
        if (!scriptPubKey.GetOp(pc, opcode, vch) || vch.size() != CPubKey::COMPACT_SIGNATURE_SIZE) {
            return false;
        }
        info.auth_sig = vch;
    }

    if (pc != scriptPubKey.end()) {
        return false;
    }

    out_info = info;
    return true;
}

uint256 ComputeDrivechainBundleAuthMessage(uint8_t scid, const uint256& bundle_hash)
{
    CHashWriter hw(SER_GETHASH, 0);
    hw.write((const char*)BUNDLE_AUTH_MAGIC, sizeof(BUNDLE_AUTH_MAGIC));
    hw << GetDrivechainAuthDomain();
    hw << scid;
    hw << bundle_hash;
    return hw.GetHash();
}

bool VerifyDrivechainBundleAuthSig(
    const uint256& owner_key_hash,
    uint8_t scid,
    const uint256& bundle_hash,
    Span<const unsigned char> compact_sig)
{
    if (compact_sig.size() != CPubKey::COMPACT_SIGNATURE_SIZE) {
        return false;
    }

    CPubKey recovered_pubkey;
    std::vector<unsigned char> sig(compact_sig.begin(), compact_sig.end());
    const uint256 msg = ComputeDrivechainBundleAuthMessage(scid, bundle_hash);
    if (!recovered_pubkey.RecoverCompact(msg, sig)) {
        return false;
    }

    const std::vector<unsigned char> pubkey_bytes(recovered_pubkey.begin(), recovered_pubkey.end());
    const uint256 recovered_key_hash = Hash(pubkey_bytes);
    return recovered_key_hash == owner_key_hash;
}

uint256 ComputeDrivechainRegisterAuthMessage(uint8_t scid, const uint256& owner_key_hash)
{
    CHashWriter hw(SER_GETHASH, 0);
    hw.write((const char*)REGISTER_AUTH_MAGIC, sizeof(REGISTER_AUTH_MAGIC));
    hw << GetDrivechainAuthDomain();
    hw << scid;
    hw << owner_key_hash;
    return hw.GetHash();
}

bool VerifyDrivechainRegisterAuthSig(
    uint8_t scid,
    const uint256& owner_key_hash,
    Span<const unsigned char> compact_sig)
{
    if (compact_sig.size() != CPubKey::COMPACT_SIGNATURE_SIZE) {
        return false;
    }

    CPubKey recovered_pubkey;
    std::vector<unsigned char> sig(compact_sig.begin(), compact_sig.end());
    const uint256 msg = ComputeDrivechainRegisterAuthMessage(scid, owner_key_hash);
    if (!recovered_pubkey.RecoverCompact(msg, sig)) {
        return false;
    }

    const std::vector<unsigned char> pubkey_bytes(recovered_pubkey.begin(), recovered_pubkey.end());
    const uint256 recovered_key_hash = Hash(pubkey_bytes);
    return recovered_key_hash == owner_key_hash;
}

bool DecodeDrivechainBmmRequestScript(const CScript& scriptPubKey, DrivechainBmmRequestInfo& out_info)
{
    std::vector<unsigned char> payload;
    if (!DecodeSinglePushAfterOpReturn(scriptPubKey, payload)) {
        return false;
    }

    static constexpr size_t BMM_REQUEST_SIZE = 3 + 1 + 32 + 32;
    if (payload.size() != BMM_REQUEST_SIZE) {
        return false;
    }
    if (!std::equal(std::begin(BMM_REQUEST_MAGIC), std::end(BMM_REQUEST_MAGIC), payload.begin())) {
        return false;
    }

    DrivechainBmmRequestInfo info;
    info.sidechain_id = payload[3];
    std::copy(payload.begin() + 4, payload.begin() + 36, info.side_block_hash.begin());
    std::copy(payload.begin() + 36, payload.begin() + 68, info.prev_main_block_hash.begin());

    out_info = info;
    return true;
}

bool DecodeDrivechainBmmAcceptScript(const CScript& scriptPubKey, DrivechainBmmAcceptInfo& out_info)
{
    std::vector<unsigned char> payload;
    if (!DecodeSinglePushAfterOpReturn(scriptPubKey, payload)) {
        return false;
    }

    static constexpr size_t BMM_ACCEPT_SIZE = 4 + 1 + 32;
    if (payload.size() != BMM_ACCEPT_SIZE) {
        return false;
    }
    if (!std::equal(std::begin(BMM_ACCEPT_MAGIC), std::end(BMM_ACCEPT_MAGIC), payload.begin())) {
        return false;
    }

    DrivechainBmmAcceptInfo info;
    info.sidechain_id = payload[4];
    std::copy(payload.begin() + 5, payload.begin() + 37, info.side_block_hash.begin());

    out_info = info;
    return true;
}

static void WriteLE32(std::vector<unsigned char>& out, uint32_t v)
{
    out.resize(4);
    out[0] = (v >> 0) & 0xff;
    out[1] = (v >> 8) & 0xff;
    out[2] = (v >> 16) & 0xff;
    out[3] = (v >> 24) & 0xff;
}

CScript BuildDrivechainExecuteScript(uint8_t scid, const uint256& bundle_hash, uint32_t n_withdrawals)
{
    std::vector<unsigned char> scid_v{scid};

    std::vector<unsigned char> payload(32);
    std::copy(bundle_hash.begin(), bundle_hash.end(), payload.begin());

    std::vector<unsigned char> tag{0x03};

    std::vector<unsigned char> n_le;
    WriteLE32(n_le, n_withdrawals);

    CScript s;
    s << OP_RETURN << OP_DRIVECHAIN << scid_v << payload << tag << n_le;
    return s;
}

CScript BuildDrivechainBmmRequestScript(uint8_t scid, const uint256& side_block_hash, const uint256& prev_main_block_hash)
{
    std::vector<unsigned char> payload;
    payload.reserve(3 + 1 + 32 + 32);
    payload.insert(payload.end(), std::begin(BMM_REQUEST_MAGIC), std::end(BMM_REQUEST_MAGIC));
    payload.push_back(scid);
    payload.insert(payload.end(), side_block_hash.begin(), side_block_hash.end());
    payload.insert(payload.end(), prev_main_block_hash.begin(), prev_main_block_hash.end());

    CScript s;
    s << OP_RETURN << payload;
    return s;
}

CScript BuildDrivechainBmmAcceptScript(uint8_t scid, const uint256& side_block_hash)
{
    std::vector<unsigned char> payload;
    payload.reserve(4 + 1 + 32);
    payload.insert(payload.end(), std::begin(BMM_ACCEPT_MAGIC), std::end(BMM_ACCEPT_MAGIC));
    payload.push_back(scid);
    payload.insert(payload.end(), side_block_hash.begin(), side_block_hash.end());

    CScript s;
    s << OP_RETURN << payload;
    return s;
}
