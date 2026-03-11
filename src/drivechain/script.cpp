// Copyright (c) 2025-2026 AllSageTech, LLC
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <drivechain/script.h>

#include <hash.h>
#include <pubkey.h>
#include <script/script.h>
#include <script/script_error.h>

#include <algorithm>
#include <crypto/common.h>
#include <limits>
#include <set>

namespace {

static constexpr unsigned char BMM_REQUEST_MAGIC[] = {0x00, 0xbf, 0x00};
static constexpr unsigned char BMM_ACCEPT_MAGIC[] = {0xd1, 0x61, 0x73, 0x68};
static constexpr unsigned char BUNDLE_AUTH_MAGIC[] = {'D', 'C', 'B', 'A', 0x01};
static constexpr unsigned char REGISTER_AUTH_MAGIC[] = {'D', 'C', 'R', 'A', 0x01};
static constexpr unsigned char POLICY_HASH_MAGIC[] = {'D', 'C', 'P', 'A', 0x01};

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

static void WriteLE64(std::vector<unsigned char>& out, uint64_t v)
{
    out.resize(8);
    out[0] = (v >> 0) & 0xff;
    out[1] = (v >> 8) & 0xff;
    out[2] = (v >> 16) & 0xff;
    out[3] = (v >> 24) & 0xff;
    out[4] = (v >> 32) & 0xff;
    out[5] = (v >> 40) & 0xff;
    out[6] = (v >> 48) & 0xff;
    out[7] = (v >> 56) & 0xff;
}

static bool RecoverCompactSigKeyHash(
    const uint256& msg,
    Span<const unsigned char> compact_sig,
    uint256& out_key_hash)
{
    if (compact_sig.size() != CPubKey::COMPACT_SIGNATURE_SIZE) {
        return false;
    }

    CPubKey recovered_pubkey;
    std::vector<unsigned char> sig(compact_sig.begin(), compact_sig.end());
    if (!recovered_pubkey.RecoverCompact(msg, sig)) {
        return false;
    }

    const std::vector<unsigned char> pubkey_bytes(recovered_pubkey.begin(), recovered_pubkey.end());
    out_key_hash = Hash(pubkey_bytes);
    return true;
}

static bool HasDistinctThresholdMatches(
    const DrivechainSidechainPolicy& policy,
    const uint256& msg,
    const std::vector<std::vector<unsigned char>>& compact_sigs)
{
    if (!policy.RequiresOwnerAuth() ||
        policy.owner_key_hashes.size() > MAX_DRIVECHAIN_OWNER_KEYS ||
        policy.auth_threshold > policy.owner_key_hashes.size() ||
        compact_sigs.size() < policy.auth_threshold) {
        return false;
    }

    std::set<uint256> matched_hashes;
    for (const auto& sig : compact_sigs) {
        uint256 recovered_key_hash;
        if (!RecoverCompactSigKeyHash(msg, sig, recovered_key_hash)) {
            return false;
        }

        if (std::find(policy.owner_key_hashes.begin(), policy.owner_key_hashes.end(), recovered_key_hash) ==
            policy.owner_key_hashes.end()) {
            return false;
        }

        if (!matched_hashes.insert(recovered_key_hash).second) {
            return false;
        }
    }

    return matched_hashes.size() >= policy.auth_threshold;
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
    // [5]: (REGISTER only) PUSHDATA(policy)
    // [5..n]: (BUNDLE_COMMIT/REGISTER optional) PUSHDATA(65) -> compact auth signatures

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
    info.auth_sigs.clear();

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
    } else if (info.kind == DrivechainScriptInfo::Kind::REGISTER) {
        if (!scriptPubKey.GetOp(pc, opcode, vch)) {
            return false;
        }
        if (!DecodeDrivechainSidechainPolicy(vch, info.sidechain_policy)) {
            return false;
        }

        while (pc != scriptPubKey.end()) {
            if (!scriptPubKey.GetOp(pc, opcode, vch) || vch.size() != CPubKey::COMPACT_SIGNATURE_SIZE) {
                return false;
            }
            info.auth_sigs.push_back(vch);
        }
    } else if (info.kind == DrivechainScriptInfo::Kind::BUNDLE_COMMIT) {
        while (pc != scriptPubKey.end()) {
            if (!scriptPubKey.GetOp(pc, opcode, vch) || vch.size() != CPubKey::COMPACT_SIGNATURE_SIZE) {
                return false;
            }
            info.auth_sigs.push_back(vch);
        }
    }

    if (!info.auth_sigs.empty()) {
        info.auth_sig = info.auth_sigs.front();
    }

    if (pc != scriptPubKey.end()) {
        return false;
    }

    out_info = info;
    return true;
}

std::vector<unsigned char> EncodeDrivechainSidechainPolicy(const DrivechainSidechainPolicy& policy)
{
    std::vector<unsigned char> out;
    out.reserve(18 + (policy.owner_key_hashes.size() * 32));

    out.push_back(policy.auth_threshold);
    out.push_back(static_cast<unsigned char>(policy.owner_key_hashes.size()));

    std::vector<unsigned char> max_escrow_bytes;
    WriteLE64(max_escrow_bytes, static_cast<uint64_t>(policy.max_escrow_amount));
    out.insert(out.end(), max_escrow_bytes.begin(), max_escrow_bytes.end());

    std::vector<unsigned char> max_bundle_bytes;
    WriteLE64(max_bundle_bytes, static_cast<uint64_t>(policy.max_bundle_withdrawal));
    out.insert(out.end(), max_bundle_bytes.begin(), max_bundle_bytes.end());

    for (const uint256& key_hash : policy.owner_key_hashes) {
        out.insert(out.end(), key_hash.begin(), key_hash.end());
    }

    return out;
}

bool DecodeDrivechainSidechainPolicy(Span<const unsigned char> policy_bytes, DrivechainSidechainPolicy& out_policy)
{
    if (policy_bytes.size() < 18) {
        return false;
    }

    DrivechainSidechainPolicy policy;
    policy.auth_threshold = policy_bytes[0];
    const size_t key_count = policy_bytes[1];
    if (key_count == 0 || key_count > MAX_DRIVECHAIN_OWNER_KEYS) {
        return false;
    }
    if (policy.auth_threshold == 0 || policy.auth_threshold > key_count) {
        return false;
    }
    if (policy_bytes.size() != 18 + (key_count * 32)) {
        return false;
    }

    const uint64_t max_escrow = ReadLE64(policy_bytes.data() + 2);
    const uint64_t max_bundle_withdrawal = ReadLE64(policy_bytes.data() + 10);
    if (max_escrow == 0 || max_bundle_withdrawal == 0) {
        return false;
    }
    if (max_bundle_withdrawal > max_escrow) {
        return false;
    }
    if (max_escrow > std::numeric_limits<CAmount>::max() ||
        max_bundle_withdrawal > std::numeric_limits<CAmount>::max()) {
        return false;
    }
    policy.max_escrow_amount = static_cast<CAmount>(max_escrow);
    policy.max_bundle_withdrawal = static_cast<CAmount>(max_bundle_withdrawal);
    if (!MoneyRange(policy.max_escrow_amount) || !MoneyRange(policy.max_bundle_withdrawal)) {
        return false;
    }

    policy.owner_key_hashes.reserve(key_count);
    for (size_t i = 0; i < key_count; ++i) {
        uint256 key_hash;
        std::copy(
            policy_bytes.begin() + 18 + (i * 32),
            policy_bytes.begin() + 18 + ((i + 1) * 32),
            key_hash.begin());
        if (!policy.owner_key_hashes.empty() && !(policy.owner_key_hashes.back() < key_hash)) {
            return false;
        }
        policy.owner_key_hashes.push_back(key_hash);
    }

    out_policy = policy;
    return true;
}

uint256 ComputeDrivechainSidechainPolicyHash(const DrivechainSidechainPolicy& policy)
{
    const std::vector<unsigned char> encoded_policy = EncodeDrivechainSidechainPolicy(policy);

    CHashWriter hw(SER_GETHASH, 0);
    hw.write((const char*)POLICY_HASH_MAGIC, sizeof(POLICY_HASH_MAGIC));
    hw.write((const char*)encoded_policy.data(), encoded_policy.size());
    return hw.GetHash();
}

uint256 ComputeDrivechainBundleAuthMessage(uint8_t scid, const uint256& bundle_hash)
{
    CHashWriter hw(SER_GETHASH, 0);
    hw.write((const char*)BUNDLE_AUTH_MAGIC, sizeof(BUNDLE_AUTH_MAGIC));
    hw << scid;
    hw << bundle_hash;
    return hw.GetHash();
}

bool VerifyDrivechainBundleAuthSigs(
    const DrivechainSidechainPolicy& policy,
    uint8_t scid,
    const uint256& bundle_hash,
    const std::vector<std::vector<unsigned char>>& compact_sigs)
{
    const uint256 msg = ComputeDrivechainBundleAuthMessage(scid, bundle_hash);
    return HasDistinctThresholdMatches(policy, msg, compact_sigs);
}

uint256 ComputeDrivechainRegisterAuthMessage(uint8_t scid, const uint256& owner_policy_hash)
{
    CHashWriter hw(SER_GETHASH, 0);
    hw.write((const char*)REGISTER_AUTH_MAGIC, sizeof(REGISTER_AUTH_MAGIC));
    hw << scid;
    hw << owner_policy_hash;
    return hw.GetHash();
}

bool VerifyDrivechainRegisterAuthSigs(
    uint8_t scid,
    const DrivechainSidechainPolicy& policy,
    const std::vector<std::vector<unsigned char>>& compact_sigs)
{
    const uint256 policy_hash = ComputeDrivechainSidechainPolicyHash(policy);
    const uint256 msg = ComputeDrivechainRegisterAuthMessage(scid, policy_hash);
    return HasDistinctThresholdMatches(policy, msg, compact_sigs);
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
