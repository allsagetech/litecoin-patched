// Copyright (c) 2026 AllSageTech, LLC
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <validitysidechain/script.h>

#include <crypto/common.h>
#include <hash.h>
#include <script/script.h>

#include <algorithm>
#include <limits>
#include <set>

namespace {

static constexpr unsigned char CONFIG_HASH_MAGIC[] = {'V', 'S', 'C', 'F', 0x01};
static constexpr unsigned char DEPOSIT_HASH_MAGIC[] = {'V', 'S', 'C', 'D', 0x01};
static constexpr unsigned char BATCH_HASH_MAGIC[] = {'V', 'S', 'C', 'B', 0x01};
static constexpr unsigned char WITHDRAWAL_ROOT_MAGIC[] = {'V', 'S', 'C', 'W', 0x01};
static constexpr unsigned char WITHDRAWAL_LEAF_HASH_MAGIC[] = {'V', 'S', 'C', 'W', 0x02};
static constexpr unsigned char WITHDRAWAL_NODE_HASH_MAGIC[] = {'V', 'S', 'C', 'W', 0x03};
static constexpr unsigned char ESCAPE_EXIT_ROOT_MAGIC[] = {'V', 'S', 'C', 'E', 0x01};
static constexpr unsigned char ESCAPE_EXIT_LEAF_HASH_MAGIC[] = {'V', 'S', 'C', 'E', 0x02};
static constexpr unsigned char ESCAPE_EXIT_NODE_HASH_MAGIC[] = {'V', 'S', 'C', 'E', 0x03};
static constexpr unsigned char ESCAPE_EXIT_STATE_CLAIM_KEY_MAGIC[] = {'V', 'S', 'C', 'E', 0x04};
static constexpr unsigned char ESCAPE_EXIT_STATE_ID_MAGIC[] = {'V', 'S', 'C', 'E', 0x05};
static constexpr unsigned char BALANCE_LEAF_HASH_MAGIC[] = {'V', 'S', 'C', 'S', 0x01};
static constexpr unsigned char BALANCE_NODE_HASH_MAGIC[] = {'V', 'S', 'C', 'S', 0x02};
static constexpr unsigned char ACCOUNT_STATE_LEAF_HASH_MAGIC[] = {'V', 'S', 'C', 'S', 0x03};
static constexpr unsigned char ACCOUNT_STATE_NODE_HASH_MAGIC[] = {'V', 'S', 'C', 'S', 0x04};
static constexpr unsigned char FORCE_EXIT_HASH_MAGIC[] = {'V', 'S', 'C', 'X', 0x01};
static constexpr unsigned char ACCEPTED_BATCH_ID_MAGIC[] = {'V', 'S', 'C', 'A', 0x01};
static constexpr size_t UINT256_BYTES = sizeof(uint256);

static constexpr size_t VALIDITY_SIDECHAIN_CONFIG_BYTES = 94;
static constexpr size_t VALIDITY_SIDECHAIN_DEPOSIT_BYTES = 112;
static constexpr size_t VALIDITY_SIDECHAIN_BATCH_PUBLIC_INPUT_BYTES = 236;
static constexpr size_t VALIDITY_SIDECHAIN_BATCH_DATA_CHUNK_HEADER_BYTES = 8;
static constexpr size_t VALIDITY_SIDECHAIN_WITHDRAWAL_LEAF_BYTES = 72;
static constexpr size_t VALIDITY_SIDECHAIN_WITHDRAWAL_PROOF_BASE_BYTES = 80;
static constexpr size_t VALIDITY_SIDECHAIN_BALANCE_LEAF_BYTES = 40;
static constexpr size_t VALIDITY_SIDECHAIN_BALANCE_PROOF_BASE_BYTES = 48;
static constexpr size_t VALIDITY_SIDECHAIN_ACCOUNT_STATE_LEAF_BYTES = 112;
static constexpr size_t VALIDITY_SIDECHAIN_ACCOUNT_STATE_PROOF_BASE_BYTES = 120;
static constexpr size_t VALIDITY_SIDECHAIN_ESCAPE_EXIT_LEAF_BYTES = 72;
static constexpr size_t VALIDITY_SIDECHAIN_ESCAPE_EXIT_PROOF_BASE_BYTES = 80;
static constexpr size_t VALIDITY_SIDECHAIN_ESCAPE_EXIT_STATE_PROOF_HEADER_BYTES = 128;
static constexpr size_t VALIDITY_SIDECHAIN_FORCE_EXIT_BYTES = 112;
static constexpr size_t MAX_VALIDITY_SIDECHAIN_MERKLE_PROOF_DEPTH = 32;

static void AppendLE32(std::vector<unsigned char>& out, uint32_t v)
{
    out.push_back((v >> 0) & 0xff);
    out.push_back((v >> 8) & 0xff);
    out.push_back((v >> 16) & 0xff);
    out.push_back((v >> 24) & 0xff);
}

static void AppendLE64(std::vector<unsigned char>& out, uint64_t v)
{
    out.push_back((v >> 0) & 0xff);
    out.push_back((v >> 8) & 0xff);
    out.push_back((v >> 16) & 0xff);
    out.push_back((v >> 24) & 0xff);
    out.push_back((v >> 32) & 0xff);
    out.push_back((v >> 40) & 0xff);
    out.push_back((v >> 48) & 0xff);
    out.push_back((v >> 56) & 0xff);
}

static void AppendUint256(std::vector<unsigned char>& out, const uint256& value)
{
    out.insert(out.end(), value.begin(), value.end());
}

static bool ReadUint256At(Span<const unsigned char> bytes, size_t offset, uint256& out)
{
    if (bytes.size() < offset + UINT256_BYTES) {
        return false;
    }

    std::copy(bytes.begin() + offset, bytes.begin() + offset + UINT256_BYTES, out.begin());
    return true;
}

static bool ReadAmount64(Span<const unsigned char> bytes, size_t offset, CAmount& out_amount)
{
    if (bytes.size() < offset + sizeof(uint64_t)) {
        return false;
    }

    const uint64_t raw_amount = ReadLE64(bytes.data() + offset);
    if (raw_amount == 0 || raw_amount > std::numeric_limits<CAmount>::max()) {
        return false;
    }

    out_amount = static_cast<CAmount>(raw_amount);
    return MoneyRange(out_amount);
}

static bool ReadAmount64AllowZero(Span<const unsigned char> bytes, size_t offset, CAmount& out_amount)
{
    if (bytes.size() < offset + sizeof(uint64_t)) {
        return false;
    }

    const uint64_t raw_amount = ReadLE64(bytes.data() + offset);
    if (raw_amount > static_cast<uint64_t>(std::numeric_limits<CAmount>::max())) {
        return false;
    }

    out_amount = static_cast<CAmount>(raw_amount);
    return MoneyRange(out_amount);
}

// Commit metadata carries explicit chunk ordinals so malformed DA ordering can
// be rejected before root recomputation.
static std::vector<unsigned char> EncodeValiditySidechainBatchDataChunk(
    uint32_t chunk_index,
    uint32_t chunk_count,
    Span<const unsigned char> chunk_bytes)
{
    std::vector<unsigned char> out;
    out.reserve(VALIDITY_SIDECHAIN_BATCH_DATA_CHUNK_HEADER_BYTES + chunk_bytes.size());
    AppendLE32(out, chunk_index);
    AppendLE32(out, chunk_count);
    out.insert(out.end(), chunk_bytes.begin(), chunk_bytes.end());
    return out;
}

static bool DecodeValiditySidechainBatchDataChunk(
    Span<const unsigned char> encoded_chunk,
    uint32_t expected_chunk_index,
    uint32_t expected_chunk_count,
    std::vector<unsigned char>& out_chunk_bytes)
{
    if (encoded_chunk.size() < VALIDITY_SIDECHAIN_BATCH_DATA_CHUNK_HEADER_BYTES) {
        return false;
    }
    if (ReadLE32(encoded_chunk.data()) != expected_chunk_index ||
        ReadLE32(encoded_chunk.data() + 4) != expected_chunk_count) {
        return false;
    }

    out_chunk_bytes.assign(
        encoded_chunk.begin() + VALIDITY_SIDECHAIN_BATCH_DATA_CHUNK_HEADER_BYTES,
        encoded_chunk.end());
    return true;
}

static uint256 HashWithOptionalSidechainId(
    const unsigned char* magic,
    size_t magic_len,
    Span<const unsigned char> bytes,
    const uint8_t* sidechain_id = nullptr)
{
    CHashWriter hw(SER_GETHASH, 0);
    hw.write((const char*)magic, magic_len);
    if (sidechain_id != nullptr) {
        hw << *sidechain_id;
    }
    hw.write((const char*)bytes.data(), bytes.size());
    return hw.GetHash();
}

static uint256 ComputeWithdrawalMerkleParent(const uint256& left, const uint256& right)
{
    CHashWriter hw(SER_GETHASH, 0);
    hw.write((const char*)WITHDRAWAL_NODE_HASH_MAGIC, sizeof(WITHDRAWAL_NODE_HASH_MAGIC));
    hw << left;
    hw << right;
    return hw.GetHash();
}

static uint256 FinalizeWithdrawalRoot(uint32_t leaf_count, const uint256& merkle_root)
{
    CHashWriter hw(SER_GETHASH, 0);
    hw.write((const char*)WITHDRAWAL_ROOT_MAGIC, sizeof(WITHDRAWAL_ROOT_MAGIC));
    hw << leaf_count;
    hw << merkle_root;
    return hw.GetHash();
}

static uint256 ComputeEscapeExitMerkleParent(const uint256& left, const uint256& right)
{
    CHashWriter hw(SER_GETHASH, 0);
    hw.write((const char*)ESCAPE_EXIT_NODE_HASH_MAGIC, sizeof(ESCAPE_EXIT_NODE_HASH_MAGIC));
    hw << left;
    hw << right;
    return hw.GetHash();
}

static uint256 FinalizeEscapeExitRoot(uint32_t leaf_count, const uint256& merkle_root)
{
    CHashWriter hw(SER_GETHASH, 0);
    hw.write((const char*)ESCAPE_EXIT_ROOT_MAGIC, sizeof(ESCAPE_EXIT_ROOT_MAGIC));
    hw << leaf_count;
    hw << merkle_root;
    return hw.GetHash();
}

static uint256 ComputeBalanceMerkleParent(const uint256& left, const uint256& right)
{
    CHashWriter hw(SER_GETHASH, 0);
    hw.write((const char*)BALANCE_NODE_HASH_MAGIC, sizeof(BALANCE_NODE_HASH_MAGIC));
    hw << left;
    hw << right;
    return hw.GetHash();
}

static uint256 ComputeAccountStateMerkleParent(const uint256& left, const uint256& right)
{
    CHashWriter hw(SER_GETHASH, 0);
    hw.write((const char*)ACCOUNT_STATE_NODE_HASH_MAGIC, sizeof(ACCOUNT_STATE_NODE_HASH_MAGIC));
    hw << left;
    hw << right;
    return hw.GetHash();
}

static bool BuildMerkleProof(
    std::vector<uint256> level_hashes,
    uint32_t leaf_index,
    uint256 (*parent_fn)(const uint256&, const uint256&),
    std::vector<uint256>& out_sibling_hashes)
{
    if (level_hashes.empty() || leaf_index >= level_hashes.size()) {
        return false;
    }

    out_sibling_hashes.clear();
    uint32_t index = leaf_index;
    while (level_hashes.size() > 1) {
        const size_t sibling_index = (index & 1U) != 0
            ? static_cast<size_t>(index - 1)
            : std::min(static_cast<size_t>(index + 1), level_hashes.size() - 1);
        out_sibling_hashes.push_back(level_hashes[sibling_index]);

        std::vector<uint256> next_level;
        next_level.reserve((level_hashes.size() + 1) / 2);
        for (size_t i = 0; i < level_hashes.size(); i += 2) {
            const uint256& left = level_hashes[i];
            const uint256& right = (i + 1 < level_hashes.size()) ? level_hashes[i + 1] : level_hashes[i];
            next_level.push_back(parent_fn(left, right));
        }

        index >>= 1;
        level_hashes = std::move(next_level);
    }

    return true;
}

static bool VerifyMerkleProof(
    uint32_t leaf_count,
    uint32_t leaf_index,
    const std::vector<uint256>& sibling_hashes,
    uint256 current_hash,
    uint256 (*parent_fn)(const uint256&, const uint256&),
    const uint256& expected_root)
{
    if (leaf_count == 0 || leaf_index >= leaf_count) {
        return false;
    }

    uint32_t width = leaf_count;
    size_t expected_sibling_count = 0;
    while (width > 1) {
        ++expected_sibling_count;
        width = (width + 1) / 2;
    }
    if (sibling_hashes.size() != expected_sibling_count) {
        return false;
    }

    width = leaf_count;
    uint32_t index = leaf_index;
    for (const auto& sibling_hash : sibling_hashes) {
        const bool is_right_child = (index & 1U) != 0;
        const bool has_distinct_sibling = is_right_child || (index + 1 < width);
        if (!has_distinct_sibling && sibling_hash != current_hash) {
            return false;
        }

        current_hash = is_right_child
            ? parent_fn(sibling_hash, current_hash)
            : parent_fn(current_hash, sibling_hash);
        index >>= 1;
        width = (width + 1) / 2;
    }

    return index == 0 && width == 1 && current_hash == expected_root;
}

static uint256 ComputeMerkleRoot(
    std::vector<uint256> level_hashes,
    uint256 (*parent_fn)(const uint256&, const uint256&))
{
    if (level_hashes.empty()) {
        return uint256();
    }

    while (level_hashes.size() > 1) {
        std::vector<uint256> next_level;
        next_level.reserve((level_hashes.size() + 1) / 2);
        for (size_t i = 0; i < level_hashes.size(); i += 2) {
            const uint256& left = level_hashes[i];
            const uint256& right = (i + 1 < level_hashes.size()) ? level_hashes[i + 1] : level_hashes[i];
            next_level.push_back(parent_fn(left, right));
        }
        level_hashes = std::move(next_level);
    }

    return level_hashes.front();
}

static ValiditySidechainScriptInfo::Kind DecodeTag(uint8_t tag)
{
    switch (tag) {
        case 0x06: return ValiditySidechainScriptInfo::Kind::REGISTER_VALIDITY_SIDECHAIN;
        case 0x07: return ValiditySidechainScriptInfo::Kind::DEPOSIT_TO_VALIDITY_SIDECHAIN;
        case 0x08: return ValiditySidechainScriptInfo::Kind::COMMIT_VALIDITY_BATCH;
        case 0x09: return ValiditySidechainScriptInfo::Kind::EXECUTE_VERIFIED_WITHDRAWALS;
        case 0x0A: return ValiditySidechainScriptInfo::Kind::REQUEST_FORCE_EXIT;
        case 0x0B: return ValiditySidechainScriptInfo::Kind::RECLAIM_STALE_DEPOSIT;
        case 0x0C: return ValiditySidechainScriptInfo::Kind::EXECUTE_ESCAPE_EXIT;
        default:   return ValiditySidechainScriptInfo::Kind::UNKNOWN;
    }
}

} // namespace

bool IsValiditySidechainTransport(const CScript& scriptPubKey)
{
    CScript::const_iterator pc = scriptPubKey.begin();
    opcodetype opcode;

    return scriptPubKey.GetOp(pc, opcode) &&
           opcode == OP_RETURN &&
           scriptPubKey.GetOp(pc, opcode) &&
           opcode == OP_SIDECHAIN;
}

bool DecodeValiditySidechainScript(const CScript& scriptPubKey, ValiditySidechainScriptInfo& out_info)
{
    // The validity-sidechain path uses dedicated sidechain transport.
    //
    // [0]: OP_RETURN
    // [1]: OP_SIDECHAIN
    // [2]: PUSHDATA(1)  -> sidechain_id
    // [3]: PUSHDATA(32) -> payload
    // [4]: PUSHDATA(1)  -> tag
    // [5..n]: optional pushed metadata items, depending on tag

    CScript::const_iterator pc = scriptPubKey.begin();
    opcodetype opcode;

    if (!scriptPubKey.GetOp(pc, opcode) || opcode != OP_RETURN) {
        return false;
    }
    if (!scriptPubKey.GetOp(pc, opcode) || opcode != OP_SIDECHAIN) {
        return false;
    }

    std::vector<unsigned char> vch;
    if (!scriptPubKey.GetOp(pc, opcode, vch) || vch.size() != 1) {
        return false;
    }
    const uint8_t sidechain_id = vch[0];

    if (!scriptPubKey.GetOp(pc, opcode, vch) || vch.size() != UINT256_BYTES) {
        return false;
    }
    uint256 payload;
    std::copy(vch.begin(), vch.end(), payload.begin());

    if (!scriptPubKey.GetOp(pc, opcode, vch) || vch.size() != 1) {
        return false;
    }

    ValiditySidechainScriptInfo info;
    info.kind = DecodeTag(vch[0]);
    info.sidechain_id = sidechain_id;
    info.payload = payload;

    if (info.kind == ValiditySidechainScriptInfo::Kind::UNKNOWN) {
        return false;
    }

    while (pc != scriptPubKey.end()) {
        if (!scriptPubKey.GetOp(pc, opcode, vch) || opcode > OP_PUSHDATA4) {
            return false;
        }
        info.metadata_pushes.push_back(vch);
    }

    if (!info.metadata_pushes.empty()) {
        info.primary_metadata = info.metadata_pushes.front();
    }

    switch (info.kind) {
        case ValiditySidechainScriptInfo::Kind::REGISTER_VALIDITY_SIDECHAIN:
        case ValiditySidechainScriptInfo::Kind::DEPOSIT_TO_VALIDITY_SIDECHAIN:
        case ValiditySidechainScriptInfo::Kind::RECLAIM_STALE_DEPOSIT:
        case ValiditySidechainScriptInfo::Kind::REQUEST_FORCE_EXIT:
            if (info.metadata_pushes.size() != 1) {
                return false;
            }
            break;
        case ValiditySidechainScriptInfo::Kind::EXECUTE_VERIFIED_WITHDRAWALS:
        case ValiditySidechainScriptInfo::Kind::EXECUTE_ESCAPE_EXIT:
            if (info.metadata_pushes.empty()) {
                return false;
            }
            break;
        case ValiditySidechainScriptInfo::Kind::COMMIT_VALIDITY_BATCH:
            if (info.metadata_pushes.size() < 2) {
                return false;
            }
            break;
        case ValiditySidechainScriptInfo::Kind::UNKNOWN:
            break;
    }

    out_info = info;
    return true;
}

CScript BuildValiditySidechainScript(
    ValiditySidechainScriptInfo::Kind kind,
    uint8_t scid,
    const uint256& payload,
    const std::vector<std::vector<unsigned char>>& metadata_pushes)
{
    const std::vector<unsigned char> sidechain_v{scid};
    const std::vector<unsigned char> payload_v(payload.begin(), payload.end());
    const std::vector<unsigned char> tag_v{static_cast<uint8_t>(kind)};

    CScript script;
    script << OP_RETURN << OP_SIDECHAIN << sidechain_v << payload_v << tag_v;
    for (const auto& push : metadata_pushes) {
        script << push;
    }
    return script;
}

CScript BuildValiditySidechainRegisterScript(uint8_t scid, const ValiditySidechainConfig& config)
{
    const std::vector<unsigned char> encoded_config = EncodeValiditySidechainConfig(config);
    const uint256 payload = ComputeValiditySidechainConfigHash(config);
    return BuildValiditySidechainScript(
        ValiditySidechainScriptInfo::Kind::REGISTER_VALIDITY_SIDECHAIN,
        scid,
        payload,
        {encoded_config});
}

CScript BuildValiditySidechainDepositScript(uint8_t scid, const ValiditySidechainDepositData& deposit)
{
    const std::vector<unsigned char> encoded_deposit = EncodeValiditySidechainDepositData(deposit);
    const uint256 payload = ComputeValiditySidechainDepositMessageHash(scid, deposit);
    return BuildValiditySidechainScript(
        ValiditySidechainScriptInfo::Kind::DEPOSIT_TO_VALIDITY_SIDECHAIN,
        scid,
        payload,
        {encoded_deposit});
}

CScript BuildValiditySidechainCommitScript(
    uint8_t scid,
    const ValiditySidechainBatchPublicInputs& public_inputs,
    const std::vector<unsigned char>& proof_bytes,
    const std::vector<std::vector<unsigned char>>& data_chunks)
{
    std::vector<std::vector<unsigned char>> metadata_pushes;
    metadata_pushes.reserve(2 + data_chunks.size());
    metadata_pushes.push_back(EncodeValiditySidechainBatchPublicInputs(public_inputs));
    metadata_pushes.push_back(proof_bytes);
    const uint32_t chunk_count = static_cast<uint32_t>(data_chunks.size());
    for (uint32_t i = 0; i < chunk_count; ++i) {
        metadata_pushes.push_back(EncodeValiditySidechainBatchDataChunk(
            i,
            chunk_count,
            data_chunks[i]));
    }

    const uint256 payload = ComputeValiditySidechainBatchCommitmentHash(scid, public_inputs);
    return BuildValiditySidechainScript(
        ValiditySidechainScriptInfo::Kind::COMMIT_VALIDITY_BATCH,
        scid,
        payload,
        metadata_pushes);
}

CScript BuildValiditySidechainExecuteScript(
    uint8_t scid,
    uint32_t batch_number,
    const uint256& withdrawal_root,
    const std::vector<ValiditySidechainWithdrawalProof>& withdrawal_proofs)
{
    std::vector<std::vector<unsigned char>> metadata_pushes;
    metadata_pushes.reserve(withdrawal_proofs.size());
    for (const auto& proof : withdrawal_proofs) {
        metadata_pushes.push_back(EncodeValiditySidechainWithdrawalProof(proof));
    }

    return BuildValiditySidechainScript(
        ValiditySidechainScriptInfo::Kind::EXECUTE_VERIFIED_WITHDRAWALS,
        scid,
        ComputeValiditySidechainAcceptedBatchId(scid, batch_number, withdrawal_root),
        metadata_pushes);
}

CScript BuildValiditySidechainForceExitScript(uint8_t scid, const ValiditySidechainForceExitData& request)
{
    const std::vector<unsigned char> encoded_request = EncodeValiditySidechainForceExitData(request);
    return BuildValiditySidechainScript(
        ValiditySidechainScriptInfo::Kind::REQUEST_FORCE_EXIT,
        scid,
        ComputeValiditySidechainForceExitHash(scid, request),
        {encoded_request});
}

CScript BuildValiditySidechainReclaimDepositScript(uint8_t scid, const ValiditySidechainDepositData& deposit)
{
    const std::vector<unsigned char> encoded_deposit = EncodeValiditySidechainDepositData(deposit);
    return BuildValiditySidechainScript(
        ValiditySidechainScriptInfo::Kind::RECLAIM_STALE_DEPOSIT,
        scid,
        deposit.deposit_id,
        {encoded_deposit});
}

CScript BuildValiditySidechainEscapeExitScript(
    uint8_t scid,
    const uint256& state_root_reference,
    const std::vector<ValiditySidechainEscapeExitProof>& exit_proofs)
{
    std::vector<std::vector<unsigned char>> metadata_pushes;
    metadata_pushes.reserve(exit_proofs.size());
    for (const auto& proof : exit_proofs) {
        metadata_pushes.push_back(EncodeValiditySidechainEscapeExitProof(proof));
    }

    return BuildValiditySidechainScript(
        ValiditySidechainScriptInfo::Kind::EXECUTE_ESCAPE_EXIT,
        scid,
        state_root_reference,
        metadata_pushes);
}

CScript BuildValiditySidechainEscapeExitStateScript(
    uint8_t scid,
    const uint256& state_root_reference,
    const std::vector<ValiditySidechainEscapeExitStateProof>& exit_state_proofs)
{
    std::vector<std::vector<unsigned char>> metadata_pushes;
    metadata_pushes.reserve(exit_state_proofs.size());
    for (const auto& proof : exit_state_proofs) {
        metadata_pushes.push_back(EncodeValiditySidechainEscapeExitStateProof(proof));
    }

    return BuildValiditySidechainScript(
        ValiditySidechainScriptInfo::Kind::EXECUTE_ESCAPE_EXIT,
        scid,
        state_root_reference,
        metadata_pushes);
}

std::vector<unsigned char> EncodeValiditySidechainConfig(const ValiditySidechainConfig& config)
{
    std::vector<unsigned char> out;
    out.reserve(VALIDITY_SIDECHAIN_CONFIG_BYTES);

    out.push_back(config.version);
    out.push_back(config.proof_system_id);
    out.push_back(config.circuit_family_id);
    out.push_back(config.verifier_id);
    out.push_back(config.public_input_version);
    out.push_back(config.state_root_format);
    out.push_back(config.deposit_message_format);
    out.push_back(config.withdrawal_leaf_format);
    out.push_back(config.balance_leaf_format);
    out.push_back(config.data_availability_mode);
    AppendLE32(out, config.max_batch_data_bytes);
    AppendLE32(out, config.max_proof_bytes);
    AppendLE32(out, config.force_inclusion_delay);
    AppendLE32(out, config.deposit_reclaim_delay);
    AppendLE32(out, config.escape_hatch_delay);
    AppendUint256(out, config.initial_state_root);
    AppendUint256(out, config.initial_withdrawal_root);

    return out;
}

bool DecodeValiditySidechainConfig(Span<const unsigned char> config_bytes, ValiditySidechainConfig& out_config)
{
    if (config_bytes.size() != VALIDITY_SIDECHAIN_CONFIG_BYTES) {
        return false;
    }

    ValiditySidechainConfig config;
    config.version = config_bytes[0];
    config.proof_system_id = config_bytes[1];
    config.circuit_family_id = config_bytes[2];
    config.verifier_id = config_bytes[3];
    config.public_input_version = config_bytes[4];
    config.state_root_format = config_bytes[5];
    config.deposit_message_format = config_bytes[6];
    config.withdrawal_leaf_format = config_bytes[7];
    config.balance_leaf_format = config_bytes[8];
    config.data_availability_mode = config_bytes[9];
    config.max_batch_data_bytes = ReadLE32(config_bytes.data() + 10);
    config.max_proof_bytes = ReadLE32(config_bytes.data() + 14);
    config.force_inclusion_delay = ReadLE32(config_bytes.data() + 18);
    config.deposit_reclaim_delay = ReadLE32(config_bytes.data() + 22);
    config.escape_hatch_delay = ReadLE32(config_bytes.data() + 26);

    if (!ReadUint256At(config_bytes, 30, config.initial_state_root) ||
        !ReadUint256At(config_bytes, 62, config.initial_withdrawal_root)) {
        return false;
    }

    if (config.version == 0 ||
        config.max_batch_data_bytes == 0 ||
        config.max_proof_bytes == 0 ||
        config.force_inclusion_delay == 0 ||
        config.deposit_reclaim_delay == 0 ||
        config.escape_hatch_delay == 0) {
        return false;
    }

    out_config = config;
    return true;
}

uint256 ComputeValiditySidechainConfigHash(const ValiditySidechainConfig& config)
{
    const std::vector<unsigned char> encoded_config = EncodeValiditySidechainConfig(config);
    return HashWithOptionalSidechainId(CONFIG_HASH_MAGIC, sizeof(CONFIG_HASH_MAGIC), encoded_config);
}

std::vector<unsigned char> EncodeValiditySidechainDepositData(const ValiditySidechainDepositData& deposit)
{
    std::vector<unsigned char> out;
    out.reserve(VALIDITY_SIDECHAIN_DEPOSIT_BYTES);

    AppendUint256(out, deposit.deposit_id);
    AppendLE64(out, static_cast<uint64_t>(deposit.amount));
    AppendUint256(out, deposit.destination_commitment);
    AppendUint256(out, deposit.refund_script_commitment);
    AppendLE64(out, deposit.nonce);

    return out;
}

bool DecodeValiditySidechainDepositData(Span<const unsigned char> deposit_bytes, ValiditySidechainDepositData& out_deposit)
{
    if (deposit_bytes.size() != VALIDITY_SIDECHAIN_DEPOSIT_BYTES) {
        return false;
    }

    ValiditySidechainDepositData deposit;
    if (!ReadUint256At(deposit_bytes, 0, deposit.deposit_id) ||
        !ReadAmount64(deposit_bytes, 32, deposit.amount) ||
        !ReadUint256At(deposit_bytes, 40, deposit.destination_commitment) ||
        !ReadUint256At(deposit_bytes, 72, deposit.refund_script_commitment)) {
        return false;
    }

    deposit.nonce = ReadLE64(deposit_bytes.data() + 104);
    out_deposit = deposit;
    return true;
}

uint256 ComputeValiditySidechainDepositMessageHash(uint8_t scid, const ValiditySidechainDepositData& deposit)
{
    const std::vector<unsigned char> encoded_deposit = EncodeValiditySidechainDepositData(deposit);
    return HashWithOptionalSidechainId(DEPOSIT_HASH_MAGIC, sizeof(DEPOSIT_HASH_MAGIC), encoded_deposit, &scid);
}

std::vector<unsigned char> EncodeValiditySidechainBatchPublicInputs(const ValiditySidechainBatchPublicInputs& public_inputs)
{
    std::vector<unsigned char> out;
    out.reserve(VALIDITY_SIDECHAIN_BATCH_PUBLIC_INPUT_BYTES);

    AppendLE32(out, public_inputs.batch_number);
    AppendUint256(out, public_inputs.prior_state_root);
    AppendUint256(out, public_inputs.new_state_root);
    AppendUint256(out, public_inputs.l1_message_root_before);
    AppendUint256(out, public_inputs.l1_message_root_after);
    AppendLE32(out, public_inputs.consumed_queue_messages);
    AppendUint256(out, public_inputs.queue_prefix_commitment);
    AppendUint256(out, public_inputs.withdrawal_root);
    AppendUint256(out, public_inputs.data_root);
    AppendLE32(out, public_inputs.data_size);

    return out;
}

bool DecodeValiditySidechainBatchPublicInputs(
    Span<const unsigned char> public_input_bytes,
    ValiditySidechainBatchPublicInputs& out_public_inputs)
{
    if (public_input_bytes.size() != VALIDITY_SIDECHAIN_BATCH_PUBLIC_INPUT_BYTES) {
        return false;
    }

    ValiditySidechainBatchPublicInputs public_inputs;
    public_inputs.batch_number = ReadLE32(public_input_bytes.data());
    if (!ReadUint256At(public_input_bytes, 4, public_inputs.prior_state_root) ||
        !ReadUint256At(public_input_bytes, 36, public_inputs.new_state_root) ||
        !ReadUint256At(public_input_bytes, 68, public_inputs.l1_message_root_before) ||
        !ReadUint256At(public_input_bytes, 100, public_inputs.l1_message_root_after) ||
        !ReadUint256At(public_input_bytes, 136, public_inputs.queue_prefix_commitment) ||
        !ReadUint256At(public_input_bytes, 168, public_inputs.withdrawal_root) ||
        !ReadUint256At(public_input_bytes, 200, public_inputs.data_root)) {
        return false;
    }

    public_inputs.consumed_queue_messages = ReadLE32(public_input_bytes.data() + 132);
    public_inputs.data_size = ReadLE32(public_input_bytes.data() + 232);
    out_public_inputs = public_inputs;
    return true;
}

bool DecodeValiditySidechainCommitMetadata(
    const ValiditySidechainScriptInfo& info,
    ValiditySidechainBatchPublicInputs& out_public_inputs,
    std::vector<unsigned char>& out_proof_bytes,
    std::vector<std::vector<unsigned char>>& out_data_chunks)
{
    if (info.kind != ValiditySidechainScriptInfo::Kind::COMMIT_VALIDITY_BATCH ||
        info.metadata_pushes.size() < 2) {
        return false;
    }
    if (!DecodeValiditySidechainBatchPublicInputs(info.metadata_pushes.front(), out_public_inputs)) {
        return false;
    }

    out_proof_bytes = info.metadata_pushes[1];
    out_data_chunks.clear();
    const size_t encoded_chunk_count = info.metadata_pushes.size() - 2;
    if (encoded_chunk_count > std::numeric_limits<uint32_t>::max()) {
        return false;
    }

    const uint32_t chunk_count = static_cast<uint32_t>(encoded_chunk_count);
    if (chunk_count > MAX_VALIDITY_SIDECHAIN_BATCH_DATA_CHUNKS) {
        return false;
    }
    out_data_chunks.reserve(encoded_chunk_count);
    for (uint32_t i = 0; i < chunk_count; ++i) {
        std::vector<unsigned char> chunk_bytes;
        if (!DecodeValiditySidechainBatchDataChunk(
                info.metadata_pushes[i + 2],
                i,
                chunk_count,
                chunk_bytes)) {
            return false;
        }
        out_data_chunks.push_back(std::move(chunk_bytes));
    }
    return true;
}

uint256 ComputeValiditySidechainBatchCommitmentHash(uint8_t scid, const ValiditySidechainBatchPublicInputs& public_inputs)
{
    const std::vector<unsigned char> encoded_public_inputs = EncodeValiditySidechainBatchPublicInputs(public_inputs);
    return HashWithOptionalSidechainId(BATCH_HASH_MAGIC, sizeof(BATCH_HASH_MAGIC), encoded_public_inputs, &scid);
}

std::vector<unsigned char> EncodeValiditySidechainWithdrawalLeaf(const ValiditySidechainWithdrawalLeaf& withdrawal)
{
    std::vector<unsigned char> out;
    out.reserve(VALIDITY_SIDECHAIN_WITHDRAWAL_LEAF_BYTES);

    AppendUint256(out, withdrawal.withdrawal_id);
    AppendLE64(out, static_cast<uint64_t>(withdrawal.amount));
    AppendUint256(out, withdrawal.destination_commitment);

    return out;
}

bool DecodeValiditySidechainWithdrawalLeaf(
    Span<const unsigned char> withdrawal_bytes,
    ValiditySidechainWithdrawalLeaf& out_withdrawal)
{
    if (withdrawal_bytes.size() != VALIDITY_SIDECHAIN_WITHDRAWAL_LEAF_BYTES) {
        return false;
    }

    ValiditySidechainWithdrawalLeaf withdrawal;
    if (!ReadUint256At(withdrawal_bytes, 0, withdrawal.withdrawal_id) ||
        !ReadAmount64(withdrawal_bytes, 32, withdrawal.amount) ||
        !ReadUint256At(withdrawal_bytes, 40, withdrawal.destination_commitment)) {
        return false;
    }

    out_withdrawal = withdrawal;
    return true;
}

std::vector<unsigned char> EncodeValiditySidechainWithdrawalProof(const ValiditySidechainWithdrawalProof& proof)
{
    std::vector<unsigned char> out;
    out.reserve(VALIDITY_SIDECHAIN_WITHDRAWAL_PROOF_BASE_BYTES + (proof.sibling_hashes.size() * UINT256_BYTES));

    AppendLE32(out, proof.leaf_index);
    AppendLE32(out, proof.leaf_count);
    const std::vector<unsigned char> encoded_leaf = EncodeValiditySidechainWithdrawalLeaf(proof.withdrawal);
    out.insert(out.end(), encoded_leaf.begin(), encoded_leaf.end());
    for (const auto& sibling_hash : proof.sibling_hashes) {
        AppendUint256(out, sibling_hash);
    }

    return out;
}

bool DecodeValiditySidechainWithdrawalProof(
    Span<const unsigned char> proof_bytes,
    ValiditySidechainWithdrawalProof& out_proof)
{
    if (proof_bytes.size() < VALIDITY_SIDECHAIN_WITHDRAWAL_PROOF_BASE_BYTES ||
        ((proof_bytes.size() - VALIDITY_SIDECHAIN_WITHDRAWAL_PROOF_BASE_BYTES) % UINT256_BYTES) != 0) {
        return false;
    }

    ValiditySidechainWithdrawalProof proof;
    proof.leaf_index = ReadLE32(proof_bytes.data());
    proof.leaf_count = ReadLE32(proof_bytes.data() + sizeof(uint32_t));
    if (proof.leaf_count == 0 || proof.leaf_index >= proof.leaf_count) {
        return false;
    }
    if (!DecodeValiditySidechainWithdrawalLeaf(
            proof_bytes.subspan(sizeof(uint32_t) * 2, VALIDITY_SIDECHAIN_WITHDRAWAL_LEAF_BYTES),
            proof.withdrawal)) {
        return false;
    }

    const size_t sibling_count = (proof_bytes.size() - VALIDITY_SIDECHAIN_WITHDRAWAL_PROOF_BASE_BYTES) / UINT256_BYTES;
    if (sibling_count > MAX_VALIDITY_SIDECHAIN_MERKLE_PROOF_DEPTH) {
        return false;
    }
    proof.sibling_hashes.reserve(sibling_count);
    size_t offset = VALIDITY_SIDECHAIN_WITHDRAWAL_PROOF_BASE_BYTES;
    for (size_t i = 0; i < sibling_count; ++i) {
        uint256 sibling_hash;
        if (!ReadUint256At(proof_bytes, offset, sibling_hash)) {
            return false;
        }
        proof.sibling_hashes.push_back(sibling_hash);
        offset += UINT256_BYTES;
    }

    out_proof = std::move(proof);
    return true;
}

bool DecodeValiditySidechainExecuteMetadata(
    const ValiditySidechainScriptInfo& info,
    std::vector<ValiditySidechainWithdrawalProof>& out_withdrawal_proofs)
{
    if (info.kind != ValiditySidechainScriptInfo::Kind::EXECUTE_VERIFIED_WITHDRAWALS ||
        info.metadata_pushes.empty()) {
        return false;
    }
    if (info.metadata_pushes.size() > MAX_VALIDITY_SIDECHAIN_EXECUTION_FANOUT) {
        return false;
    }

    std::vector<ValiditySidechainWithdrawalProof> withdrawal_proofs;
    withdrawal_proofs.reserve(info.metadata_pushes.size());
    for (const auto& push : info.metadata_pushes) {
        ValiditySidechainWithdrawalProof proof;
        if (!DecodeValiditySidechainWithdrawalProof(push, proof)) {
            return false;
        }
        withdrawal_proofs.push_back(std::move(proof));
    }

    out_withdrawal_proofs = std::move(withdrawal_proofs);
    return true;
}

bool BuildValiditySidechainWithdrawalProof(
    const std::vector<ValiditySidechainWithdrawalLeaf>& withdrawals,
    uint32_t leaf_index,
    ValiditySidechainWithdrawalProof& out_proof)
{
    if (withdrawals.empty() || leaf_index >= withdrawals.size()) {
        return false;
    }

    std::vector<uint256> level_hashes;
    level_hashes.reserve(withdrawals.size());
    for (const auto& withdrawal : withdrawals) {
        const std::vector<unsigned char> encoded_leaf = EncodeValiditySidechainWithdrawalLeaf(withdrawal);
        level_hashes.push_back(HashWithOptionalSidechainId(
            WITHDRAWAL_LEAF_HASH_MAGIC,
            sizeof(WITHDRAWAL_LEAF_HASH_MAGIC),
            encoded_leaf));
    }

    ValiditySidechainWithdrawalProof proof;
    proof.withdrawal = withdrawals[leaf_index];
    proof.leaf_index = leaf_index;
    proof.leaf_count = static_cast<uint32_t>(withdrawals.size());

    uint32_t index = leaf_index;
    while (level_hashes.size() > 1) {
        const size_t sibling_index = (index & 1U) != 0 ? static_cast<size_t>(index - 1) : std::min(static_cast<size_t>(index + 1), level_hashes.size() - 1);
        proof.sibling_hashes.push_back(level_hashes[sibling_index]);

        std::vector<uint256> next_level;
        next_level.reserve((level_hashes.size() + 1) / 2);
        for (size_t i = 0; i < level_hashes.size(); i += 2) {
            const uint256& left = level_hashes[i];
            const uint256& right = (i + 1 < level_hashes.size()) ? level_hashes[i + 1] : level_hashes[i];
            next_level.push_back(ComputeWithdrawalMerkleParent(left, right));
        }

        index >>= 1;
        level_hashes = std::move(next_level);
    }

    out_proof = std::move(proof);
    return true;
}

bool VerifyValiditySidechainWithdrawalProof(
    const ValiditySidechainWithdrawalProof& proof,
    const uint256& expected_root)
{
    if (proof.leaf_count == 0 || proof.leaf_index >= proof.leaf_count) {
        return false;
    }

    const std::vector<unsigned char> encoded_leaf = EncodeValiditySidechainWithdrawalLeaf(proof.withdrawal);
    uint256 current_hash = HashWithOptionalSidechainId(
        WITHDRAWAL_LEAF_HASH_MAGIC,
        sizeof(WITHDRAWAL_LEAF_HASH_MAGIC),
        encoded_leaf);

    uint32_t width = proof.leaf_count;
    uint32_t index = proof.leaf_index;
    size_t expected_sibling_count = 0;
    while (width > 1) {
        ++expected_sibling_count;
        width = (width + 1) / 2;
    }
    if (proof.sibling_hashes.size() != expected_sibling_count) {
        return false;
    }

    width = proof.leaf_count;
    index = proof.leaf_index;
    for (const auto& sibling_hash : proof.sibling_hashes) {
        const bool is_right_child = (index & 1U) != 0;
        const bool has_distinct_sibling = is_right_child || (index + 1 < width);
        if (!has_distinct_sibling && sibling_hash != current_hash) {
            return false;
        }

        current_hash = is_right_child
            ? ComputeWithdrawalMerkleParent(sibling_hash, current_hash)
            : ComputeWithdrawalMerkleParent(current_hash, sibling_hash);
        index >>= 1;
        width = (width + 1) / 2;
    }

    return index == 0 && width == 1 && FinalizeWithdrawalRoot(proof.leaf_count, current_hash) == expected_root;
}

bool ValidateValiditySidechainWithdrawalLeafIds(
    const std::vector<ValiditySidechainWithdrawalLeaf>& withdrawals,
    std::string* error)
{
    std::set<uint256> withdrawal_ids;
    for (const auto& withdrawal : withdrawals) {
        if (!withdrawal_ids.insert(withdrawal.withdrawal_id).second) {
            if (error != nullptr) {
                *error = "duplicate withdrawal_id in withdrawal witness set";
            }
            return false;
        }
    }
    if (error != nullptr) {
        error->clear();
    }
    return true;
}

uint256 ComputeValiditySidechainWithdrawalRoot(const std::vector<ValiditySidechainWithdrawalLeaf>& withdrawals)
{
    if (withdrawals.empty()) {
        return FinalizeWithdrawalRoot(/* leaf_count= */ 0, uint256());
    }

    std::vector<uint256> level_hashes;
    level_hashes.reserve(withdrawals.size());
    for (const auto& withdrawal : withdrawals) {
        const std::vector<unsigned char> encoded_leaf = EncodeValiditySidechainWithdrawalLeaf(withdrawal);
        level_hashes.push_back(HashWithOptionalSidechainId(
            WITHDRAWAL_LEAF_HASH_MAGIC,
            sizeof(WITHDRAWAL_LEAF_HASH_MAGIC),
            encoded_leaf));
    }

    while (level_hashes.size() > 1) {
        std::vector<uint256> next_level;
        next_level.reserve((level_hashes.size() + 1) / 2);
        for (size_t i = 0; i < level_hashes.size(); i += 2) {
            const uint256& left = level_hashes[i];
            const uint256& right = (i + 1 < level_hashes.size()) ? level_hashes[i + 1] : level_hashes[i];
            next_level.push_back(ComputeWithdrawalMerkleParent(left, right));
        }
        level_hashes = std::move(next_level);
    }

    return FinalizeWithdrawalRoot(static_cast<uint32_t>(withdrawals.size()), level_hashes.front());
}

std::vector<unsigned char> EncodeValiditySidechainBalanceLeaf(const ValiditySidechainBalanceLeaf& balance)
{
    std::vector<unsigned char> out;
    out.reserve(VALIDITY_SIDECHAIN_BALANCE_LEAF_BYTES);

    AppendUint256(out, balance.asset_id);
    AppendLE64(out, static_cast<uint64_t>(balance.balance));

    return out;
}

bool DecodeValiditySidechainBalanceLeaf(
    Span<const unsigned char> balance_bytes,
    ValiditySidechainBalanceLeaf& out_balance)
{
    if (balance_bytes.size() != VALIDITY_SIDECHAIN_BALANCE_LEAF_BYTES) {
        return false;
    }

    ValiditySidechainBalanceLeaf balance;
    if (!ReadUint256At(balance_bytes, 0, balance.asset_id) ||
        !ReadAmount64AllowZero(balance_bytes, 32, balance.balance)) {
        return false;
    }

    out_balance = balance;
    return true;
}

std::vector<unsigned char> EncodeValiditySidechainBalanceProof(const ValiditySidechainBalanceProof& proof)
{
    std::vector<unsigned char> out;
    out.reserve(VALIDITY_SIDECHAIN_BALANCE_PROOF_BASE_BYTES + (proof.sibling_hashes.size() * UINT256_BYTES));

    AppendLE32(out, proof.leaf_index);
    AppendLE32(out, proof.leaf_count);
    const std::vector<unsigned char> encoded_leaf = EncodeValiditySidechainBalanceLeaf(proof.balance);
    out.insert(out.end(), encoded_leaf.begin(), encoded_leaf.end());
    for (const auto& sibling_hash : proof.sibling_hashes) {
        AppendUint256(out, sibling_hash);
    }

    return out;
}

bool DecodeValiditySidechainBalanceProof(
    Span<const unsigned char> proof_bytes,
    ValiditySidechainBalanceProof& out_proof)
{
    if (proof_bytes.size() < VALIDITY_SIDECHAIN_BALANCE_PROOF_BASE_BYTES ||
        ((proof_bytes.size() - VALIDITY_SIDECHAIN_BALANCE_PROOF_BASE_BYTES) % UINT256_BYTES) != 0) {
        return false;
    }

    ValiditySidechainBalanceProof proof;
    proof.leaf_index = ReadLE32(proof_bytes.data());
    proof.leaf_count = ReadLE32(proof_bytes.data() + sizeof(uint32_t));
    if (proof.leaf_count == 0 || proof.leaf_index >= proof.leaf_count) {
        return false;
    }
    if (!DecodeValiditySidechainBalanceLeaf(
            proof_bytes.subspan(sizeof(uint32_t) * 2, VALIDITY_SIDECHAIN_BALANCE_LEAF_BYTES),
            proof.balance)) {
        return false;
    }

    const size_t sibling_count = (proof_bytes.size() - VALIDITY_SIDECHAIN_BALANCE_PROOF_BASE_BYTES) / UINT256_BYTES;
    if (sibling_count > MAX_VALIDITY_SIDECHAIN_MERKLE_PROOF_DEPTH) {
        return false;
    }
    proof.sibling_hashes.reserve(sibling_count);
    size_t offset = VALIDITY_SIDECHAIN_BALANCE_PROOF_BASE_BYTES;
    for (size_t i = 0; i < sibling_count; ++i) {
        uint256 sibling_hash;
        if (!ReadUint256At(proof_bytes, offset, sibling_hash)) {
            return false;
        }
        proof.sibling_hashes.push_back(sibling_hash);
        offset += UINT256_BYTES;
    }

    out_proof = std::move(proof);
    return true;
}

bool BuildValiditySidechainBalanceProof(
    const std::vector<ValiditySidechainBalanceLeaf>& balances,
    uint32_t leaf_index,
    ValiditySidechainBalanceProof& out_proof)
{
    if (balances.empty() || leaf_index >= balances.size()) {
        return false;
    }

    std::vector<uint256> level_hashes;
    level_hashes.reserve(balances.size());
    for (const auto& balance : balances) {
        const std::vector<unsigned char> encoded_leaf = EncodeValiditySidechainBalanceLeaf(balance);
        level_hashes.push_back(HashWithOptionalSidechainId(
            BALANCE_LEAF_HASH_MAGIC,
            sizeof(BALANCE_LEAF_HASH_MAGIC),
            encoded_leaf));
    }

    ValiditySidechainBalanceProof proof;
    proof.balance = balances[leaf_index];
    proof.leaf_index = leaf_index;
    proof.leaf_count = static_cast<uint32_t>(balances.size());
    if (!BuildMerkleProof(std::move(level_hashes), leaf_index, ComputeBalanceMerkleParent, proof.sibling_hashes)) {
        return false;
    }

    out_proof = std::move(proof);
    return true;
}

bool VerifyValiditySidechainBalanceProof(
    const ValiditySidechainBalanceProof& proof,
    const uint256& expected_root)
{
    const std::vector<unsigned char> encoded_leaf = EncodeValiditySidechainBalanceLeaf(proof.balance);
    const uint256 leaf_hash = HashWithOptionalSidechainId(
        BALANCE_LEAF_HASH_MAGIC,
        sizeof(BALANCE_LEAF_HASH_MAGIC),
        encoded_leaf);
    return VerifyMerkleProof(
        proof.leaf_count,
        proof.leaf_index,
        proof.sibling_hashes,
        leaf_hash,
        ComputeBalanceMerkleParent,
        expected_root);
}

uint256 ComputeValiditySidechainBalanceRoot(const std::vector<ValiditySidechainBalanceLeaf>& balances)
{
    std::vector<uint256> level_hashes;
    level_hashes.reserve(balances.size());
    for (const auto& balance : balances) {
        const std::vector<unsigned char> encoded_leaf = EncodeValiditySidechainBalanceLeaf(balance);
        level_hashes.push_back(HashWithOptionalSidechainId(
            BALANCE_LEAF_HASH_MAGIC,
            sizeof(BALANCE_LEAF_HASH_MAGIC),
            encoded_leaf));
    }
    return ComputeMerkleRoot(std::move(level_hashes), ComputeBalanceMerkleParent);
}

std::vector<unsigned char> EncodeValiditySidechainAccountStateLeaf(const ValiditySidechainAccountStateLeaf& account)
{
    std::vector<unsigned char> out;
    out.reserve(VALIDITY_SIDECHAIN_ACCOUNT_STATE_LEAF_BYTES);

    AppendUint256(out, account.account_id);
    AppendUint256(out, account.spend_key_commitment);
    AppendUint256(out, account.balance_root);
    AppendLE64(out, account.account_nonce);
    AppendLE64(out, account.last_forced_exit_nonce);

    return out;
}

bool DecodeValiditySidechainAccountStateLeaf(
    Span<const unsigned char> account_bytes,
    ValiditySidechainAccountStateLeaf& out_account)
{
    if (account_bytes.size() != VALIDITY_SIDECHAIN_ACCOUNT_STATE_LEAF_BYTES) {
        return false;
    }

    ValiditySidechainAccountStateLeaf account;
    if (!ReadUint256At(account_bytes, 0, account.account_id) ||
        !ReadUint256At(account_bytes, 32, account.spend_key_commitment) ||
        !ReadUint256At(account_bytes, 64, account.balance_root)) {
        return false;
    }
    account.account_nonce = ReadLE64(account_bytes.data() + 96);
    account.last_forced_exit_nonce = ReadLE64(account_bytes.data() + 104);

    out_account = account;
    return true;
}

std::vector<unsigned char> EncodeValiditySidechainAccountStateProof(const ValiditySidechainAccountStateProof& proof)
{
    std::vector<unsigned char> out;
    out.reserve(VALIDITY_SIDECHAIN_ACCOUNT_STATE_PROOF_BASE_BYTES + (proof.sibling_hashes.size() * UINT256_BYTES));

    AppendLE32(out, proof.leaf_index);
    AppendLE32(out, proof.leaf_count);
    const std::vector<unsigned char> encoded_leaf = EncodeValiditySidechainAccountStateLeaf(proof.account);
    out.insert(out.end(), encoded_leaf.begin(), encoded_leaf.end());
    for (const auto& sibling_hash : proof.sibling_hashes) {
        AppendUint256(out, sibling_hash);
    }

    return out;
}

bool DecodeValiditySidechainAccountStateProof(
    Span<const unsigned char> proof_bytes,
    ValiditySidechainAccountStateProof& out_proof)
{
    if (proof_bytes.size() < VALIDITY_SIDECHAIN_ACCOUNT_STATE_PROOF_BASE_BYTES ||
        ((proof_bytes.size() - VALIDITY_SIDECHAIN_ACCOUNT_STATE_PROOF_BASE_BYTES) % UINT256_BYTES) != 0) {
        return false;
    }

    ValiditySidechainAccountStateProof proof;
    proof.leaf_index = ReadLE32(proof_bytes.data());
    proof.leaf_count = ReadLE32(proof_bytes.data() + sizeof(uint32_t));
    if (proof.leaf_count == 0 || proof.leaf_index >= proof.leaf_count) {
        return false;
    }
    if (!DecodeValiditySidechainAccountStateLeaf(
            proof_bytes.subspan(sizeof(uint32_t) * 2, VALIDITY_SIDECHAIN_ACCOUNT_STATE_LEAF_BYTES),
            proof.account)) {
        return false;
    }

    const size_t sibling_count = (proof_bytes.size() - VALIDITY_SIDECHAIN_ACCOUNT_STATE_PROOF_BASE_BYTES) / UINT256_BYTES;
    if (sibling_count > MAX_VALIDITY_SIDECHAIN_MERKLE_PROOF_DEPTH) {
        return false;
    }
    proof.sibling_hashes.reserve(sibling_count);
    size_t offset = VALIDITY_SIDECHAIN_ACCOUNT_STATE_PROOF_BASE_BYTES;
    for (size_t i = 0; i < sibling_count; ++i) {
        uint256 sibling_hash;
        if (!ReadUint256At(proof_bytes, offset, sibling_hash)) {
            return false;
        }
        proof.sibling_hashes.push_back(sibling_hash);
        offset += UINT256_BYTES;
    }

    out_proof = std::move(proof);
    return true;
}

bool BuildValiditySidechainAccountStateProof(
    const std::vector<ValiditySidechainAccountStateLeaf>& accounts,
    uint32_t leaf_index,
    ValiditySidechainAccountStateProof& out_proof)
{
    if (accounts.empty() || leaf_index >= accounts.size()) {
        return false;
    }

    std::vector<uint256> level_hashes;
    level_hashes.reserve(accounts.size());
    for (const auto& account : accounts) {
        const std::vector<unsigned char> encoded_leaf = EncodeValiditySidechainAccountStateLeaf(account);
        level_hashes.push_back(HashWithOptionalSidechainId(
            ACCOUNT_STATE_LEAF_HASH_MAGIC,
            sizeof(ACCOUNT_STATE_LEAF_HASH_MAGIC),
            encoded_leaf));
    }

    ValiditySidechainAccountStateProof proof;
    proof.account = accounts[leaf_index];
    proof.leaf_index = leaf_index;
    proof.leaf_count = static_cast<uint32_t>(accounts.size());
    if (!BuildMerkleProof(std::move(level_hashes), leaf_index, ComputeAccountStateMerkleParent, proof.sibling_hashes)) {
        return false;
    }

    out_proof = std::move(proof);
    return true;
}

bool VerifyValiditySidechainAccountStateProof(
    const ValiditySidechainAccountStateProof& proof,
    const uint256& expected_root)
{
    const std::vector<unsigned char> encoded_leaf = EncodeValiditySidechainAccountStateLeaf(proof.account);
    const uint256 leaf_hash = HashWithOptionalSidechainId(
        ACCOUNT_STATE_LEAF_HASH_MAGIC,
        sizeof(ACCOUNT_STATE_LEAF_HASH_MAGIC),
        encoded_leaf);
    return VerifyMerkleProof(
        proof.leaf_count,
        proof.leaf_index,
        proof.sibling_hashes,
        leaf_hash,
        ComputeAccountStateMerkleParent,
        expected_root);
}

uint256 ComputeValiditySidechainAccountStateRoot(const std::vector<ValiditySidechainAccountStateLeaf>& accounts)
{
    std::vector<uint256> level_hashes;
    level_hashes.reserve(accounts.size());
    for (const auto& account : accounts) {
        const std::vector<unsigned char> encoded_leaf = EncodeValiditySidechainAccountStateLeaf(account);
        level_hashes.push_back(HashWithOptionalSidechainId(
            ACCOUNT_STATE_LEAF_HASH_MAGIC,
            sizeof(ACCOUNT_STATE_LEAF_HASH_MAGIC),
            encoded_leaf));
    }
    return ComputeMerkleRoot(std::move(level_hashes), ComputeAccountStateMerkleParent);
}

std::vector<unsigned char> EncodeValiditySidechainEscapeExitLeaf(const ValiditySidechainEscapeExitLeaf& exit)
{
    std::vector<unsigned char> out;
    out.reserve(VALIDITY_SIDECHAIN_ESCAPE_EXIT_LEAF_BYTES);

    AppendUint256(out, exit.exit_id);
    AppendLE64(out, static_cast<uint64_t>(exit.amount));
    AppendUint256(out, exit.destination_commitment);

    return out;
}

bool DecodeValiditySidechainEscapeExitLeaf(
    Span<const unsigned char> exit_bytes,
    ValiditySidechainEscapeExitLeaf& out_exit)
{
    if (exit_bytes.size() != VALIDITY_SIDECHAIN_ESCAPE_EXIT_LEAF_BYTES) {
        return false;
    }

    ValiditySidechainEscapeExitLeaf exit;
    if (!ReadUint256At(exit_bytes, 0, exit.exit_id) ||
        !ReadAmount64(exit_bytes, 32, exit.amount) ||
        !ReadUint256At(exit_bytes, 40, exit.destination_commitment)) {
        return false;
    }

    out_exit = exit;
    return true;
}

std::vector<unsigned char> EncodeValiditySidechainEscapeExitProof(const ValiditySidechainEscapeExitProof& proof)
{
    std::vector<unsigned char> out;
    out.reserve(VALIDITY_SIDECHAIN_ESCAPE_EXIT_PROOF_BASE_BYTES + (proof.sibling_hashes.size() * UINT256_BYTES));

    AppendLE32(out, proof.leaf_index);
    AppendLE32(out, proof.leaf_count);
    const std::vector<unsigned char> encoded_leaf = EncodeValiditySidechainEscapeExitLeaf(proof.exit);
    out.insert(out.end(), encoded_leaf.begin(), encoded_leaf.end());
    for (const auto& sibling_hash : proof.sibling_hashes) {
        AppendUint256(out, sibling_hash);
    }

    return out;
}

bool DecodeValiditySidechainEscapeExitProof(
    Span<const unsigned char> proof_bytes,
    ValiditySidechainEscapeExitProof& out_proof)
{
    if (proof_bytes.size() < VALIDITY_SIDECHAIN_ESCAPE_EXIT_PROOF_BASE_BYTES ||
        ((proof_bytes.size() - VALIDITY_SIDECHAIN_ESCAPE_EXIT_PROOF_BASE_BYTES) % UINT256_BYTES) != 0) {
        return false;
    }

    ValiditySidechainEscapeExitProof proof;
    proof.leaf_index = ReadLE32(proof_bytes.data());
    proof.leaf_count = ReadLE32(proof_bytes.data() + sizeof(uint32_t));
    if (proof.leaf_count == 0 || proof.leaf_index >= proof.leaf_count) {
        return false;
    }
    if (!DecodeValiditySidechainEscapeExitLeaf(
            proof_bytes.subspan(sizeof(uint32_t) * 2, VALIDITY_SIDECHAIN_ESCAPE_EXIT_LEAF_BYTES),
            proof.exit)) {
        return false;
    }

    const size_t sibling_count = (proof_bytes.size() - VALIDITY_SIDECHAIN_ESCAPE_EXIT_PROOF_BASE_BYTES) / UINT256_BYTES;
    if (sibling_count > MAX_VALIDITY_SIDECHAIN_MERKLE_PROOF_DEPTH) {
        return false;
    }
    proof.sibling_hashes.reserve(sibling_count);
    size_t offset = VALIDITY_SIDECHAIN_ESCAPE_EXIT_PROOF_BASE_BYTES;
    for (size_t i = 0; i < sibling_count; ++i) {
        uint256 sibling_hash;
        if (!ReadUint256At(proof_bytes, offset, sibling_hash)) {
            return false;
        }
        proof.sibling_hashes.push_back(sibling_hash);
        offset += UINT256_BYTES;
    }

    out_proof = std::move(proof);
    return true;
}

std::vector<unsigned char> EncodeValiditySidechainEscapeExitStateProof(const ValiditySidechainEscapeExitStateProof& proof)
{
    const std::vector<unsigned char> encoded_account_proof =
        EncodeValiditySidechainAccountStateProof(proof.account_proof);
    const std::vector<unsigned char> encoded_balance_proof =
        EncodeValiditySidechainBalanceProof(proof.balance_proof);

    std::vector<unsigned char> out;
    out.reserve(
        VALIDITY_SIDECHAIN_ESCAPE_EXIT_STATE_PROOF_HEADER_BYTES +
        encoded_account_proof.size() +
        encoded_balance_proof.size());

    AppendUint256(out, proof.exit_id);
    AppendUint256(out, proof.exit_asset_id);
    AppendLE64(out, static_cast<uint64_t>(proof.amount));
    AppendUint256(out, proof.destination_commitment);
    AppendLE64(out, proof.required_account_nonce);
    AppendLE64(out, proof.required_last_forced_exit_nonce);
    AppendLE32(out, static_cast<uint32_t>(encoded_account_proof.size()));
    AppendLE32(out, static_cast<uint32_t>(encoded_balance_proof.size()));
    out.insert(out.end(), encoded_account_proof.begin(), encoded_account_proof.end());
    out.insert(out.end(), encoded_balance_proof.begin(), encoded_balance_proof.end());

    return out;
}

bool DecodeValiditySidechainEscapeExitStateProof(
    Span<const unsigned char> proof_bytes,
    ValiditySidechainEscapeExitStateProof& out_proof)
{
    if (proof_bytes.size() < VALIDITY_SIDECHAIN_ESCAPE_EXIT_STATE_PROOF_HEADER_BYTES) {
        return false;
    }

    ValiditySidechainEscapeExitStateProof proof;
    if (!ReadUint256At(proof_bytes, 0, proof.exit_id) ||
        !ReadUint256At(proof_bytes, 32, proof.exit_asset_id) ||
        !ReadAmount64(proof_bytes, 64, proof.amount) ||
        !ReadUint256At(proof_bytes, 72, proof.destination_commitment)) {
        return false;
    }
    proof.required_account_nonce = ReadLE64(proof_bytes.data() + 104);
    proof.required_last_forced_exit_nonce = ReadLE64(proof_bytes.data() + 112);

    const uint32_t account_proof_size = ReadLE32(proof_bytes.data() + 120);
    const uint32_t balance_proof_size = ReadLE32(proof_bytes.data() + 124);
    const size_t total_size =
        VALIDITY_SIDECHAIN_ESCAPE_EXIT_STATE_PROOF_HEADER_BYTES +
        static_cast<size_t>(account_proof_size) +
        static_cast<size_t>(balance_proof_size);
    if (total_size != proof_bytes.size()) {
        return false;
    }

    if (!DecodeValiditySidechainAccountStateProof(
            proof_bytes.subspan(
                VALIDITY_SIDECHAIN_ESCAPE_EXIT_STATE_PROOF_HEADER_BYTES,
                account_proof_size),
            proof.account_proof)) {
        return false;
    }
    if (!DecodeValiditySidechainBalanceProof(
            proof_bytes.subspan(
                VALIDITY_SIDECHAIN_ESCAPE_EXIT_STATE_PROOF_HEADER_BYTES + account_proof_size,
                balance_proof_size),
            proof.balance_proof)) {
        return false;
    }

    out_proof = std::move(proof);
    return true;
}

bool DecodeValiditySidechainEscapeExitMetadata(
    const ValiditySidechainScriptInfo& info,
    std::vector<ValiditySidechainEscapeExitProof>& out_exit_proofs)
{
    if (info.kind != ValiditySidechainScriptInfo::Kind::EXECUTE_ESCAPE_EXIT ||
        info.metadata_pushes.empty()) {
        return false;
    }
    if (info.metadata_pushes.size() > MAX_VALIDITY_SIDECHAIN_EXECUTION_FANOUT) {
        return false;
    }

    std::vector<ValiditySidechainEscapeExitProof> exit_proofs;
    exit_proofs.reserve(info.metadata_pushes.size());
    for (const auto& push : info.metadata_pushes) {
        ValiditySidechainEscapeExitProof proof;
        if (!DecodeValiditySidechainEscapeExitProof(push, proof)) {
            return false;
        }
        exit_proofs.push_back(std::move(proof));
    }

    out_exit_proofs = std::move(exit_proofs);
    return true;
}

bool DecodeValiditySidechainEscapeExitStateMetadata(
    const ValiditySidechainScriptInfo& info,
    std::vector<ValiditySidechainEscapeExitStateProof>& out_exit_state_proofs)
{
    if (info.kind != ValiditySidechainScriptInfo::Kind::EXECUTE_ESCAPE_EXIT ||
        info.metadata_pushes.empty()) {
        return false;
    }
    if (info.metadata_pushes.size() > MAX_VALIDITY_SIDECHAIN_EXECUTION_FANOUT) {
        return false;
    }

    std::vector<ValiditySidechainEscapeExitStateProof> exit_state_proofs;
    exit_state_proofs.reserve(info.metadata_pushes.size());
    for (const auto& push : info.metadata_pushes) {
        ValiditySidechainEscapeExitStateProof proof;
        if (!DecodeValiditySidechainEscapeExitStateProof(push, proof)) {
            return false;
        }
        exit_state_proofs.push_back(std::move(proof));
    }

    out_exit_state_proofs = std::move(exit_state_proofs);
    return true;
}

uint256 ComputeValiditySidechainEscapeExitStateClaimKey(
    uint8_t scid,
    const ValiditySidechainEscapeExitStateProof& proof)
{
    CHashWriter hw(SER_GETHASH, 0);
    hw.write((const char*)ESCAPE_EXIT_STATE_CLAIM_KEY_MAGIC, sizeof(ESCAPE_EXIT_STATE_CLAIM_KEY_MAGIC));
    hw << scid;
    hw << proof.account_proof.account.account_id;
    hw << proof.exit_asset_id;
    hw << proof.required_account_nonce;
    hw << proof.required_last_forced_exit_nonce;
    return hw.GetHash();
}

uint256 ComputeValiditySidechainEscapeExitStateId(
    uint8_t scid,
    const ValiditySidechainEscapeExitStateProof& proof)
{
    CHashWriter hw(SER_GETHASH, 0);
    hw.write((const char*)ESCAPE_EXIT_STATE_ID_MAGIC, sizeof(ESCAPE_EXIT_STATE_ID_MAGIC));
    hw << ComputeValiditySidechainEscapeExitStateClaimKey(scid, proof);
    hw << static_cast<int64_t>(proof.amount);
    hw << proof.destination_commitment;
    return hw.GetHash();
}

bool BuildValiditySidechainEscapeExitProof(
    const std::vector<ValiditySidechainEscapeExitLeaf>& exits,
    uint32_t leaf_index,
    ValiditySidechainEscapeExitProof& out_proof)
{
    if (exits.empty() || leaf_index >= exits.size()) {
        return false;
    }

    std::vector<uint256> level_hashes;
    level_hashes.reserve(exits.size());
    for (const auto& exit : exits) {
        const std::vector<unsigned char> encoded_leaf = EncodeValiditySidechainEscapeExitLeaf(exit);
        level_hashes.push_back(HashWithOptionalSidechainId(
            ESCAPE_EXIT_LEAF_HASH_MAGIC,
            sizeof(ESCAPE_EXIT_LEAF_HASH_MAGIC),
            encoded_leaf));
    }

    ValiditySidechainEscapeExitProof proof;
    proof.exit = exits[leaf_index];
    proof.leaf_index = leaf_index;
    proof.leaf_count = static_cast<uint32_t>(exits.size());

    uint32_t index = leaf_index;
    while (level_hashes.size() > 1) {
        const size_t sibling_index = (index & 1U) != 0 ? static_cast<size_t>(index - 1) : std::min(static_cast<size_t>(index + 1), level_hashes.size() - 1);
        proof.sibling_hashes.push_back(level_hashes[sibling_index]);

        std::vector<uint256> next_level;
        next_level.reserve((level_hashes.size() + 1) / 2);
        for (size_t i = 0; i < level_hashes.size(); i += 2) {
            const uint256& left = level_hashes[i];
            const uint256& right = (i + 1 < level_hashes.size()) ? level_hashes[i + 1] : level_hashes[i];
            next_level.push_back(ComputeEscapeExitMerkleParent(left, right));
        }

        index >>= 1;
        level_hashes = std::move(next_level);
    }

    out_proof = std::move(proof);
    return true;
}

bool VerifyValiditySidechainEscapeExitProof(
    const ValiditySidechainEscapeExitProof& proof,
    const uint256& expected_root)
{
    if (proof.leaf_count == 0 || proof.leaf_index >= proof.leaf_count) {
        return false;
    }

    const std::vector<unsigned char> encoded_leaf = EncodeValiditySidechainEscapeExitLeaf(proof.exit);
    uint256 current_hash = HashWithOptionalSidechainId(
        ESCAPE_EXIT_LEAF_HASH_MAGIC,
        sizeof(ESCAPE_EXIT_LEAF_HASH_MAGIC),
        encoded_leaf);

    uint32_t width = proof.leaf_count;
    uint32_t index = proof.leaf_index;
    size_t expected_sibling_count = 0;
    while (width > 1) {
        ++expected_sibling_count;
        width = (width + 1) / 2;
    }
    if (proof.sibling_hashes.size() != expected_sibling_count) {
        return false;
    }

    width = proof.leaf_count;
    index = proof.leaf_index;
    for (const auto& sibling_hash : proof.sibling_hashes) {
        const bool is_right_child = (index & 1U) != 0;
        const bool has_distinct_sibling = is_right_child || (index + 1 < width);
        if (!has_distinct_sibling && sibling_hash != current_hash) {
            return false;
        }

        current_hash = is_right_child
            ? ComputeEscapeExitMerkleParent(sibling_hash, current_hash)
            : ComputeEscapeExitMerkleParent(current_hash, sibling_hash);
        index >>= 1;
        width = (width + 1) / 2;
    }

    return index == 0 && width == 1 && FinalizeEscapeExitRoot(proof.leaf_count, current_hash) == expected_root;
}

uint256 ComputeValiditySidechainEscapeExitRoot(const std::vector<ValiditySidechainEscapeExitLeaf>& exits)
{
    if (exits.empty()) {
        return FinalizeEscapeExitRoot(/* leaf_count= */ 0, uint256());
    }

    std::vector<uint256> level_hashes;
    level_hashes.reserve(exits.size());
    for (const auto& exit : exits) {
        const std::vector<unsigned char> encoded_leaf = EncodeValiditySidechainEscapeExitLeaf(exit);
        level_hashes.push_back(HashWithOptionalSidechainId(
            ESCAPE_EXIT_LEAF_HASH_MAGIC,
            sizeof(ESCAPE_EXIT_LEAF_HASH_MAGIC),
            encoded_leaf));
    }

    while (level_hashes.size() > 1) {
        std::vector<uint256> next_level;
        next_level.reserve((level_hashes.size() + 1) / 2);
        for (size_t i = 0; i < level_hashes.size(); i += 2) {
            const uint256& left = level_hashes[i];
            const uint256& right = (i + 1 < level_hashes.size()) ? level_hashes[i + 1] : level_hashes[i];
            next_level.push_back(ComputeEscapeExitMerkleParent(left, right));
        }
        level_hashes = std::move(next_level);
    }

    return FinalizeEscapeExitRoot(static_cast<uint32_t>(exits.size()), level_hashes.front());
}

std::vector<unsigned char> EncodeValiditySidechainForceExitData(const ValiditySidechainForceExitData& request)
{
    std::vector<unsigned char> out;
    out.reserve(VALIDITY_SIDECHAIN_FORCE_EXIT_BYTES);

    AppendUint256(out, request.account_id);
    AppendUint256(out, request.exit_asset_id);
    AppendLE64(out, static_cast<uint64_t>(request.max_exit_amount));
    AppendUint256(out, request.destination_commitment);
    AppendLE64(out, request.nonce);

    return out;
}

bool DecodeValiditySidechainForceExitData(Span<const unsigned char> request_bytes, ValiditySidechainForceExitData& out_request)
{
    if (request_bytes.size() != VALIDITY_SIDECHAIN_FORCE_EXIT_BYTES) {
        return false;
    }

    ValiditySidechainForceExitData request;
    if (!ReadUint256At(request_bytes, 0, request.account_id) ||
        !ReadUint256At(request_bytes, 32, request.exit_asset_id) ||
        !ReadAmount64(request_bytes, 64, request.max_exit_amount) ||
        !ReadUint256At(request_bytes, 72, request.destination_commitment)) {
        return false;
    }

    request.nonce = ReadLE64(request_bytes.data() + 104);
    out_request = request;
    return true;
}

uint256 ComputeValiditySidechainForceExitHash(uint8_t scid, const ValiditySidechainForceExitData& request)
{
    const std::vector<unsigned char> encoded_request = EncodeValiditySidechainForceExitData(request);
    return HashWithOptionalSidechainId(FORCE_EXIT_HASH_MAGIC, sizeof(FORCE_EXIT_HASH_MAGIC), encoded_request, &scid);
}

uint256 ComputeValiditySidechainAcceptedBatchId(uint8_t scid, uint32_t batch_number, const uint256& withdrawal_root)
{
    CHashWriter hw(SER_GETHASH, 0);
    hw.write((const char*)ACCEPTED_BATCH_ID_MAGIC, sizeof(ACCEPTED_BATCH_ID_MAGIC));
    hw << scid;
    hw << batch_number;
    hw << withdrawal_root;
    return hw.GetHash();
}
