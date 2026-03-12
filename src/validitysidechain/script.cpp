// Copyright (c) 2026 AllSageTech, LLC
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <validitysidechain/script.h>

#include <crypto/common.h>
#include <hash.h>
#include <script/script.h>

#include <algorithm>
#include <limits>

namespace {

static constexpr unsigned char CONFIG_HASH_MAGIC[] = {'V', 'S', 'C', 'F', 0x01};
static constexpr unsigned char DEPOSIT_HASH_MAGIC[] = {'V', 'S', 'C', 'D', 0x01};
static constexpr unsigned char BATCH_HASH_MAGIC[] = {'V', 'S', 'C', 'B', 0x01};
static constexpr unsigned char FORCE_EXIT_HASH_MAGIC[] = {'V', 'S', 'C', 'X', 0x01};
static constexpr unsigned char ACCEPTED_BATCH_ID_MAGIC[] = {'V', 'S', 'C', 'A', 0x01};
static constexpr size_t UINT256_BYTES = uint256::WIDTH;

static constexpr size_t VALIDITY_SIDECHAIN_CONFIG_BYTES = 94;
static constexpr size_t VALIDITY_SIDECHAIN_DEPOSIT_BYTES = 112;
static constexpr size_t VALIDITY_SIDECHAIN_BATCH_PUBLIC_INPUT_BYTES = 200;
static constexpr size_t VALIDITY_SIDECHAIN_FORCE_EXIT_BYTES = 112;

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

bool DecodeValiditySidechainScript(const CScript& scriptPubKey, ValiditySidechainScriptInfo& out_info)
{
    // The new validity-sidechain path temporarily reuses OP_DRIVECHAIN transport,
    // but intentionally keeps a non-overlapping tag range while the legacy
    // drivechain withdrawal model still exists in the codebase.
    //
    // [0]: OP_RETURN
    // [1]: OP_DRIVECHAIN
    // [2]: PUSHDATA(1)  -> sidechain_id
    // [3]: PUSHDATA(32) -> payload
    // [4]: PUSHDATA(1)  -> tag
    // [5..n]: optional pushed metadata items, depending on tag

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
        case ValiditySidechainScriptInfo::Kind::REQUEST_FORCE_EXIT:
            if (info.metadata_pushes.empty()) {
                return false;
            }
            break;
        case ValiditySidechainScriptInfo::Kind::EXECUTE_VERIFIED_WITHDRAWALS:
        case ValiditySidechainScriptInfo::Kind::RECLAIM_STALE_DEPOSIT:
        case ValiditySidechainScriptInfo::Kind::EXECUTE_ESCAPE_EXIT:
            if (!info.metadata_pushes.empty()) {
                return false;
            }
            break;
        case ValiditySidechainScriptInfo::Kind::COMMIT_VALIDITY_BATCH:
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
    script << OP_RETURN << OP_DRIVECHAIN << sidechain_v << payload_v << tag_v;
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
    const std::vector<std::vector<unsigned char>>& extra_metadata_pushes)
{
    std::vector<std::vector<unsigned char>> metadata_pushes;
    metadata_pushes.push_back(EncodeValiditySidechainBatchPublicInputs(public_inputs));
    metadata_pushes.insert(metadata_pushes.end(), extra_metadata_pushes.begin(), extra_metadata_pushes.end());

    const uint256 payload = ComputeValiditySidechainBatchCommitmentHash(scid, public_inputs);
    return BuildValiditySidechainScript(
        ValiditySidechainScriptInfo::Kind::COMMIT_VALIDITY_BATCH,
        scid,
        payload,
        metadata_pushes);
}

CScript BuildValiditySidechainExecuteScript(uint8_t scid, uint32_t batch_number, const uint256& withdrawal_root)
{
    return BuildValiditySidechainScript(
        ValiditySidechainScriptInfo::Kind::EXECUTE_VERIFIED_WITHDRAWALS,
        scid,
        ComputeValiditySidechainAcceptedBatchId(scid, batch_number, withdrawal_root));
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

CScript BuildValiditySidechainReclaimDepositScript(uint8_t scid, const uint256& deposit_id)
{
    return BuildValiditySidechainScript(
        ValiditySidechainScriptInfo::Kind::RECLAIM_STALE_DEPOSIT,
        scid,
        deposit_id);
}

CScript BuildValiditySidechainEscapeExitScript(uint8_t scid, const uint256& state_root_reference)
{
    return BuildValiditySidechainScript(
        ValiditySidechainScriptInfo::Kind::EXECUTE_ESCAPE_EXIT,
        scid,
        state_root_reference);
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
        !ReadUint256At(public_input_bytes, 132, public_inputs.withdrawal_root) ||
        !ReadUint256At(public_input_bytes, 164, public_inputs.data_root)) {
        return false;
    }

    public_inputs.data_size = ReadLE32(public_input_bytes.data() + 196);
    out_public_inputs = public_inputs;
    return true;
}

uint256 ComputeValiditySidechainBatchCommitmentHash(uint8_t scid, const ValiditySidechainBatchPublicInputs& public_inputs)
{
    const std::vector<unsigned char> encoded_public_inputs = EncodeValiditySidechainBatchPublicInputs(public_inputs);
    return HashWithOptionalSidechainId(BATCH_HASH_MAGIC, sizeof(BATCH_HASH_MAGIC), encoded_public_inputs, &scid);
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
