// Copyright (c) 2026 AllSageTech, LLC
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <validitysidechain/verifier.h>

#include <hash.h>
#include <validitysidechain/registry.h>

#include <limits>

namespace {

static constexpr unsigned char DATA_ROOT_MAGIC[] = {'V', 'S', 'C', 'R', 0x01};

static bool FailValidation(std::string* error, const char* message)
{
    if (error != nullptr) {
        *error = message;
    }
    return false;
}

} // namespace

ValiditySidechainBatchVerifierMode GetValiditySidechainBatchVerifierMode(const ValiditySidechainConfig& config)
{
    const SupportedValiditySidechainConfig* supported = FindSupportedValiditySidechainConfig(config);
    if (supported == nullptr) {
        return ValiditySidechainBatchVerifierMode::DISABLED;
    }
    if (supported->scaffolding_only) {
        return ValiditySidechainBatchVerifierMode::SCAFFOLD_NOOP_ONLY;
    }
    return ValiditySidechainBatchVerifierMode::DISABLED;
}

const char* ValiditySidechainBatchVerifierModeToString(ValiditySidechainBatchVerifierMode mode)
{
    switch (mode) {
        case ValiditySidechainBatchVerifierMode::DISABLED:
            return "disabled";
        case ValiditySidechainBatchVerifierMode::SCAFFOLD_NOOP_ONLY:
            return "scaffold_noop_only";
    }

    return "unknown";
}

uint256 ComputeValiditySidechainDataRoot(const std::vector<std::vector<unsigned char>>& data_chunks)
{
    if (data_chunks.empty()) {
        return uint256();
    }

    CHashWriter hw(SER_GETHASH, 0);
    hw.write((const char*)DATA_ROOT_MAGIC, sizeof(DATA_ROOT_MAGIC));
    hw << static_cast<uint32_t>(data_chunks.size());
    for (const auto& chunk : data_chunks) {
        hw << static_cast<uint32_t>(chunk.size());
        if (!chunk.empty()) {
            hw.write((const char*)chunk.data(), chunk.size());
        }
    }
    return hw.GetHash();
}

bool VerifyValiditySidechainBatch(
    const ValiditySidechainConfig& config,
    uint8_t sidechain_id,
    const ValiditySidechainBatchPublicInputs& public_inputs,
    const std::vector<unsigned char>& proof_bytes,
    const std::vector<std::vector<unsigned char>>& data_chunks,
    const uint256& current_state_root,
    const uint256& current_withdrawal_root,
    const uint256& current_data_root,
    const uint256& current_l1_message_root,
    std::string* error,
    ValiditySidechainBatchVerifierMode* mode_out)
{
    (void)sidechain_id;

    const ValiditySidechainBatchVerifierMode mode = GetValiditySidechainBatchVerifierMode(config);
    if (mode_out != nullptr) {
        *mode_out = mode;
    }

    if (public_inputs.batch_number == 0) {
        return FailValidation(error, "batch_number must be non-zero");
    }
    if (proof_bytes.size() > config.max_proof_bytes) {
        return FailValidation(error, "proof bytes exceed configured limit");
    }

    uint32_t total_data_size = 0;
    for (const auto& chunk : data_chunks) {
        if (chunk.size() > static_cast<size_t>(std::numeric_limits<uint32_t>::max() - total_data_size)) {
            return FailValidation(error, "data chunk size overflow");
        }
        total_data_size += static_cast<uint32_t>(chunk.size());
    }
    if (total_data_size != public_inputs.data_size) {
        return FailValidation(error, "data size does not match published chunks");
    }
    if (public_inputs.data_size > config.max_batch_data_bytes) {
        return FailValidation(error, "data size exceeds configured limit");
    }
    if (ComputeValiditySidechainDataRoot(data_chunks) != public_inputs.data_root) {
        return FailValidation(error, "data root does not match published chunks");
    }

    if (mode != ValiditySidechainBatchVerifierMode::SCAFFOLD_NOOP_ONLY) {
        return FailValidation(error, "proof verifier is not implemented for this profile");
    }

    if (!proof_bytes.empty()) {
        return FailValidation(error, "scaffold verifier requires empty proof bytes");
    }
    if (public_inputs.consumed_queue_messages != 0) {
        return FailValidation(error, "scaffold verifier does not allow queue consumption yet");
    }
    if (public_inputs.new_state_root != current_state_root) {
        return FailValidation(error, "scaffold verifier only allows no-op state root updates");
    }
    if (public_inputs.withdrawal_root != current_withdrawal_root) {
        return FailValidation(error, "scaffold verifier only allows no-op withdrawal roots");
    }
    if (public_inputs.data_root != current_data_root) {
        return FailValidation(error, "scaffold verifier only allows no-op data roots");
    }
    if (public_inputs.l1_message_root_before != current_l1_message_root ||
        public_inputs.l1_message_root_after != current_l1_message_root) {
        return FailValidation(error, "scaffold verifier only allows no-op queue roots");
    }
    if (public_inputs.data_size != 0 || !data_chunks.empty()) {
        return FailValidation(error, "scaffold verifier requires empty DA payload");
    }

    return true;
}
