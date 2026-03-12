// Copyright (c) 2026 AllSageTech, LLC
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <validitysidechain/verifier.h>

#include <hash.h>
#include <validitysidechain/registry.h>
#include <validitysidechain/script.h>

#include <algorithm>
#include <iterator>
#include <limits>

namespace {

static constexpr unsigned char DATA_ROOT_MAGIC[] = {'V', 'S', 'C', 'R', 0x01};
static constexpr unsigned char SCAFFOLD_PROOF_MAGIC[] = {'V', 'S', 'C', 'P', 0x01};
static constexpr size_t UINT256_SERIALIZED_SIZE = 32;

struct ValiditySidechainScaffoldProofEnvelope
{
    uint256 batch_commitment;
    uint256 current_state_root;
    uint256 current_withdrawal_root;
    uint256 current_data_root;
    uint256 current_l1_message_root;
};

static bool FailValidation(std::string* error, const char* message)
{
    if (error != nullptr) {
        *error = message;
    }
    return false;
}

static void AppendUint256(std::vector<unsigned char>& out, const uint256& value)
{
    out.insert(out.end(), value.begin(), value.end());
}

static bool ReadUint256(
    const std::vector<unsigned char>& bytes,
    size_t offset,
    uint256& out_value)
{
    if (offset > bytes.size() || bytes.size() - offset < UINT256_SERIALIZED_SIZE) {
        return false;
    }

    out_value = uint256(std::vector<unsigned char>(
        bytes.begin() + offset,
        bytes.begin() + offset + UINT256_SERIALIZED_SIZE));
    return true;
}

static std::vector<unsigned char> EncodeValiditySidechainScaffoldProofEnvelope(
    const ValiditySidechainScaffoldProofEnvelope& envelope)
{
    std::vector<unsigned char> out;
    out.insert(out.end(), std::begin(SCAFFOLD_PROOF_MAGIC), std::end(SCAFFOLD_PROOF_MAGIC));
    AppendUint256(out, envelope.batch_commitment);
    AppendUint256(out, envelope.current_state_root);
    AppendUint256(out, envelope.current_withdrawal_root);
    AppendUint256(out, envelope.current_data_root);
    AppendUint256(out, envelope.current_l1_message_root);
    return out;
}

static bool DecodeValiditySidechainScaffoldProofEnvelope(
    const std::vector<unsigned char>& proof_bytes,
    ValiditySidechainScaffoldProofEnvelope& out_envelope)
{
    if (proof_bytes.size() != sizeof(SCAFFOLD_PROOF_MAGIC) + (UINT256_SERIALIZED_SIZE * 5)) {
        return false;
    }
    if (!std::equal(
            std::begin(SCAFFOLD_PROOF_MAGIC),
            std::end(SCAFFOLD_PROOF_MAGIC),
            proof_bytes.begin())) {
        return false;
    }

    size_t offset = sizeof(SCAFFOLD_PROOF_MAGIC);
    return ReadUint256(proof_bytes, offset, out_envelope.batch_commitment) &&
           ReadUint256(proof_bytes, offset += UINT256_SERIALIZED_SIZE, out_envelope.current_state_root) &&
           ReadUint256(proof_bytes, offset += UINT256_SERIALIZED_SIZE, out_envelope.current_withdrawal_root) &&
           ReadUint256(proof_bytes, offset += UINT256_SERIALIZED_SIZE, out_envelope.current_data_root) &&
           ReadUint256(proof_bytes, offset += UINT256_SERIALIZED_SIZE, out_envelope.current_l1_message_root);
}

} // namespace

ValiditySidechainBatchVerifierMode GetValiditySidechainBatchVerifierMode(const ValiditySidechainConfig& config)
{
    const SupportedValiditySidechainConfig* supported = FindSupportedValiditySidechainConfig(config);
    if (supported == nullptr) {
        return ValiditySidechainBatchVerifierMode::DISABLED;
    }
    if (supported->scaffolding_only) {
        return ValiditySidechainBatchVerifierMode::SCAFFOLD_QUEUE_PREFIX_ONLY;
    }
    return ValiditySidechainBatchVerifierMode::DISABLED;
}

const char* ValiditySidechainBatchVerifierModeToString(ValiditySidechainBatchVerifierMode mode)
{
    switch (mode) {
        case ValiditySidechainBatchVerifierMode::DISABLED:
            return "disabled";
        case ValiditySidechainBatchVerifierMode::SCAFFOLD_QUEUE_PREFIX_ONLY:
            return "scaffold_queue_prefix_commitment_v1";
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

std::vector<unsigned char> BuildValiditySidechainScaffoldBatchProof(
    uint8_t sidechain_id,
    const ValiditySidechainBatchPublicInputs& public_inputs,
    const uint256& current_state_root,
    const uint256& current_withdrawal_root,
    const uint256& current_data_root,
    const uint256& current_l1_message_root)
{
    const ValiditySidechainScaffoldProofEnvelope envelope{
        /* batch_commitment        = */ ComputeValiditySidechainBatchCommitmentHash(sidechain_id, public_inputs),
        /* current_state_root      = */ current_state_root,
        /* current_withdrawal_root = */ current_withdrawal_root,
        /* current_data_root       = */ current_data_root,
        /* current_l1_message_root = */ current_l1_message_root,
    };
    return EncodeValiditySidechainScaffoldProofEnvelope(envelope);
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

    if (mode != ValiditySidechainBatchVerifierMode::SCAFFOLD_QUEUE_PREFIX_ONLY) {
        return FailValidation(error, "proof verifier is not implemented for this profile");
    }

    ValiditySidechainScaffoldProofEnvelope envelope;
    if (!DecodeValiditySidechainScaffoldProofEnvelope(proof_bytes, envelope)) {
        return FailValidation(error, "invalid scaffold proof envelope");
    }
    if (envelope.batch_commitment != ComputeValiditySidechainBatchCommitmentHash(sidechain_id, public_inputs)) {
        return FailValidation(error, "scaffold proof envelope does not match batch commitment");
    }
    if (envelope.current_state_root != current_state_root ||
        envelope.current_withdrawal_root != current_withdrawal_root ||
        envelope.current_data_root != current_data_root ||
        envelope.current_l1_message_root != current_l1_message_root) {
        return FailValidation(error, "scaffold proof envelope does not match current chainstate roots");
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
    if (public_inputs.l1_message_root_before != current_l1_message_root) {
        return FailValidation(error, "batch queue root before does not match current queue root");
    }
    if (public_inputs.data_size != 0 || !data_chunks.empty()) {
        return FailValidation(error, "scaffold verifier requires empty DA payload");
    }

    return true;
}
