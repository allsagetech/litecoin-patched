// Copyright (c) 2026 AllSageTech, LLC
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <validitysidechain/verifier.h>

#include <fs.h>
#include <hash.h>
#include <util/system.h>
#include <validitysidechain/registry.h>
#include <validitysidechain/script.h>

#include <algorithm>
#include <cstdint>
#include <ios>
#include <iterator>
#include <limits>
#include <string>

namespace {

static constexpr unsigned char DATA_ROOT_MAGIC[] = {'V', 'S', 'C', 'R', 0x01};
static constexpr unsigned char SCAFFOLD_PROOF_MAGIC[] = {'V', 'S', 'C', 'P', 0x01};
static constexpr size_t UINT256_SERIALIZED_SIZE = 32;
static constexpr char VERIFIER_ARTIFACTS_DIR[] = "artifacts";
static constexpr char VERIFIER_NAMESPACE_DIR[] = "validitysidechain";
static constexpr char VERIFIER_PROFILE_MANIFEST[] = "profile.json";
static constexpr char VERIFIER_BATCH_VK[] = "batch_vk.bin";
static constexpr char PLACEHOLDER_SENTINEL[] = "PLACEHOLDER";

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

static bool ValidatePublishedBatchData(
    const ValiditySidechainConfig& config,
    const ValiditySidechainBatchPublicInputs& public_inputs,
    const std::vector<std::vector<unsigned char>>& data_chunks,
    std::string* error)
{
    if (public_inputs.data_size > config.max_batch_data_bytes) {
        return FailValidation(error, "data size exceeds configured limit");
    }
    if (public_inputs.data_size != 0 && data_chunks.empty()) {
        return FailValidation(error, "data chunks missing for non-zero data_size");
    }

    uint64_t total_data_size = 0;
    for (const auto& chunk : data_chunks) {
        if (chunk.empty()) {
            return FailValidation(error, "data chunk must be non-empty");
        }
        total_data_size += chunk.size();
        if (total_data_size > std::numeric_limits<uint32_t>::max()) {
            return FailValidation(error, "data chunk size overflow");
        }
    }

    if (total_data_size != public_inputs.data_size) {
        return FailValidation(error, "data size does not match published chunks");
    }
    if (ComputeValiditySidechainDataRoot(data_chunks) != public_inputs.data_root) {
        return FailValidation(error, "data root does not match published chunks");
    }

    return true;
}

static fs::path ResolveVerifierArtifactDir(const SupportedValiditySidechainConfig& supported)
{
    const fs::path datadir_candidate =
        GetDataDir() / VERIFIER_ARTIFACTS_DIR / VERIFIER_NAMESPACE_DIR / supported.verifier_artifact_name;
    if (fs::exists(datadir_candidate)) {
        return datadir_candidate;
    }

    const fs::path repo_candidate =
        fs::path(VERIFIER_ARTIFACTS_DIR) / VERIFIER_NAMESPACE_DIR / supported.verifier_artifact_name;
    if (fs::exists(repo_candidate)) {
        return repo_candidate;
    }

    return datadir_candidate;
}

static bool ReadFilePrefix(const fs::path& path, std::string& out, size_t max_bytes)
{
    fsbridge::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }

    std::vector<char> buffer(max_bytes);
    file.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
    const std::streamsize read_bytes = file.gcount();
    if (read_bytes <= 0) {
        out.clear();
        return true;
    }

    out.assign(buffer.data(), static_cast<size_t>(read_bytes));
    return true;
}

static bool FileContainsPlaceholderSentinel(const fs::path& path)
{
    std::string prefix;
    if (!ReadFilePrefix(path, prefix, 256)) {
        return false;
    }
    return prefix.find(PLACEHOLDER_SENTINEL) != std::string::npos ||
           prefix.find("\"placeholder\": true") != std::string::npos;
}

static bool PopulateVerifierAssetsStatus(
    const SupportedValiditySidechainConfig& supported,
    ValiditySidechainVerifierAssetsStatus& out_status)
{
    out_status.requires_external_assets = supported.requires_external_verifier_assets;
    out_status.artifact_name = supported.verifier_artifact_name == nullptr ? "" : supported.verifier_artifact_name;

    if (!supported.requires_external_verifier_assets || supported.verifier_artifact_name == nullptr) {
        out_status.assets_present = true;
        out_status.backend_ready = true;
        out_status.status = "embedded scaffold verifier";
        return true;
    }

    const fs::path artifact_dir = ResolveVerifierArtifactDir(supported);
    const fs::path manifest_path = artifact_dir / VERIFIER_PROFILE_MANIFEST;
    const fs::path verifying_key_path = artifact_dir / VERIFIER_BATCH_VK;

    out_status.artifact_dir = artifact_dir.string();
    out_status.profile_manifest_path = manifest_path.string();
    out_status.verifying_key_path = verifying_key_path.string();

    try {
        const bool has_manifest = fs::exists(manifest_path) && fs::is_regular_file(manifest_path);
        const bool has_vk = fs::exists(verifying_key_path) && fs::is_regular_file(verifying_key_path);

        if (has_vk) {
            out_status.verifying_key_bytes = static_cast<uint64_t>(fs::file_size(verifying_key_path));
        }

        out_status.assets_present = has_manifest && has_vk && out_status.verifying_key_bytes > 0;
        if (!has_manifest) {
            out_status.status = "missing profile manifest";
            return true;
        }
        if (!has_vk || out_status.verifying_key_bytes == 0) {
            out_status.status = "missing verifying key";
            return true;
        }
        if (FileContainsPlaceholderSentinel(manifest_path) ||
            FileContainsPlaceholderSentinel(verifying_key_path)) {
            out_status.assets_present = false;
            out_status.status = "placeholder verifier artifacts only";
            return true;
        }

        out_status.backend_ready = false;
        out_status.status = "assets found but Groth16 verifier backend is not implemented";
        return true;
    } catch (const fs::filesystem_error& e) {
        out_status.assets_present = false;
        out_status.backend_ready = false;
        out_status.status = fsbridge::get_filesystem_error_message(e);
        return false;
    }
}

} // namespace

ValiditySidechainBatchVerifierMode GetValiditySidechainBatchVerifierMode(const ValiditySidechainConfig& config)
{
    const SupportedValiditySidechainConfig* supported = FindSupportedValiditySidechainConfig(config);
    if (supported == nullptr) {
        return ValiditySidechainBatchVerifierMode::DISABLED;
    }
    if (supported->scaffolding_only &&
        supported->profile_name != nullptr &&
        std::string(supported->profile_name) == "scaffold_transition_da_v1") {
        return ValiditySidechainBatchVerifierMode::SCAFFOLD_TRANSITION_COMMITMENT;
    }
    if (!supported->scaffolding_only &&
        supported->profile_name != nullptr &&
        std::string(supported->profile_name) == "groth16_bls12_381_poseidon_v1") {
        return ValiditySidechainBatchVerifierMode::GROTH16_BLS12_381_POSEIDON_V1;
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
        case ValiditySidechainBatchVerifierMode::SCAFFOLD_TRANSITION_COMMITMENT:
            return "scaffold_transition_commitment_v1";
        case ValiditySidechainBatchVerifierMode::GROTH16_BLS12_381_POSEIDON_V1:
            return "groth16_bls12_381_poseidon_v1";
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

bool GetValiditySidechainVerifierAssetsStatus(
    const ValiditySidechainConfig& config,
    ValiditySidechainVerifierAssetsStatus& out_status)
{
    out_status = ValiditySidechainVerifierAssetsStatus{};
    const SupportedValiditySidechainConfig* supported = FindSupportedValiditySidechainConfig(config);
    if (supported == nullptr) {
        out_status.status = "unsupported proof configuration tuple";
        return false;
    }
    return PopulateVerifierAssetsStatus(*supported, out_status);
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
    if (proof_bytes.empty()) {
        return FailValidation(error, "proof bytes must be non-empty");
    }
    if (proof_bytes.size() > config.max_proof_bytes) {
        return FailValidation(error, "proof bytes exceed configured limit");
    }
    if (!ValidatePublishedBatchData(config, public_inputs, data_chunks, error)) {
        return false;
    }

    if (mode != ValiditySidechainBatchVerifierMode::SCAFFOLD_QUEUE_PREFIX_ONLY &&
        mode != ValiditySidechainBatchVerifierMode::SCAFFOLD_TRANSITION_COMMITMENT &&
        mode != ValiditySidechainBatchVerifierMode::GROTH16_BLS12_381_POSEIDON_V1) {
        return FailValidation(error, "proof verifier is not implemented for this profile");
    }

    if (mode == ValiditySidechainBatchVerifierMode::GROTH16_BLS12_381_POSEIDON_V1) {
        ValiditySidechainVerifierAssetsStatus assets_status;
        GetValiditySidechainVerifierAssetsStatus(config, assets_status);
        if (!assets_status.assets_present) {
            return FailValidation(error, "verifier assets missing for supported profile");
        }
        if (!assets_status.backend_ready) {
            return FailValidation(error, "Groth16 verifier backend is not implemented for this profile");
        }
        return FailValidation(error, "Groth16 verifier backend is not implemented for this profile");
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
    if (public_inputs.l1_message_root_before != current_l1_message_root) {
        return FailValidation(error, "batch queue root before does not match current queue root");
    }

    if (mode == ValiditySidechainBatchVerifierMode::SCAFFOLD_QUEUE_PREFIX_ONLY) {
        if (public_inputs.new_state_root != current_state_root) {
            return FailValidation(error, "scaffold verifier only allows no-op state root updates");
        }
        if (public_inputs.withdrawal_root != current_withdrawal_root) {
            return FailValidation(error, "scaffold verifier only allows no-op withdrawal roots");
        }
        if (public_inputs.data_root != current_data_root) {
            return FailValidation(error, "scaffold verifier only allows no-op data roots");
        }
        if (public_inputs.data_size != 0 || !data_chunks.empty()) {
            return FailValidation(error, "scaffold verifier requires empty DA payload");
        }
    }

    return true;
}
