// Copyright (c) 2026 AllSageTech, LLC
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <validitysidechain/verifier.h>

#include <fs.h>
#include <hash.h>
#include <univalue.h>
#include <util/moneystr.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <validitysidechain/blst_backend.h>
#include <validitysidechain/groth16.h>
#include <validitysidechain/registry.h>
#include <validitysidechain/script.h>

#include <algorithm>
#include <array>
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
static constexpr char VERIFIER_BATCH_PK[] = "batch_pk.bin";
static constexpr char PLACEHOLDER_SENTINEL[] = "PLACEHOLDER";
static constexpr char TOY_PROFILE_NAME[] = "gnark_groth16_toy_batch_transition_v1";
static constexpr char NATIVE_TOY_PROFILE_NAME[] = "native_blst_groth16_toy_batch_transition_v1";
static constexpr char POSEIDON_PROFILE_NAME[] = "groth16_bls12_381_poseidon_v1";
static constexpr char POSEIDON_PROFILE_NAME_V2[] = "groth16_bls12_381_poseidon_v2";
static constexpr char POSEIDON_PROFILE_PREFIX[] = "groth16_bls12_381_poseidon_v";
static constexpr uint8_t POSEIDON_FINAL_DECOMPOSED_PUBLIC_INPUT_VERSION = 5;
static constexpr size_t GROTH16_DECOMPOSED_LIMB_BYTES = 16;

struct ValiditySidechainScaffoldProofEnvelope
{
    uint256 batch_commitment;
    uint256 current_state_root;
    uint256 current_withdrawal_root;
    uint256 current_data_root;
    uint256 current_l1_message_root;
};

struct ParsedVerifierManifest
{
    bool placeholder{false};
    std::string profile_name;
    std::string backend_name;
    std::string verifying_key_file;
    std::string proving_key_file;
    bool has_consensus_tuple{false};
    uint8_t version{0};
    uint8_t proof_system_id{0};
    uint8_t circuit_family_id{0};
    uint8_t verifier_id{0};
    uint8_t public_input_version{0};
    uint8_t state_root_format{0};
    uint8_t deposit_message_format{0};
    uint8_t withdrawal_leaf_format{0};
    uint8_t balance_leaf_format{0};
    uint8_t data_availability_mode{0};
    std::vector<std::string> public_inputs;
    std::vector<std::string> valid_vector_files;
    std::vector<std::string> invalid_vector_files;
};

static bool FailValidation(std::string* error, const char* message)
{
    if (error != nullptr) {
        *error = message;
    }
    return false;
}

static bool IsPoseidonProfileName(const char* profile_name)
{
    return profile_name != nullptr &&
           std::string(profile_name).rfind(POSEIDON_PROFILE_PREFIX, 0) == 0;
}

static bool IsPoseidonProfile(const SupportedValiditySidechainConfig& supported)
{
    return IsPoseidonProfileName(supported.profile_name);
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
    if (data_chunks.size() > MAX_VALIDITY_SIDECHAIN_BATCH_DATA_CHUNKS) {
        return FailValidation(error, "batch data chunk count exceeds consensus limit");
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
    if (gArgs.IsArgSet("-validityartifactsdir")) {
        const fs::path explicit_root =
            AbsPathForConfigVal(fs::path(gArgs.GetArg("-validityartifactsdir", "")), /* net_specific= */ false);
        const fs::path explicit_candidate =
            explicit_root / VERIFIER_NAMESPACE_DIR / supported.verifier_artifact_name;
        if (fs::exists(explicit_candidate)) {
            return explicit_candidate;
        }
        return explicit_candidate;
    }

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

static bool ReadTextFile(const fs::path& path, std::string& out)
{
    fsbridge::ifstream file(path);
    if (!file.is_open()) {
        return false;
    }

    out.assign(
        std::istreambuf_iterator<char>(file),
        std::istreambuf_iterator<char>());
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

static bool ParseStringArray(
    const UniValue& value,
    std::vector<std::string>& out)
{
    if (!value.isArray()) {
        return false;
    }

    out.clear();
    out.reserve(value.size());
    for (size_t i = 0; i < value.size(); ++i) {
        if (!value[i].isStr()) {
            return false;
        }
        out.push_back(value[i].get_str());
    }
    return true;
}

static bool ParseManifestUint8(
    const UniValue& value,
    const char* field_name,
    uint8_t& out_value,
    std::string* error)
{
    if (!value.isNum()) {
        return FailValidation(error, field_name);
    }
    const int64_t parsed = value.get_int64();
    if (parsed < 0 || parsed > std::numeric_limits<uint8_t>::max()) {
        return FailValidation(error, field_name);
    }
    out_value = static_cast<uint8_t>(parsed);
    return true;
}

static std::vector<std::string> ExpectedManifestPublicInputs(const SupportedValiditySidechainConfig& supported)
{
    if (supported.profile_name != nullptr &&
        std::string(supported.profile_name) == TOY_PROFILE_NAME) {
        return {
            "sidechain_id",
            "batch_number",
            "prior_state_root",
            "new_state_root",
            "consumed_queue_messages",
            "withdrawal_root",
            "data_root",
        };
    }
    if (supported.profile_name != nullptr &&
        std::string(supported.profile_name) == NATIVE_TOY_PROFILE_NAME) {
        return {
            "sidechain_id",
            "batch_number",
            "prior_state_root",
            "new_state_root",
            "consumed_queue_messages",
            "withdrawal_root",
            "data_root",
        };
    }
    if (IsPoseidonProfile(supported)) {
        if (supported.public_input_version >= POSEIDON_FINAL_DECOMPOSED_PUBLIC_INPUT_VERSION) {
            return {
                "sidechain_id",
                "batch_number",
                "prior_state_root",
                "new_state_root",
                "l1_message_root_before_lo",
                "l1_message_root_before_hi",
                "l1_message_root_after_lo",
                "l1_message_root_after_hi",
                "consumed_queue_messages",
                "queue_prefix_commitment_lo",
                "queue_prefix_commitment_hi",
                "withdrawal_root_lo",
                "withdrawal_root_hi",
                "data_root_lo",
                "data_root_hi",
                "data_size",
            };
        }
        return {
            "sidechain_id",
            "batch_number",
            "prior_state_root",
            "new_state_root",
            "l1_message_root_before",
            "l1_message_root_after",
            "consumed_queue_messages",
            "queue_prefix_commitment",
            "withdrawal_root",
            "data_root",
            "data_size",
        };
    }
    return {};
}

static bool ParseVerifierManifest(
    const fs::path& manifest_path,
    ParsedVerifierManifest& out_manifest,
    std::string* error)
{
    std::string manifest_json;
    if (!ReadTextFile(manifest_path, manifest_json)) {
        return FailValidation(error, "unable to read profile manifest");
    }

    UniValue root(UniValue::VOBJ);
    if (!root.read(manifest_json) || !root.isObject()) {
        return FailValidation(error, "profile manifest is not valid JSON");
    }

    out_manifest = ParsedVerifierManifest{};

    const UniValue& profile_name = find_value(root, "name");
    if (profile_name.isStr()) {
        out_manifest.profile_name = profile_name.get_str();
    } else {
        const UniValue& legacy_profile_name = find_value(root, "profile_name");
        if (legacy_profile_name.isStr()) {
            out_manifest.profile_name = legacy_profile_name.get_str();
        }
    }

    const UniValue& backend_name = find_value(root, "backend");
    if (backend_name.isStr()) {
        out_manifest.backend_name = backend_name.get_str();
    }

    const UniValue& placeholder = find_value(root, "placeholder");
    if (placeholder.isBool()) {
        out_manifest.placeholder = placeholder.get_bool();
    }

    const UniValue& verifying_key_file = find_value(root, "verifying_key_file");
    if (verifying_key_file.isStr()) {
        out_manifest.verifying_key_file = verifying_key_file.get_str();
    }

    const UniValue& proving_key_file = find_value(root, "proving_key_file");
    if (proving_key_file.isStr()) {
        out_manifest.proving_key_file = proving_key_file.get_str();
    }

    const UniValue& consensus_tuple = find_value(root, "consensus_tuple");
    if (consensus_tuple.isObject()) {
        if (!ParseManifestUint8(find_value(consensus_tuple, "version"), "profile manifest consensus_tuple.version is invalid", out_manifest.version, error) ||
            !ParseManifestUint8(find_value(consensus_tuple, "proof_system_id"), "profile manifest consensus_tuple.proof_system_id is invalid", out_manifest.proof_system_id, error) ||
            !ParseManifestUint8(find_value(consensus_tuple, "circuit_family_id"), "profile manifest consensus_tuple.circuit_family_id is invalid", out_manifest.circuit_family_id, error) ||
            !ParseManifestUint8(find_value(consensus_tuple, "verifier_id"), "profile manifest consensus_tuple.verifier_id is invalid", out_manifest.verifier_id, error) ||
            !ParseManifestUint8(find_value(consensus_tuple, "public_input_version"), "profile manifest consensus_tuple.public_input_version is invalid", out_manifest.public_input_version, error) ||
            !ParseManifestUint8(find_value(consensus_tuple, "state_root_format"), "profile manifest consensus_tuple.state_root_format is invalid", out_manifest.state_root_format, error) ||
            !ParseManifestUint8(find_value(consensus_tuple, "deposit_message_format"), "profile manifest consensus_tuple.deposit_message_format is invalid", out_manifest.deposit_message_format, error) ||
            !ParseManifestUint8(find_value(consensus_tuple, "withdrawal_leaf_format"), "profile manifest consensus_tuple.withdrawal_leaf_format is invalid", out_manifest.withdrawal_leaf_format, error) ||
            !ParseManifestUint8(find_value(consensus_tuple, "balance_leaf_format"), "profile manifest consensus_tuple.balance_leaf_format is invalid", out_manifest.balance_leaf_format, error) ||
            !ParseManifestUint8(find_value(consensus_tuple, "data_availability_mode"), "profile manifest consensus_tuple.data_availability_mode is invalid", out_manifest.data_availability_mode, error)) {
            return false;
        }
        out_manifest.has_consensus_tuple = true;
    }

    const UniValue& public_inputs = find_value(root, "public_inputs");
    if (!public_inputs.isNull() &&
        !ParseStringArray(public_inputs, out_manifest.public_inputs)) {
        return FailValidation(error, "profile manifest public_inputs must be a string array");
    }

    const UniValue& proof_vectors = find_value(root, "proof_vectors");
    if (proof_vectors.isObject()) {
        const UniValue& valid_vectors = find_value(proof_vectors, "valid");
        if (!valid_vectors.isNull() &&
            !ParseStringArray(valid_vectors, out_manifest.valid_vector_files)) {
            return FailValidation(error, "profile manifest valid proof_vectors must be a string array");
        }

        const UniValue& invalid_vectors = find_value(proof_vectors, "invalid");
        if (!invalid_vectors.isNull() &&
            !ParseStringArray(invalid_vectors, out_manifest.invalid_vector_files)) {
            return FailValidation(error, "profile manifest invalid proof_vectors must be a string array");
        }
    }

    return true;
}

static bool PopulateVerifierAssetsStatus(
    const SupportedValiditySidechainConfig& supported,
    ValiditySidechainVerifierAssetsStatus& out_status)
{
    out_status.requires_external_assets = supported.requires_external_verifier_assets;
    out_status.artifact_name = supported.verifier_artifact_name == nullptr ? "" : supported.verifier_artifact_name;
    out_status.backend_name = supported.verifier_backend == nullptr ? "" : supported.verifier_backend;
    if (supported.verifier_backend != nullptr &&
        std::string(supported.verifier_backend) == "native_blst_groth16") {
        ValiditySidechainNativeBlstBackendStatus native_backend_status;
        GetValiditySidechainNativeBlstBackendStatus(native_backend_status);
        out_status.native_backend_available = native_backend_status.available;
        out_status.native_backend_self_test_passed = native_backend_status.self_test_passed;
        out_status.native_backend_pairing_context_bytes = native_backend_status.pairing_context_bytes;
        out_status.native_backend_status = native_backend_status.status;
    }

    if (!supported.requires_external_verifier_assets || supported.verifier_artifact_name == nullptr) {
        out_status.assets_present = true;
        out_status.prover_assets_present = true;
        out_status.backend_ready = true;
        out_status.status = "embedded scaffold verifier";
        return true;
    }

    const fs::path artifact_dir = ResolveVerifierArtifactDir(supported);
    const fs::path manifest_path = artifact_dir / VERIFIER_PROFILE_MANIFEST;
    const fs::path verifying_key_path = artifact_dir / VERIFIER_BATCH_VK;
    const fs::path proving_key_path = artifact_dir / VERIFIER_BATCH_PK;

    out_status.artifact_dir = artifact_dir.string();
    out_status.profile_manifest_path = manifest_path.string();
    out_status.verifying_key_path = verifying_key_path.string();
    out_status.proving_key_path = proving_key_path.string();

    try {
        const bool has_manifest = fs::exists(manifest_path) && fs::is_regular_file(manifest_path);
        const bool has_vk = fs::exists(verifying_key_path) && fs::is_regular_file(verifying_key_path);
        const bool has_pk = fs::exists(proving_key_path) && fs::is_regular_file(proving_key_path);
        ParsedVerifierManifest manifest;

        if (has_vk) {
            out_status.verifying_key_bytes = static_cast<uint64_t>(fs::file_size(verifying_key_path));
        }
        if (has_pk) {
            out_status.proving_key_bytes = static_cast<uint64_t>(fs::file_size(proving_key_path));
        }

        out_status.assets_present = has_manifest && has_vk && out_status.verifying_key_bytes > 0;
        out_status.prover_assets_present = has_pk && out_status.proving_key_bytes > 0;
        if (!has_manifest) {
            out_status.status = "missing profile manifest";
            return true;
        }
        {
            std::string manifest_error;
            if (!ParseVerifierManifest(manifest_path, manifest, &manifest_error)) {
                out_status.assets_present = false;
                out_status.prover_assets_present = false;
                out_status.backend_ready = false;
                out_status.status = manifest_error;
                return true;
            }
        }
        out_status.profile_manifest_parsed = true;
        out_status.profile_manifest_name = manifest.profile_name;
        out_status.profile_manifest_backend = manifest.backend_name;
        out_status.valid_proof_vector_count = static_cast<uint64_t>(manifest.valid_vector_files.size());
        out_status.invalid_proof_vector_count = static_cast<uint64_t>(manifest.invalid_vector_files.size());
        out_status.profile_manifest_public_input_count = static_cast<uint64_t>(manifest.public_inputs.size());
        out_status.profile_manifest_public_inputs = manifest.public_inputs;

        for (const auto& relpath : manifest.valid_vector_files) {
            out_status.valid_proof_vector_paths.push_back((artifact_dir / relpath).string());
        }
        for (const auto& relpath : manifest.invalid_vector_files) {
            out_status.invalid_proof_vector_paths.push_back((artifact_dir / relpath).string());
        }

        const std::string expected_profile_name =
            supported.profile_name == nullptr ? "" : supported.profile_name;
        out_status.profile_manifest_name_matches =
            !manifest.profile_name.empty() && manifest.profile_name == expected_profile_name;
        if (!out_status.profile_manifest_name_matches) {
            out_status.assets_present = false;
            out_status.prover_assets_present = false;
            out_status.backend_ready = false;
            out_status.status = "profile manifest name does not match supported profile";
            return true;
        }

        const std::string expected_backend_name =
            supported.verifier_backend == nullptr ? "" : supported.verifier_backend;
        out_status.profile_manifest_backend_matches =
            manifest.backend_name.empty() || manifest.backend_name == expected_backend_name;
        if (!out_status.profile_manifest_backend_matches) {
            out_status.assets_present = false;
            out_status.prover_assets_present = false;
            out_status.backend_ready = false;
            out_status.status = "profile manifest backend does not match supported profile";
            return true;
        }

        out_status.profile_manifest_tuple_matches =
            manifest.has_consensus_tuple &&
            manifest.version == supported.version &&
            manifest.proof_system_id == supported.proof_system_id &&
            manifest.circuit_family_id == supported.circuit_family_id &&
            manifest.verifier_id == supported.verifier_id &&
            manifest.public_input_version == supported.public_input_version &&
            manifest.state_root_format == supported.state_root_format &&
            manifest.deposit_message_format == supported.deposit_message_format &&
            manifest.withdrawal_leaf_format == supported.withdrawal_leaf_format &&
            manifest.balance_leaf_format == supported.balance_leaf_format &&
            manifest.data_availability_mode == supported.data_availability_mode;
        if (!out_status.profile_manifest_tuple_matches) {
            out_status.assets_present = false;
            out_status.prover_assets_present = false;
            out_status.backend_ready = false;
            out_status.status = "profile manifest consensus tuple does not match supported profile";
            return true;
        }

        const std::vector<std::string> expected_public_inputs = ExpectedManifestPublicInputs(supported);
        out_status.profile_manifest_public_inputs_match =
            !expected_public_inputs.empty() &&
            manifest.public_inputs == expected_public_inputs;
        if (!expected_public_inputs.empty() && !out_status.profile_manifest_public_inputs_match) {
            out_status.assets_present = false;
            out_status.prover_assets_present = false;
            out_status.backend_ready = false;
            out_status.status = "profile manifest public inputs do not match supported profile";
            return true;
        }

        out_status.profile_manifest_key_layout_matches =
            manifest.verifying_key_file.empty() ||
            manifest.verifying_key_file == fs::path(VERIFIER_BATCH_VK).string();
        if (!out_status.profile_manifest_key_layout_matches ||
            (!manifest.proving_key_file.empty() &&
             manifest.proving_key_file != fs::path(VERIFIER_BATCH_PK).string())) {
            out_status.assets_present = false;
            out_status.prover_assets_present = false;
            out_status.backend_ready = false;
            out_status.status = "profile manifest key layout does not match expected artifact names";
            return true;
        }

        out_status.valid_proof_vectors_present = !manifest.valid_vector_files.empty();
        for (const auto& relpath : manifest.valid_vector_files) {
            const fs::path candidate = artifact_dir / relpath;
            if (!fs::exists(candidate) || !fs::is_regular_file(candidate) || fs::file_size(candidate) == 0) {
                out_status.valid_proof_vectors_present = false;
                break;
            }
        }

        out_status.invalid_proof_vectors_present = !manifest.invalid_vector_files.empty();
        for (const auto& relpath : manifest.invalid_vector_files) {
            const fs::path candidate = artifact_dir / relpath;
            if (!fs::exists(candidate) || !fs::is_regular_file(candidate) || fs::file_size(candidate) == 0) {
                out_status.invalid_proof_vectors_present = false;
                break;
            }
        }

        if (!has_vk || out_status.verifying_key_bytes == 0) {
            out_status.status = "missing verifying key";
            return true;
        }
        if (manifest.placeholder ||
            FileContainsPlaceholderSentinel(manifest_path) ||
            FileContainsPlaceholderSentinel(verifying_key_path)) {
            out_status.assets_present = false;
            out_status.status = "placeholder verifier artifacts only";
            return true;
        }
        if (supported.verifier_backend != nullptr &&
            std::string(supported.verifier_backend) == "native_blst_groth16") {
            if (!out_status.native_backend_available) {
                out_status.status =
                    out_status.native_backend_status.empty() ? "native blst backend unavailable" : out_status.native_backend_status;
                return true;
            }
            if (!out_status.native_backend_self_test_passed) {
                out_status.status =
                    out_status.native_backend_status.empty() ? "native blst backend self-test failed" : out_status.native_backend_status;
                return true;
            }
            ValiditySidechainGroth16VerificationKey verifying_key;
            std::string key_error;
            if (!LoadValiditySidechainGroth16VerificationKey(
                    verifying_key_path,
                    static_cast<uint32_t>(expected_public_inputs.size()),
                    verifying_key,
                    &key_error)) {
                out_status.assets_present = false;
                out_status.prover_assets_present = false;
                out_status.status = key_error;
                return true;
            }
            out_status.backend_ready = true;
            out_status.status = "native blst Groth16 verifier ready";
            return true;
        }
        if (supported.profile_name != nullptr &&
            std::string(supported.profile_name) == TOY_PROFILE_NAME) {
#ifdef HAVE_BOOST_PROCESS
            out_status.verifier_command_configured = !gArgs.GetArg("-validityverifiercommand", "").empty();
            out_status.prover_command_configured = !gArgs.GetArg("-validityprovercommand", "").empty();
            if (!out_status.verifier_command_configured) {
                out_status.status = "verifier command not configured";
                return true;
            }
            out_status.backend_ready = true;
            if (!out_status.prover_assets_present) {
                out_status.status = "external gnark verifier command configured; proving key missing for auto-prover";
                return true;
            }
            out_status.status = "external gnark verifier command configured";
            return true;
#else
            out_status.status = "boost process support not built";
            return true;
#endif
        }

        out_status.backend_ready = false;
        out_status.status = "assets found but Groth16 verifier backend is not implemented";
        return true;
    } catch (const fs::filesystem_error& e) {
        out_status.assets_present = false;
        out_status.prover_assets_present = false;
        out_status.backend_ready = false;
        out_status.status = fsbridge::get_filesystem_error_message(e);
        return false;
    }
}

static UniValue BatchPublicInputsToJSON(const ValiditySidechainBatchPublicInputs& public_inputs)
{
    UniValue inputs(UniValue::VOBJ);
    inputs.pushKV("batch_number", static_cast<int64_t>(public_inputs.batch_number));
    inputs.pushKV("prior_state_root", public_inputs.prior_state_root.GetHex());
    inputs.pushKV("new_state_root", public_inputs.new_state_root.GetHex());
    inputs.pushKV("l1_message_root_before", public_inputs.l1_message_root_before.GetHex());
    inputs.pushKV("l1_message_root_after", public_inputs.l1_message_root_after.GetHex());
    inputs.pushKV("consumed_queue_messages", static_cast<int64_t>(public_inputs.consumed_queue_messages));
    inputs.pushKV("queue_prefix_commitment", public_inputs.queue_prefix_commitment.GetHex());
    inputs.pushKV("withdrawal_root", public_inputs.withdrawal_root.GetHex());
    inputs.pushKV("data_root", public_inputs.data_root.GetHex());
    inputs.pushKV("data_size", static_cast<int64_t>(public_inputs.data_size));
    return inputs;
}

static bool ExtractExternalCommandResult(
    const UniValue& result,
    const char* success_key,
    std::string* error)
{
    const UniValue& ok = find_value(result, success_key);
    if (!ok.isBool()) {
        return FailValidation(error, "external verifier command returned malformed JSON");
    }
    if (ok.get_bool()) {
        return true;
    }

    const UniValue& external_error = find_value(result, "error");
    if (external_error.isStr()) {
        return FailValidation(error, external_error.get_str().c_str());
    }
    return FailValidation(error, "external verifier command rejected proof");
}

static bool VerifyValiditySidechainBatchWithExternalCommand(
    const SupportedValiditySidechainConfig& supported,
    uint8_t sidechain_id,
    const ValiditySidechainBatchPublicInputs& public_inputs,
    const std::vector<unsigned char>& proof_bytes,
    std::string* error)
{
#ifndef HAVE_BOOST_PROCESS
    return FailValidation(error, "external verifier command backend is unavailable in this build");
#else
    const std::string command = gArgs.GetArg("-validityverifiercommand", "");
    if (command.empty()) {
        return FailValidation(error, "external verifier command is not configured");
    }

    UniValue request(UniValue::VOBJ);
    request.pushKV("profile_name", supported.profile_name == nullptr ? "" : supported.profile_name);
    request.pushKV("artifact_dir", ResolveVerifierArtifactDir(supported).string());
    request.pushKV("sidechain_id", static_cast<int64_t>(sidechain_id));
    request.pushKV("public_inputs", BatchPublicInputsToJSON(public_inputs));
    request.pushKV("proof_bytes_hex", HexStr(proof_bytes));

    try {
        const UniValue result = RunCommandParseJSON(command, request.write());
        return ExtractExternalCommandResult(result, "ok", error);
    } catch (const std::exception& e) {
        if (error != nullptr) {
            *error = e.what();
        }
        return false;
    }
#endif
}

static UniValue DataChunksToJSON(const std::vector<std::vector<unsigned char>>& data_chunks)
{
    UniValue chunks(UniValue::VARR);
    for (const auto& chunk : data_chunks) {
        chunks.push_back(HexStr(chunk));
    }
    return chunks;
}

static UniValue ConsumedQueueEntriesToJSON(const std::vector<ValiditySidechainQueueEntry>& consumed_queue_entries)
{
    UniValue entries(UniValue::VARR);
    for (const auto& entry : consumed_queue_entries) {
        UniValue encoded(UniValue::VOBJ);
        encoded.pushKV("queue_index", static_cast<int64_t>(entry.queue_index));
        encoded.pushKV("message_kind", static_cast<int64_t>(entry.message_kind));
        encoded.pushKV("message_id", entry.message_id.GetHex());
        encoded.pushKV("message_hash", entry.message_hash.GetHex());
        entries.push_back(encoded);
    }
    return entries;
}

static UniValue WithdrawalLeavesToJSON(const std::vector<ValiditySidechainWithdrawalLeaf>& withdrawal_leaves)
{
    UniValue leaves(UniValue::VARR);
    for (const auto& leaf : withdrawal_leaves) {
        UniValue encoded(UniValue::VOBJ);
        encoded.pushKV("withdrawal_id", leaf.withdrawal_id.GetHex());
        encoded.pushKV("amount", FormatMoney(leaf.amount));
        encoded.pushKV("destination_commitment", leaf.destination_commitment.GetHex());
        leaves.push_back(encoded);
    }
    return leaves;
}

static std::array<unsigned char, 32> EncodeGroth16ScalarLE(uint32_t value)
{
    std::array<unsigned char, 32> encoded{};
    encoded[0] = static_cast<unsigned char>(value & 0xff);
    encoded[1] = static_cast<unsigned char>((value >> 8) & 0xff);
    encoded[2] = static_cast<unsigned char>((value >> 16) & 0xff);
    encoded[3] = static_cast<unsigned char>((value >> 24) & 0xff);
    return encoded;
}

static std::array<unsigned char, 32> EncodeGroth16ScalarLE(const uint256& value)
{
    std::array<unsigned char, 32> encoded{};
    std::copy(value.begin(), value.end(), encoded.begin());
    return encoded;
}

static std::array<unsigned char, 32> EncodeGroth16ScalarLE128Limb(
    const uint256& value,
    size_t limb_index)
{
    std::array<unsigned char, 32> scalar{};
    const size_t byte_offset = limb_index * GROTH16_DECOMPOSED_LIMB_BYTES;
    if (byte_offset >= UINT256_SERIALIZED_SIZE) {
        return scalar;
    }

    std::copy_n(
        value.begin() + byte_offset,
        GROTH16_DECOMPOSED_LIMB_BYTES,
        scalar.begin());
    return scalar;
}

static bool ResolveUint256Groth16Input(
    const std::string& input_name,
    const char* base_name,
    const uint256& value,
    std::array<unsigned char, 32>& out_input_le)
{
    if (input_name == base_name) {
        out_input_le = EncodeGroth16ScalarLE(value);
        return true;
    }

    const std::string low_name = std::string(base_name) + "_lo";
    if (input_name == low_name) {
        out_input_le = EncodeGroth16ScalarLE128Limb(value, /* limb_index= */ 0);
        return true;
    }

    const std::string high_name = std::string(base_name) + "_hi";
    if (input_name == high_name) {
        out_input_le = EncodeGroth16ScalarLE128Limb(value, /* limb_index= */ 1);
        return true;
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
    if (supported->scaffolding_only &&
        supported->profile_name != nullptr &&
        std::string(supported->profile_name) == "scaffold_transition_da_v1") {
        return ValiditySidechainBatchVerifierMode::SCAFFOLD_TRANSITION_COMMITMENT;
    }
    if (!supported->scaffolding_only &&
        supported->profile_name != nullptr &&
        std::string(supported->profile_name) == TOY_PROFILE_NAME) {
        return ValiditySidechainBatchVerifierMode::GNARK_GROTH16_TOY_BATCH_TRANSITION_V1;
    }
    if (!supported->scaffolding_only &&
        supported->profile_name != nullptr &&
        std::string(supported->profile_name) == NATIVE_TOY_PROFILE_NAME) {
        return ValiditySidechainBatchVerifierMode::NATIVE_GROTH16_TOY_BATCH_TRANSITION_V1;
    }
    if (!supported->scaffolding_only &&
        supported->profile_name != nullptr &&
        std::string(supported->profile_name) == POSEIDON_PROFILE_NAME) {
        return ValiditySidechainBatchVerifierMode::GROTH16_BLS12_381_POSEIDON_V1;
    }
    if (!supported->scaffolding_only &&
        supported->profile_name != nullptr &&
        std::string(supported->profile_name) == POSEIDON_PROFILE_NAME_V2) {
        return ValiditySidechainBatchVerifierMode::GROTH16_BLS12_381_POSEIDON_V2;
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
        case ValiditySidechainBatchVerifierMode::GROTH16_BLS12_381_POSEIDON_V2:
            return "groth16_bls12_381_poseidon_v2";
        case ValiditySidechainBatchVerifierMode::GNARK_GROTH16_TOY_BATCH_TRANSITION_V1:
            return "gnark_groth16_toy_batch_transition_v1";
        case ValiditySidechainBatchVerifierMode::NATIVE_GROTH16_TOY_BATCH_TRANSITION_V1:
            return "native_blst_groth16_toy_batch_transition_v1";
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

bool BuildValiditySidechainBatchProofWithExternalProver(
    const ValiditySidechainConfig& config,
    uint8_t sidechain_id,
    const ValiditySidechainBatchPublicInputs& public_inputs,
    const std::vector<ValiditySidechainQueueEntry>& consumed_queue_entries,
    const std::vector<ValiditySidechainWithdrawalLeaf>& withdrawal_leaves,
    const std::vector<std::vector<unsigned char>>& data_chunks,
    std::vector<unsigned char>& out_proof_bytes,
    std::string* error)
{
    out_proof_bytes.clear();

    const SupportedValiditySidechainConfig* supported = FindSupportedValiditySidechainConfig(config);
    if (supported == nullptr) {
        return FailValidation(error, "unsupported proof configuration tuple");
    }
    if (!supported->supports_external_prover) {
        return FailValidation(error, "external prover is not supported for this profile");
    }
    if (IsValiditySidechainSingleEntryExperimentalQueueProfile(config) &&
        consumed_queue_entries.size() > 1) {
        return FailValidation(error, "experimental real profile supports at most one consumed queue entry for auto prover");
    }
    if (IsValiditySidechainSingleEntryExperimentalQueueProfile(config)) {
        for (const auto& entry : consumed_queue_entries) {
            if (entry.message_kind != ValiditySidechainQueueEntry::MESSAGE_DEPOSIT) {
                return FailValidation(error, "experimental real profile supports consumed deposit queue entries only for auto prover");
            }
        }
    }
    if (IsValiditySidechainSingleLeafExperimentalWithdrawalProfile(config) &&
        withdrawal_leaves.size() > 1) {
        return FailValidation(error, "experimental real profile supports at most one withdrawal leaf witness for auto prover");
    }
    {
        const std::vector<std::string> expected_public_inputs = ExpectedManifestPublicInputs(*supported);
        if (!expected_public_inputs.empty()) {
            std::vector<std::array<unsigned char, 32>> encoded_public_inputs;
            if (!BuildValiditySidechainGroth16PublicInputs(
                    expected_public_inputs,
                    sidechain_id,
                    public_inputs,
                    encoded_public_inputs,
                    error)) {
                return false;
            }
        }
    }

    ValiditySidechainVerifierAssetsStatus assets_status;
    GetValiditySidechainVerifierAssetsStatus(config, assets_status);
    if (!assets_status.assets_present) {
        return FailValidation(
            error,
            assets_status.status.empty() ? "proving key missing for supported profile" : assets_status.status.c_str());
    }
    if (!assets_status.prover_assets_present) {
        return FailValidation(error, "proving key missing for supported profile");
    }

#ifndef HAVE_BOOST_PROCESS
    return FailValidation(error, "external prover command backend is unavailable in this build");
#else
    const std::string command = gArgs.GetArg("-validityprovercommand", "");
    if (command.empty()) {
        return FailValidation(error, "external prover command is not configured");
    }

    UniValue request(UniValue::VOBJ);
    request.pushKV("profile_name", supported->profile_name == nullptr ? "" : supported->profile_name);
    request.pushKV("artifact_dir", ResolveVerifierArtifactDir(*supported).string());
    request.pushKV("sidechain_id", static_cast<int64_t>(sidechain_id));
    request.pushKV("public_inputs", BatchPublicInputsToJSON(public_inputs));
    request.pushKV("consumed_queue_entries", ConsumedQueueEntriesToJSON(consumed_queue_entries));
    request.pushKV("withdrawal_leaves", WithdrawalLeavesToJSON(withdrawal_leaves));
    request.pushKV("data_chunks_hex", DataChunksToJSON(data_chunks));

    try {
        const UniValue result = RunCommandParseJSON(command, request.write());
        const UniValue& proof_hex = find_value(result, "proof_bytes_hex");
        if (!proof_hex.isStr()) {
            const UniValue& prover_error = find_value(result, "error");
            if (prover_error.isStr()) {
                return FailValidation(error, prover_error.get_str().c_str());
            }
            return FailValidation(error, "external prover command returned malformed JSON");
        }
        out_proof_bytes = ParseHex(proof_hex.get_str());
        if (out_proof_bytes.empty()) {
            return FailValidation(error, "external prover returned empty proof bytes");
        }
        return true;
    } catch (const std::exception& e) {
        if (error != nullptr) {
            *error = e.what();
        }
        return false;
    }
#endif
}

bool BuildValiditySidechainGroth16PublicInputs(
    const std::vector<std::string>& public_input_names,
    uint8_t sidechain_id,
    const ValiditySidechainBatchPublicInputs& public_inputs,
    std::vector<std::array<unsigned char, 32>>& out_public_inputs_le,
    std::string* error)
{
    out_public_inputs_le.clear();
    out_public_inputs_le.reserve(public_input_names.size());

    for (const auto& input_name : public_input_names) {
        std::array<unsigned char, 32> encoded_input{};
        bool recognized_input = false;

        if (input_name == "sidechain_id") {
            encoded_input = EncodeGroth16ScalarLE(static_cast<uint32_t>(sidechain_id));
            recognized_input = true;
        }
        if (!recognized_input && input_name == "batch_number") {
            encoded_input = EncodeGroth16ScalarLE(public_inputs.batch_number);
            recognized_input = true;
        }
        if (!recognized_input && input_name == "consumed_queue_messages") {
            encoded_input = EncodeGroth16ScalarLE(public_inputs.consumed_queue_messages);
            recognized_input = true;
        }
        if (!recognized_input && input_name == "data_size") {
            encoded_input = EncodeGroth16ScalarLE(public_inputs.data_size);
            recognized_input = true;
        }
        if (!recognized_input &&
            (ResolveUint256Groth16Input(input_name, "prior_state_root", public_inputs.prior_state_root, encoded_input) ||
             ResolveUint256Groth16Input(input_name, "new_state_root", public_inputs.new_state_root, encoded_input) ||
             ResolveUint256Groth16Input(input_name, "l1_message_root_before", public_inputs.l1_message_root_before, encoded_input) ||
             ResolveUint256Groth16Input(input_name, "l1_message_root_after", public_inputs.l1_message_root_after, encoded_input) ||
             ResolveUint256Groth16Input(input_name, "queue_prefix_commitment", public_inputs.queue_prefix_commitment, encoded_input) ||
             ResolveUint256Groth16Input(input_name, "withdrawal_root", public_inputs.withdrawal_root, encoded_input) ||
             ResolveUint256Groth16Input(input_name, "data_root", public_inputs.data_root, encoded_input))) {
            recognized_input = true;
        }

        if (!recognized_input) {
            if (error != nullptr) {
                *error = "unsupported Groth16 public input name: " + input_name;
            }
            out_public_inputs_le.clear();
            return false;
        }

        if (!ValidateValiditySidechainGroth16ScalarFieldElement(encoded_input, nullptr)) {
            if (error != nullptr) {
                *error = "Groth16 public input " + input_name + " does not fit BLS12-381 scalar field";
            }
            out_public_inputs_le.clear();
            return false;
        }

        out_public_inputs_le.push_back(encoded_input);
    }

    if (error != nullptr) {
        error->clear();
    }
    return true;
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
        mode != ValiditySidechainBatchVerifierMode::GNARK_GROTH16_TOY_BATCH_TRANSITION_V1 &&
        mode != ValiditySidechainBatchVerifierMode::NATIVE_GROTH16_TOY_BATCH_TRANSITION_V1 &&
        mode != ValiditySidechainBatchVerifierMode::GROTH16_BLS12_381_POSEIDON_V1 &&
        mode != ValiditySidechainBatchVerifierMode::GROTH16_BLS12_381_POSEIDON_V2) {
        return FailValidation(error, "proof verifier is not implemented for this profile");
    }

    if (mode == ValiditySidechainBatchVerifierMode::GNARK_GROTH16_TOY_BATCH_TRANSITION_V1) {
        const SupportedValiditySidechainConfig* supported = FindSupportedValiditySidechainConfig(config);
        if (supported == nullptr) {
            return FailValidation(error, "unsupported proof configuration tuple");
        }
        ValiditySidechainVerifierAssetsStatus assets_status;
        GetValiditySidechainVerifierAssetsStatus(config, assets_status);
        if (!assets_status.assets_present || !assets_status.backend_ready) {
            return FailValidation(
                error,
                assets_status.status.empty() ? "verifier assets missing for supported profile" : assets_status.status.c_str());
        }
        return VerifyValiditySidechainBatchWithExternalCommand(
            *supported,
            sidechain_id,
            public_inputs,
            proof_bytes,
            error);
    }

    if (mode == ValiditySidechainBatchVerifierMode::GROTH16_BLS12_381_POSEIDON_V1 ||
        mode == ValiditySidechainBatchVerifierMode::GROTH16_BLS12_381_POSEIDON_V2) {
        const SupportedValiditySidechainConfig* supported = FindSupportedValiditySidechainConfig(config);
        if (supported == nullptr) {
            return FailValidation(error, "unsupported proof configuration tuple");
        }
        ValiditySidechainVerifierAssetsStatus assets_status;
        GetValiditySidechainVerifierAssetsStatus(config, assets_status);
        if (!assets_status.assets_present || !assets_status.backend_ready) {
            return FailValidation(
                error,
                assets_status.status.empty() ? "verifier assets missing for supported profile" : assets_status.status.c_str());
        }
        ValiditySidechainGroth16Proof proof;
        if (!ParseValiditySidechainGroth16Proof(proof_bytes, proof, error)) {
            return false;
        }
        const std::vector<std::string> expected_public_inputs = ExpectedManifestPublicInputs(*supported);
        ValiditySidechainGroth16VerificationKey verifying_key;
        if (!LoadValiditySidechainGroth16VerificationKey(
                ResolveVerifierArtifactDir(*supported) / VERIFIER_BATCH_VK,
                static_cast<uint32_t>(expected_public_inputs.size()),
                verifying_key,
                error)) {
            return false;
        }
        std::vector<std::array<unsigned char, 32>> encoded_public_inputs;
        if (!BuildValiditySidechainGroth16PublicInputs(
                expected_public_inputs,
                sidechain_id,
                public_inputs,
                encoded_public_inputs,
                error)) {
            return false;
        }
        return VerifyValiditySidechainGroth16Proof(
            verifying_key,
            proof,
            encoded_public_inputs,
            error);
    }

    if (mode == ValiditySidechainBatchVerifierMode::NATIVE_GROTH16_TOY_BATCH_TRANSITION_V1) {
        const SupportedValiditySidechainConfig* supported = FindSupportedValiditySidechainConfig(config);
        if (supported == nullptr) {
            return FailValidation(error, "unsupported proof configuration tuple");
        }
        ValiditySidechainVerifierAssetsStatus assets_status;
        GetValiditySidechainVerifierAssetsStatus(config, assets_status);
        if (!assets_status.assets_present || !assets_status.backend_ready) {
            return FailValidation(
                error,
                assets_status.status.empty() ? "verifier assets missing for supported profile" : assets_status.status.c_str());
        }
        ValiditySidechainGroth16Proof proof;
        if (!ParseValiditySidechainGroth16Proof(proof_bytes, proof, error)) {
            return false;
        }
        const std::vector<std::string> expected_public_inputs = ExpectedManifestPublicInputs(*supported);
        ValiditySidechainGroth16VerificationKey verifying_key;
        if (!LoadValiditySidechainGroth16VerificationKey(
                ResolveVerifierArtifactDir(*supported) / VERIFIER_BATCH_VK,
                static_cast<uint32_t>(expected_public_inputs.size()),
                verifying_key,
                error)) {
            return false;
        }
        std::vector<std::array<unsigned char, 32>> encoded_public_inputs;
        if (!BuildValiditySidechainGroth16PublicInputs(
                expected_public_inputs,
                sidechain_id,
                public_inputs,
                encoded_public_inputs,
                error)) {
            return false;
        }
        return VerifyValiditySidechainGroth16Proof(
            verifying_key,
            proof,
            encoded_public_inputs,
            error);
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
