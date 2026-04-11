// Copyright (c) 2026 AllSageTech, LLC
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VALIDITYSIDECHAIN_VERIFIER_H
#define BITCOIN_VALIDITYSIDECHAIN_VERIFIER_H

#include <uint256.h>
#include <validitysidechain/state.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

enum class ValiditySidechainBatchVerifierMode : uint8_t {
    DISABLED = 0,
    SCAFFOLD_QUEUE_PREFIX_ONLY = 1,
    SCAFFOLD_TRANSITION_COMMITMENT = 2,
    GROTH16_BLS12_381_POSEIDON_V1 = 3,
    GNARK_GROTH16_TOY_BATCH_TRANSITION_V1 = 4,
    NATIVE_GROTH16_TOY_BATCH_TRANSITION_V1 = 5,
    GROTH16_BLS12_381_POSEIDON_V2 = 6,
};

struct ValiditySidechainVerifierAssetsStatus
{
    bool requires_external_assets{false};
    bool assets_present{false};
    bool prover_assets_present{false};
    bool backend_ready{false};
    bool native_backend_available{false};
    bool native_backend_self_test_passed{false};
    bool verifier_command_configured{false};
    bool prover_command_configured{false};
    bool profile_manifest_parsed{false};
    bool profile_manifest_name_matches{false};
    bool profile_manifest_backend_matches{false};
    bool profile_manifest_key_layout_matches{false};
    bool profile_manifest_tuple_matches{false};
    bool profile_manifest_public_inputs_match{false};
    bool valid_proof_vectors_present{false};
    bool invalid_proof_vectors_present{false};
    std::string artifact_name;
    std::string artifact_dir;
    std::string backend_name;
    std::string profile_manifest_path;
    std::string profile_manifest_name;
    std::string profile_manifest_backend;
    std::string verifying_key_path;
    std::string proving_key_path;
    uint64_t verifying_key_bytes{0};
    uint64_t proving_key_bytes{0};
    uint64_t native_backend_pairing_context_bytes{0};
    uint64_t valid_proof_vector_count{0};
    uint64_t invalid_proof_vector_count{0};
    uint64_t profile_manifest_public_input_count{0};
    std::vector<std::string> valid_proof_vector_paths;
    std::vector<std::string> invalid_proof_vector_paths;
    std::vector<std::string> profile_manifest_public_inputs;
    std::string native_backend_status;
    std::string status;
};

ValiditySidechainBatchVerifierMode GetValiditySidechainBatchVerifierMode(const ValiditySidechainConfig& config);
const char* ValiditySidechainBatchVerifierModeToString(ValiditySidechainBatchVerifierMode mode);
uint256 ComputeValiditySidechainDataRoot(const std::vector<std::vector<unsigned char>>& data_chunks);
bool ValidateValiditySidechainPublishedBatchData(
    const ValiditySidechainConfig& config,
    const ValiditySidechainBatchPublicInputs& public_inputs,
    const std::vector<std::vector<unsigned char>>& data_chunks,
    std::string* error = nullptr);
bool GetValiditySidechainVerifierAssetsStatus(
    const ValiditySidechainConfig& config,
    ValiditySidechainVerifierAssetsStatus& out_status);
std::vector<unsigned char> BuildValiditySidechainScaffoldBatchProof(
    uint8_t sidechain_id,
    const ValiditySidechainBatchPublicInputs& public_inputs,
    const uint256& current_state_root,
    const uint256& current_withdrawal_root,
    const uint256& current_data_root,
    const uint256& current_l1_message_root);
bool BuildValiditySidechainBatchProofWithExternalProver(
    const ValiditySidechainConfig& config,
    uint8_t sidechain_id,
    const ValiditySidechainBatchPublicInputs& public_inputs,
    const uint256& current_state_root,
    const uint256& current_withdrawal_root,
    const uint256& current_data_root,
    const uint256& current_l1_message_root,
    const std::vector<ValiditySidechainQueueEntry>& consumed_queue_entries,
    bool withdrawal_leaves_supplied,
    const std::vector<ValiditySidechainWithdrawalLeaf>& withdrawal_leaves,
    const std::vector<std::vector<unsigned char>>& data_chunks,
    std::vector<unsigned char>& out_proof_bytes,
    std::string* error = nullptr);
bool BuildValiditySidechainGroth16PublicInputs(
    const std::vector<std::string>& public_input_names,
    uint8_t sidechain_id,
    const ValiditySidechainBatchPublicInputs& public_inputs,
    std::vector<std::array<unsigned char, 32>>& out_public_inputs_le,
    std::string* error = nullptr);
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
    std::string* error = nullptr,
    ValiditySidechainBatchVerifierMode* mode_out = nullptr);

#endif // BITCOIN_VALIDITYSIDECHAIN_VERIFIER_H
