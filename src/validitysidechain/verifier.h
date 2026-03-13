// Copyright (c) 2026 AllSageTech, LLC
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VALIDITYSIDECHAIN_VERIFIER_H
#define BITCOIN_VALIDITYSIDECHAIN_VERIFIER_H

#include <uint256.h>
#include <validitysidechain/state.h>

#include <cstdint>
#include <string>
#include <vector>

enum class ValiditySidechainBatchVerifierMode : uint8_t {
    DISABLED = 0,
    SCAFFOLD_QUEUE_PREFIX_ONLY = 1,
    SCAFFOLD_TRANSITION_COMMITMENT = 2,
    GROTH16_BLS12_381_POSEIDON_V1 = 3,
};

struct ValiditySidechainVerifierAssetsStatus
{
    bool requires_external_assets{false};
    bool assets_present{false};
    bool backend_ready{false};
    std::string artifact_name;
    std::string artifact_dir;
    std::string profile_manifest_path;
    std::string verifying_key_path;
    uint64_t verifying_key_bytes{0};
    std::string status;
};

ValiditySidechainBatchVerifierMode GetValiditySidechainBatchVerifierMode(const ValiditySidechainConfig& config);
const char* ValiditySidechainBatchVerifierModeToString(ValiditySidechainBatchVerifierMode mode);
uint256 ComputeValiditySidechainDataRoot(const std::vector<std::vector<unsigned char>>& data_chunks);
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
