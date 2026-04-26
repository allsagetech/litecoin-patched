// Copyright (c) 2026 AllSageTech, LLC
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VALIDITYSIDECHAIN_REGISTRY_H
#define BITCOIN_VALIDITYSIDECHAIN_REGISTRY_H

#include <validitysidechain/state.h>

#include <cstddef>
#include <string>
#include <vector>

static constexpr size_t VALIDITY_SIDECHAIN_COMMITTED_DATA_WITNESS_MAX_CHUNK_BYTES = 64;

struct SupportedValiditySidechainConfig
{
    const char* profile_name{nullptr};
    const char* verifier_artifact_name{nullptr};
    const char* verifier_backend{nullptr};
    bool scaffolding_only{true};
    bool requires_external_verifier_assets{false};
    bool supports_external_prover{false};
    uint8_t version{1};
    uint8_t proof_system_id{0};
    uint8_t circuit_family_id{0};
    uint8_t verifier_id{0};
    uint8_t public_input_version{0};
    uint8_t state_root_format{0};
    uint8_t deposit_message_format{0};
    uint8_t withdrawal_leaf_format{0};
    uint8_t balance_leaf_format{0};
    uint8_t data_availability_mode{0};
    uint32_t max_batch_data_bytes_limit{0};
    uint32_t max_proof_bytes_limit{0};
    uint32_t min_force_inclusion_delay{0};
    uint32_t max_force_inclusion_delay{0};
    uint32_t min_deposit_reclaim_delay{0};
    uint32_t max_deposit_reclaim_delay{0};
    uint32_t min_escape_hatch_delay{0};
    uint32_t max_escape_hatch_delay{0};
};

const std::vector<SupportedValiditySidechainConfig>& GetSupportedValiditySidechainConfigs();
const SupportedValiditySidechainConfig* FindSupportedValiditySidechainConfig(const ValiditySidechainConfig& config);
bool ValidateValiditySidechainConfig(const ValiditySidechainConfig& config, std::string* error = nullptr);
bool IsValiditySidechainScaffoldingOnlyProfile(const ValiditySidechainConfig& config);
const SupportedValiditySidechainConfig* GetCanonicalValiditySidechainConfig();
const SupportedValiditySidechainConfig* GetRecommendedValiditySidechainConfig();
bool IsCanonicalValiditySidechainProfile(const ValiditySidechainConfig& config);
bool IsRecommendedValiditySidechainProfile(const ValiditySidechainConfig& config);
bool IsValiditySidechainRegistrationDefaultAllowedProfile(const ValiditySidechainConfig& config);
const char* GetValiditySidechainProfileLifecycle(const ValiditySidechainConfig& config);
const char* GetValiditySidechainDepositAdmissionMode(const ValiditySidechainConfig& config);
bool IsValiditySidechainSingleEntryBoundedQueueWitnessProfile(const ValiditySidechainConfig& config);
bool IsValiditySidechainSingleEntryExperimentalQueueProfile(const ValiditySidechainConfig& config);
uint32_t GetValiditySidechainBatchCommittedQueueWitnessLimit(const ValiditySidechainConfig& config);
bool AllowsValiditySidechainForceExitRequests(const ValiditySidechainConfig& config);
const char* GetValiditySidechainForceExitRequestMode(const ValiditySidechainConfig& config);
bool RequiresValiditySidechainExternalProverCurrentChainstate(const ValiditySidechainConfig& config);
bool RequiresValiditySidechainExternalProverExplicitWitnessVectors(const ValiditySidechainConfig& config);
const char* GetValiditySidechainDerivedPublicInputMode(const ValiditySidechainConfig& config);
const char* GetValiditySidechainExternalProverRequestMode(const ValiditySidechainConfig& config);
bool AreValiditySidechainBatchQueueBindingsProvenInCircuit(const ValiditySidechainConfig& config);
bool AreValiditySidechainBatchWithdrawalBindingsProvenInCircuit(const ValiditySidechainConfig& config);
bool AreValiditySidechainBatchDataBindingsProvenInCircuit(const ValiditySidechainConfig& config);
const char* GetValiditySidechainInCircuitBindingBlocker(const ValiditySidechainConfig& config);
const char* GetValiditySidechainBatchQueueBindingMode(const ValiditySidechainConfig& config);
bool IsValiditySidechainSingleLeafBoundedWithdrawalWitnessProfile(const ValiditySidechainConfig& config);
bool IsValiditySidechainSingleLeafExperimentalWithdrawalProfile(const ValiditySidechainConfig& config);
uint32_t GetValiditySidechainBatchCommittedWithdrawalWitnessLimit(const ValiditySidechainConfig& config);
uint32_t GetValiditySidechainBatchCommittedDataChunkWitnessLimit(const ValiditySidechainConfig& config);
const char* GetValiditySidechainBatchWithdrawalBindingMode(const ValiditySidechainConfig& config);
const char* GetValiditySidechainVerifiedWithdrawalExecutionMode(const ValiditySidechainConfig& config);
bool RequiresValiditySidechainEscapeExitStateProofs(const ValiditySidechainConfig& config);
const char* GetValiditySidechainEscapeExitExecutionMode(const ValiditySidechainConfig& config);
const char* GetValiditySidechainEscapeExitRpcInputMode(const ValiditySidechainConfig& config);

#endif // BITCOIN_VALIDITYSIDECHAIN_REGISTRY_H
