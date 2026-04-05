// Copyright (c) 2026 AllSageTech, LLC
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <validitysidechain/groth16.h>
#include <validitysidechain/registry.h>

#include <algorithm>

namespace {

static constexpr char POSEIDON_PROFILE_PREFIX[] = "groth16_bls12_381_poseidon_v";

static bool FailValidation(std::string* error, const char* message)
{
    if (error != nullptr) {
        *error = message;
    }
    return false;
}

static bool MatchesProfileTuple(
    const SupportedValiditySidechainConfig& supported,
    const ValiditySidechainConfig& config)
{
    return supported.version == config.version &&
           supported.proof_system_id == config.proof_system_id &&
           supported.circuit_family_id == config.circuit_family_id &&
           supported.verifier_id == config.verifier_id &&
           supported.public_input_version == config.public_input_version &&
           supported.state_root_format == config.state_root_format &&
           supported.deposit_message_format == config.deposit_message_format &&
           supported.withdrawal_leaf_format == config.withdrawal_leaf_format &&
           supported.balance_leaf_format == config.balance_leaf_format &&
           supported.data_availability_mode == config.data_availability_mode;
}

static bool IsRealGroth16PoseidonProfile(const SupportedValiditySidechainConfig& supported)
{
    return supported.profile_name != nullptr &&
           std::string(supported.profile_name).rfind(POSEIDON_PROFILE_PREFIX, 0) == 0 &&
           supported.proof_system_id == 2 &&
           supported.circuit_family_id == 1 &&
           supported.state_root_format == 2 &&
           supported.withdrawal_leaf_format == 2 &&
           supported.balance_leaf_format == 2;
}

static bool UsesDecomposedPoseidonPublicInputs(const SupportedValiditySidechainConfig& supported)
{
    return IsRealGroth16PoseidonProfile(supported) &&
           supported.public_input_version >= 5;
}

static bool IsExperimentalScalarLimitedGroth16PoseidonProfile(const SupportedValiditySidechainConfig& supported)
{
    return IsRealGroth16PoseidonProfile(supported) &&
           !UsesDecomposedPoseidonPublicInputs(supported);
}

static std::array<unsigned char, 32> Uint256ToLEBytes(const uint256& value)
{
    std::array<unsigned char, 32> bytes{};
    std::copy(value.begin(), value.end(), bytes.begin());
    return bytes;
}

} // namespace

const std::vector<SupportedValiditySidechainConfig>& GetSupportedValiditySidechainConfigs()
{
    static const std::vector<SupportedValiditySidechainConfig> supported_configs{
        {
            /* profile_name               = */ "scaffold_onchain_da_v1",
            /* verifier_artifact_name     = */ nullptr,
            /* verifier_backend           = */ "embedded_scaffold",
            /* scaffolding_only           = */ true,
            /* requires_external_verifier_assets = */ false,
            /* supports_external_prover   = */ false,
            /* version                    = */ 1,
            /* proof_system_id            = */ 1,
            /* circuit_family_id          = */ 1,
            /* verifier_id                = */ 1,
            /* public_input_version       = */ 1,
            /* state_root_format          = */ 1,
            /* deposit_message_format     = */ 1,
            /* withdrawal_leaf_format     = */ 1,
            /* balance_leaf_format        = */ 1,
            /* data_availability_mode     = */ 1,
            /* max_batch_data_bytes_limit = */ 64 * 1024,
            /* max_proof_bytes_limit      = */ 16 * 1024,
            /* min_force_inclusion_delay  = */ 12,
            /* max_force_inclusion_delay  = */ 7 * 144,
            /* min_deposit_reclaim_delay  = */ 144,
            /* max_deposit_reclaim_delay  = */ 28 * 144,
            /* min_escape_hatch_delay     = */ 288,
            /* max_escape_hatch_delay     = */ 56 * 144,
        },
        {
            /* profile_name               = */ "scaffold_transition_da_v1",
            /* verifier_artifact_name     = */ nullptr,
            /* verifier_backend           = */ "embedded_scaffold",
            /* scaffolding_only           = */ true,
            /* requires_external_verifier_assets = */ false,
            /* supports_external_prover   = */ false,
            /* version                    = */ 1,
            /* proof_system_id            = */ 1,
            /* circuit_family_id          = */ 1,
            /* verifier_id                = */ 2,
            /* public_input_version       = */ 1,
            /* state_root_format          = */ 1,
            /* deposit_message_format     = */ 1,
            /* withdrawal_leaf_format     = */ 1,
            /* balance_leaf_format        = */ 1,
            /* data_availability_mode     = */ 1,
            /* max_batch_data_bytes_limit = */ 64 * 1024,
            /* max_proof_bytes_limit      = */ 16 * 1024,
            /* min_force_inclusion_delay  = */ 12,
            /* max_force_inclusion_delay  = */ 7 * 144,
            /* min_deposit_reclaim_delay  = */ 144,
            /* max_deposit_reclaim_delay  = */ 28 * 144,
            /* min_escape_hatch_delay     = */ 288,
            /* max_escape_hatch_delay     = */ 56 * 144,
        },
        {
            /* profile_name               = */ "gnark_groth16_toy_batch_transition_v1",
            /* verifier_artifact_name     = */ "gnark_groth16_toy_batch_transition_v1",
            /* verifier_backend           = */ "external_gnark_command",
            /* scaffolding_only           = */ false,
            /* requires_external_verifier_assets = */ true,
            /* supports_external_prover   = */ true,
            /* version                    = */ 1,
            /* proof_system_id            = */ 3,
            /* circuit_family_id          = */ 2,
            /* verifier_id                = */ 1,
            /* public_input_version       = */ 3,
            /* state_root_format          = */ 1,
            /* deposit_message_format     = */ 1,
            /* withdrawal_leaf_format     = */ 1,
            /* balance_leaf_format        = */ 1,
            /* data_availability_mode     = */ 1,
            /* max_batch_data_bytes_limit = */ 64 * 1024,
            /* max_proof_bytes_limit      = */ 1024,
            /* min_force_inclusion_delay  = */ 12,
            /* max_force_inclusion_delay  = */ 7 * 144,
            /* min_deposit_reclaim_delay  = */ 144,
            /* max_deposit_reclaim_delay  = */ 28 * 144,
            /* min_escape_hatch_delay     = */ 288,
            /* max_escape_hatch_delay     = */ 56 * 144,
        },
        {
            /* profile_name               = */ "native_blst_groth16_toy_batch_transition_v1",
            /* verifier_artifact_name     = */ "native_blst_groth16_toy_batch_transition_v1",
            /* verifier_backend           = */ "native_blst_groth16",
            /* scaffolding_only           = */ false,
            /* requires_external_verifier_assets = */ true,
            /* supports_external_prover   = */ false,
            /* version                    = */ 1,
            /* proof_system_id            = */ 3,
            /* circuit_family_id          = */ 2,
            /* verifier_id                = */ 2,
            /* public_input_version       = */ 4,
            /* state_root_format          = */ 1,
            /* deposit_message_format     = */ 1,
            /* withdrawal_leaf_format     = */ 1,
            /* balance_leaf_format        = */ 1,
            /* data_availability_mode     = */ 1,
            /* max_batch_data_bytes_limit = */ 64 * 1024,
            /* max_proof_bytes_limit      = */ 1024,
            /* min_force_inclusion_delay  = */ 12,
            /* max_force_inclusion_delay  = */ 7 * 144,
            /* min_deposit_reclaim_delay  = */ 144,
            /* max_deposit_reclaim_delay  = */ 28 * 144,
            /* min_escape_hatch_delay     = */ 288,
            /* max_escape_hatch_delay     = */ 56 * 144,
        },
        {
            /* profile_name               = */ "groth16_bls12_381_poseidon_v1",
            /* verifier_artifact_name     = */ "groth16_bls12_381_poseidon_v1",
            /* verifier_backend           = */ "native_blst_groth16",
            /* scaffolding_only           = */ false,
            /* requires_external_verifier_assets = */ true,
            /* supports_external_prover   = */ true,
            /* version                    = */ 1,
            /* proof_system_id            = */ 2,
            /* circuit_family_id          = */ 1,
            /* verifier_id                = */ 1,
            /* public_input_version       = */ 2,
            /* state_root_format          = */ 2,
            /* deposit_message_format     = */ 1,
            /* withdrawal_leaf_format     = */ 2,
            /* balance_leaf_format        = */ 2,
            /* data_availability_mode     = */ 1,
            /* max_batch_data_bytes_limit = */ 64 * 1024,
            /* max_proof_bytes_limit      = */ 4 * 1024,
            /* min_force_inclusion_delay  = */ 12,
            /* max_force_inclusion_delay  = */ 7 * 144,
            /* min_deposit_reclaim_delay  = */ 144,
            /* max_deposit_reclaim_delay  = */ 28 * 144,
            /* min_escape_hatch_delay     = */ 288,
            /* max_escape_hatch_delay     = */ 56 * 144,
        },
        {
            /* profile_name               = */ "groth16_bls12_381_poseidon_v2",
            /* verifier_artifact_name     = */ "groth16_bls12_381_poseidon_v2",
            /* verifier_backend           = */ "native_blst_groth16",
            /* scaffolding_only           = */ false,
            /* requires_external_verifier_assets = */ true,
            /* supports_external_prover   = */ true,
            /* version                    = */ 1,
            /* proof_system_id            = */ 2,
            /* circuit_family_id          = */ 1,
            /* verifier_id                = */ 1,
            /* public_input_version       = */ 5,
            /* state_root_format          = */ 2,
            /* deposit_message_format     = */ 1,
            /* withdrawal_leaf_format     = */ 2,
            /* balance_leaf_format        = */ 2,
            /* data_availability_mode     = */ 1,
            /* max_batch_data_bytes_limit = */ 64 * 1024,
            /* max_proof_bytes_limit      = */ 4 * 1024,
            /* min_force_inclusion_delay  = */ 12,
            /* max_force_inclusion_delay  = */ 7 * 144,
            /* min_deposit_reclaim_delay  = */ 144,
            /* max_deposit_reclaim_delay  = */ 28 * 144,
            /* min_escape_hatch_delay     = */ 288,
            /* max_escape_hatch_delay     = */ 56 * 144,
        },
    };

    return supported_configs;
}

const SupportedValiditySidechainConfig* FindSupportedValiditySidechainConfig(const ValiditySidechainConfig& config)
{
    for (const auto& supported : GetSupportedValiditySidechainConfigs()) {
        if (MatchesProfileTuple(supported, config)) {
            return &supported;
        }
    }
    return nullptr;
}

bool ValidateValiditySidechainConfig(const ValiditySidechainConfig& config, std::string* error)
{
    if (config.version == 0) {
        return FailValidation(error, "config version must be non-zero");
    }

    const SupportedValiditySidechainConfig* supported = FindSupportedValiditySidechainConfig(config);
    if (supported == nullptr) {
        return FailValidation(error, "unsupported proof configuration tuple");
    }

    if (config.max_batch_data_bytes == 0 ||
        config.max_batch_data_bytes > supported->max_batch_data_bytes_limit) {
        return FailValidation(error, "max_batch_data_bytes exceeds supported limit");
    }
    if (config.max_proof_bytes == 0 ||
        config.max_proof_bytes > supported->max_proof_bytes_limit) {
        return FailValidation(error, "max_proof_bytes exceeds supported limit");
    }
    if (config.force_inclusion_delay < supported->min_force_inclusion_delay ||
        config.force_inclusion_delay > supported->max_force_inclusion_delay) {
        return FailValidation(error, "force_inclusion_delay outside supported range");
    }
    if (config.deposit_reclaim_delay < supported->min_deposit_reclaim_delay ||
        config.deposit_reclaim_delay > supported->max_deposit_reclaim_delay) {
        return FailValidation(error, "deposit_reclaim_delay outside supported range");
    }
    if (config.escape_hatch_delay < supported->min_escape_hatch_delay ||
        config.escape_hatch_delay > supported->max_escape_hatch_delay) {
        return FailValidation(error, "escape_hatch_delay outside supported range");
    }
    if (IsRealGroth16PoseidonProfile(*supported)) {
        if (!ValidateValiditySidechainGroth16ScalarFieldElement(Uint256ToLEBytes(config.initial_state_root), nullptr)) {
            return FailValidation(error, "initial_state_root does not fit BLS12-381 scalar field");
        }
        if (!UsesDecomposedPoseidonPublicInputs(*supported) &&
            !ValidateValiditySidechainGroth16ScalarFieldElement(Uint256ToLEBytes(config.initial_withdrawal_root), nullptr)) {
            return FailValidation(error, "initial_withdrawal_root does not fit BLS12-381 scalar field");
        }
    }

    return true;
}

bool IsValiditySidechainScaffoldingOnlyProfile(const ValiditySidechainConfig& config)
{
    const SupportedValiditySidechainConfig* supported = FindSupportedValiditySidechainConfig(config);
    return supported != nullptr && supported->scaffolding_only;
}

const char* GetValiditySidechainDepositAdmissionMode(const ValiditySidechainConfig& config)
{
    const SupportedValiditySidechainConfig* supported = FindSupportedValiditySidechainConfig(config);
    if (supported == nullptr) {
        return "unsupported_profile";
    }
    if (IsExperimentalScalarLimitedGroth16PoseidonProfile(*supported)) {
        return "single_pending_entry_scalar_field_experimental";
    }
    return "enabled_local_queue_consensus";
}

bool IsValiditySidechainSingleEntryExperimentalQueueProfile(const ValiditySidechainConfig& config)
{
    const SupportedValiditySidechainConfig* supported = FindSupportedValiditySidechainConfig(config);
    return supported != nullptr &&
           !supported->scaffolding_only &&
           IsExperimentalScalarLimitedGroth16PoseidonProfile(*supported);
}

bool AllowsValiditySidechainForceExitRequests(const ValiditySidechainConfig& config)
{
    return !IsValiditySidechainSingleEntryExperimentalQueueProfile(config);
}

const char* GetValiditySidechainForceExitRequestMode(const ValiditySidechainConfig& config)
{
    const SupportedValiditySidechainConfig* supported = FindSupportedValiditySidechainConfig(config);
    if (supported == nullptr) {
        return "unsupported_profile";
    }
    if (!AllowsValiditySidechainForceExitRequests(config)) {
        return "disabled_pending_real_queue_entry_proof";
    }
    return "enabled_local_queue_consensus";
}

const char* GetValiditySidechainBatchQueueBindingMode(const ValiditySidechainConfig& config)
{
    const SupportedValiditySidechainConfig* supported = FindSupportedValiditySidechainConfig(config);
    if (supported == nullptr) {
        return "unsupported_profile";
    }
    if (supported->scaffolding_only) {
        return "local_prefix_consensus_scaffold";
    }
    if (IsValiditySidechainSingleEntryExperimentalQueueProfile(config)) {
        return "local_prefix_consensus_single_deposit_entry_experimental";
    }
    return "local_prefix_consensus_count_only";
}

bool IsValiditySidechainSingleLeafExperimentalWithdrawalProfile(const ValiditySidechainConfig& config)
{
    return IsValiditySidechainSingleEntryExperimentalQueueProfile(config);
}

const char* GetValiditySidechainBatchWithdrawalBindingMode(const ValiditySidechainConfig& config)
{
    const SupportedValiditySidechainConfig* supported = FindSupportedValiditySidechainConfig(config);
    if (supported == nullptr) {
        return "unsupported_profile";
    }
    if (supported->scaffolding_only) {
        return "local_merkle_consensus_scaffold";
    }
    if (IsValiditySidechainSingleLeafExperimentalWithdrawalProfile(config)) {
        return "accepted_root_single_leaf_experimental";
    }
    return "accepted_root_generic";
}

const char* GetValiditySidechainVerifiedWithdrawalExecutionMode(const ValiditySidechainConfig& config)
{
    const SupportedValiditySidechainConfig* supported = FindSupportedValiditySidechainConfig(config);
    if (supported == nullptr) {
        return "unsupported_profile";
    }
    if (supported->scaffolding_only) {
        return "merkle_inclusion_scaffold";
    }
    if (IsValiditySidechainSingleLeafExperimentalWithdrawalProfile(config)) {
        return "withdrawal_root_single_leaf_experimental";
    }
    return "withdrawal_root_merkle_inclusion";
}

const char* GetValiditySidechainEscapeExitExecutionMode(const ValiditySidechainConfig& config)
{
    const SupportedValiditySidechainConfig* supported = FindSupportedValiditySidechainConfig(config);
    if (supported == nullptr) {
        return "unsupported_profile";
    }
    if (supported->scaffolding_only) {
        return "merkle_inclusion_scaffold";
    }
    return "merkle_inclusion_current_state_root_experimental";
}
