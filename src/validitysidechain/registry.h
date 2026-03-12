// Copyright (c) 2026 AllSageTech, LLC
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VALIDITYSIDECHAIN_REGISTRY_H
#define BITCOIN_VALIDITYSIDECHAIN_REGISTRY_H

#include <validitysidechain/state.h>

#include <string>
#include <vector>

struct SupportedValiditySidechainConfig
{
    const char* profile_name{nullptr};
    bool scaffolding_only{true};
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

#endif // BITCOIN_VALIDITYSIDECHAIN_REGISTRY_H
