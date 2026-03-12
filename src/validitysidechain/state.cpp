// Copyright (c) 2026 AllSageTech, LLC
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <validitysidechain/state.h>

#include <chain.h>
#include <validitysidechain/registry.h>
#include <validitysidechain/script.h>

#include <consensus/validation.h>
#include <primitives/block.h>

const ValiditySidechain* ValiditySidechainState::GetSidechain(uint8_t id) const
{
    const auto it = sidechains.find(id);
    return it == sidechains.end() ? nullptr : &it->second;
}

ValiditySidechain* ValiditySidechainState::GetSidechain(uint8_t id)
{
    const auto it = sidechains.find(id);
    return it == sidechains.end() ? nullptr : &it->second;
}

ValiditySidechain& ValiditySidechainState::GetOrCreateSidechain(uint8_t id, int registration_height)
{
    auto [it, inserted] = sidechains.emplace(id, ValiditySidechain{});
    ValiditySidechain& sidechain = it->second;
    if (inserted) {
        sidechain.id = id;
        sidechain.registration_height = registration_height;
        sidechain.is_active = true;
        sidechain.current_state_root = sidechain.config.initial_state_root;
        sidechain.current_withdrawal_root = sidechain.config.initial_withdrawal_root;
    } else if (sidechain.registration_height < 0 && registration_height >= 0) {
        sidechain.registration_height = registration_height;
    }
    return sidechain;
}

bool ValiditySidechainState::RegisterSidechain(
    uint8_t id,
    int registration_height,
    const ValiditySidechainConfig& config,
    std::string* error)
{
    if (registration_height < 0) {
        if (error != nullptr) {
            *error = "registration height must be non-negative";
        }
        return false;
    }
    if (!ValidateValiditySidechainConfig(config, error)) {
        return false;
    }
    if (sidechains.count(id) != 0) {
        if (error != nullptr) {
            *error = "sidechain id already registered";
        }
        return false;
    }

    ValiditySidechain sidechain;
    sidechain.id = id;
    sidechain.registration_height = registration_height;
    sidechain.is_active = true;
    sidechain.config = config;
    sidechain.current_state_root = config.initial_state_root;
    sidechain.current_withdrawal_root = config.initial_withdrawal_root;

    sidechains.emplace(id, sidechain);
    return true;
}

bool ValiditySidechainState::ConnectBlock(const CBlock& block, const CBlockIndex* pindex, BlockValidationState& state)
{
    const int height = pindex->nHeight;

    for (const auto& tx : block.vtx) {
        int register_count = 0;

        for (const auto& txout : tx->vout) {
            ValiditySidechainScriptInfo info;
            if (!DecodeValiditySidechainScript(txout.scriptPubKey, info)) {
                continue;
            }

            if (info.kind != ValiditySidechainScriptInfo::Kind::REGISTER_VALIDITY_SIDECHAIN) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "validitysidechain-kind-not-enabled");
            }

            ++register_count;
            if (register_count > 1) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "validitysidechain-multi-register");
            }

            ValiditySidechainConfig config;
            if (!DecodeValiditySidechainConfig(info.primary_metadata, config)) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "validitysidechain-register-config-bad");
            }
            if (ComputeValiditySidechainConfigHash(config) != info.payload) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "validitysidechain-register-config-mismatch");
            }

            std::string error;
            if (!RegisterSidechain(info.sidechain_id, height, config, &error)) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "validitysidechain-register-invalid", error);
            }
        }
    }

    return true;
}

void ValiditySidechainState::Reset()
{
    sidechains.clear();
}
