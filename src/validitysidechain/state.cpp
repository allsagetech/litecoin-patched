// Copyright (c) 2026 AllSageTech, LLC
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <validitysidechain/state.h>

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

void ValiditySidechainState::Reset()
{
    sidechains.clear();
}
