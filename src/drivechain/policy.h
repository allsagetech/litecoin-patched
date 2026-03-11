// Copyright (c) 2026 AllSageTech, LLC
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DRIVECHAIN_POLICY_H
#define DRIVECHAIN_POLICY_H

#include <amount.h>
#include <serialize.h>
#include <uint256.h>

#include <vector>

static constexpr uint8_t MAX_DRIVECHAIN_OWNER_KEYS = 15;

struct DrivechainSidechainPolicy
{
    uint8_t auth_threshold{0};
    std::vector<uint256> owner_key_hashes;
    CAmount max_escrow_amount{0};
    CAmount max_bundle_withdrawal{0};

    bool RequiresOwnerAuth() const
    {
        return auth_threshold > 0 && !owner_key_hashes.empty();
    }

    SERIALIZE_METHODS(DrivechainSidechainPolicy, obj)
    {
        READWRITE(obj.auth_threshold, obj.owner_key_hashes, obj.max_escrow_amount, obj.max_bundle_withdrawal);
    }
};

#endif
