// Copyright (c) 2025-2026 AllSageTech, LLC
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DRIVECHAIN_STATE_H
#define DRIVECHAIN_STATE_H

#include <amount.h>
#include <consensus/params.h>
#include <drivechain/policy.h>
#include <map>
#include <serialize.h>
#include <uint256.h>

class CBlock;
class CBlockIndex;
class CTransaction;
class BlockValidationState;

struct Bundle
{
    uint256 hash;
    int first_seen_height{-1};
    int yes_votes{0};
    int no_votes{0};
    bool approved{false};
    bool executed{false};

    SERIALIZE_METHODS(Bundle, obj)
    {
        READWRITE(obj.hash, obj.first_seen_height, obj.yes_votes, obj.no_votes, obj.approved, obj.executed);
    }
};

struct Sidechain
{
    uint8_t id;
    CAmount escrow_balance{0};
    int creation_height{-1};
    bool is_active{true};
    bool owner_auth_required{false};
    DrivechainSidechainPolicy sidechain_policy;

    std::map<uint256, Bundle> bundles;

    SERIALIZE_METHODS(Sidechain, obj)
    {
        READWRITE(obj.id, obj.escrow_balance, obj.creation_height, obj.is_active, obj.owner_auth_required, obj.sidechain_policy, obj.bundles);
    }
};

struct DrivechainBundleSchedule
{
    int64_t vote_start_height{0};
    int64_t vote_end_height{0};
    int64_t approval_height{0};
    int64_t executable_height{0};
};

bool ComputeDrivechainBundleSchedule(
    const Consensus::Params& params,
    int first_seen_height,
    DrivechainBundleSchedule& out_schedule);

class DrivechainState
{
public:
    std::map<uint8_t, Sidechain> sidechains;

    SERIALIZE_METHODS(DrivechainState, obj)
    {
        READWRITE(obj.sidechains);
    }

    bool ConnectBlock(
        const CBlock& block,
        const CBlockIndex* pindex,
        const Consensus::Params& params,
        BlockValidationState& state);

    const Sidechain* GetSidechain(uint8_t id) const;
    const Bundle* GetBundle(uint8_t sidechain_id, const uint256& hash) const;

    Sidechain& GetOrCreateSidechain(uint8_t id, int height);
    Bundle& GetOrCreateBundle(Sidechain& sc, const uint256& hash, int height);
};

#endif
