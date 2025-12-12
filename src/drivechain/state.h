#ifndef DRIVECHAIN_STATE_H
#define DRIVECHAIN_STATE_H

#include <amount.h>
#include <map>
#include <uint256.h>

class CBlock;
class CBlockIndex;
class CTransaction;
class CValidationState;

struct Bundle
{
    uint256 hash;
    int first_seen_height{-1};
    int yes_votes{0};
    bool approved{false};
    bool executed{false};
};

struct Sidechain
{
    uint8_t id;
    CAmount escrow_balance{0};
    int creation_height{-1};
    bool is_active{true};

    std::map<uint256, Bundle> bundles;
};

class DrivechainState
{
public:
    std::map<uint8_t, Sidechain> sidechains;

    bool ConnectBlock(const CBlock& block, const CBlockIndex* pindex, CValidationState& state);
    void DisconnectBlock(const CBlock& block, const CBlockIndex* pindex);

    const Sidechain* GetSidechain(uint8_t id) const;

    Sidechain& GetOrCreateSidechain(uint8_t id, int height);
    Bundle& GetOrCreateBundle(Sidechain& sc, const uint256& hash, int height);
};

extern DrivechainState g_drivechain_state;

#endif
