#ifndef DRIVECHAIN_STATE_H
#define DRIVECHAIN_STATE_H

#include <amount.h>
#include <map>
#include <uint256.h>

class CBlock;
class CBlockIndex;
class CTransaction;

struct Sidechain
{
    uint8_t id;
    CAmount escrow_balance{0};
    int creation_height{-1};
    bool is_active{true};
};

class DrivechainState
{
public:
    std::map<uint8_t, Sidechain> sidechains;

    void ConnectBlock(const CBlock& block, const CBlockIndex* pindex);
    void DisconnectBlock(const CBlock& block, const CBlockIndex* pindex);

    const Sidechain* GetSidechain(uint8_t id) const;
};

extern DrivechainState g_drivechain_state;

#endif
