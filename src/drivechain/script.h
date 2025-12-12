#ifndef DRIVECHAIN_SCRIPT_H
#define DRIVECHAIN_SCRIPT_H

#include <cstdint>
#include <uint256.h>
#include <script/script.h>

struct DrivechainScriptInfo
{
    enum class Kind : uint8_t {
        DEPOSIT       = 0,
        BUNDLE_COMMIT = 1,
        VOTE_YES      = 2,
        EXECUTE       = 3,
        UNKNOWN       = 255,
    };

    Kind kind{Kind::UNKNOWN};
    uint8_t sidechain_id{0};
    uint256 payload;
    uint32_t n_withdrawals{0};
};

bool DecodeDrivechainScript(const CScript& scriptPubKey, DrivechainScriptInfo& out_info);

// OP_DRIVECHAIN <scid> <bundle_hash> <tag=0x03> <n_withdrawals LE32>
CScript BuildDrivechainExecuteScript(uint8_t scid, const uint256& bundle_hash, uint32_t n_withdrawals);

#endif
