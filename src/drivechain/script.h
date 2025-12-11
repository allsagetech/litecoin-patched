#ifndef DRIVECHAIN_SCRIPT_H
#define DRIVECHAIN_SCRIPT_H

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
};

bool DecodeDrivechainScript(const CScript& scriptPubKey, DrivechainScriptInfo& out_info);

CScript MakeDrivechainScript(uint8_t sidechain_id, const uint256& payload, DrivechainScriptInfo::Kind kind);

#endif
