#ifndef DRIVECHAIN_SCRIPT_H
#define DRIVECHAIN_SCRIPT_H

#include <uint256.h>
#include <script/script.h>
#include <optional>

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

std::optional<DrivechainScriptInfo> DecodeDrivechainScript(const CScript& scriptPubKey);

#endif
