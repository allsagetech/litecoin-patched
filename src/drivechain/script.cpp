#include <drivechain/script.h>
#include <script/script.h>
#include <script/script_error.h>

std::optional<DrivechainScriptInfo> DecodeDrivechainScript(const CScript& scriptPubKey)
{
    // Expected layout:
    // [0]: OP_DRIVECHAIN
    // [1]: PUSHDATA(1) -> sidechain_id
    // [3]: PUSHDATA(32) -> payload
    // [..]: PUSHDATA(1) -> kind_tag

    CScript::const_iterator pc = scriptPubKey.begin();
    opcodetype opcode;

    if (!scriptPubKey.GetOp(pc, opcode) || opcode != OP_DRIVECHAIN) {
        return std::nullopt;
    }

    std::vector<unsigned char> vch;

    if (!scriptPubKey.GetOp(pc, opcode, vch) || vch.size() != 1) {
        return std::nullopt;
    }
    uint8_t sidechain_id = vch[0];

    if (!scriptPubKey.GetOp(pc, opcode, vch) || vch.size() != 32) {
        return std::nullopt;
    }
    uint256 payload;
    if (vch.size() == 32) {
        payload = uint256(std::span<const unsigned char>(vch).data());
    }

    if (!scriptPubKey.GetOp(pc, opcode, vch) || vch.size() != 1) {
        return std::nullopt;
    }
    uint8_t tag = vch[0];

    DrivechainScriptInfo info;
    info.sidechain_id = sidechain_id;
    info.payload = payload;

    switch (tag) {
        case 0x00: info.kind = DrivechainScriptInfo::Kind::DEPOSIT;       break;
        case 0x01: info.kind = DrivechainScriptInfo::Kind::BUNDLE_COMMIT; break;
        case 0x02: info.kind = DrivechainScriptInfo::Kind::VOTE_YES;      break;
        case 0x03: info.kind = DrivechainScriptInfo::Kind::EXECUTE;       break;
        default:   info.kind = DrivechainScriptInfo::Kind::UNKNOWN;       break;
    }


    if (info.kind == DrivechainScriptInfo::Kind::UNKNOWN) {
        return std::nullopt;
    }

    if (pc != scriptPubKey.end()) {
        return std::nullopt;
    }

    return info;
}