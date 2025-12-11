#include <drivechain/script.h>
#include <script/script.h>
#include <script/script_error.h>
#include <algorithm>
#include <vector>

bool DecodeDrivechainScript(const CScript& scriptPubKey, DrivechainScriptInfo& out_info)
{
    // Expected layout:
    // [0]: OP_DRIVECHAIN
    // [1]: PUSHDATA(1)  -> sidechain_id
    // [2]: PUSHDATA(32) -> payload
    // [3]: PUSHDATA(1)  -> kind_tag

    CScript::const_iterator pc = scriptPubKey.begin();
    opcodetype opcode;

    if (!scriptPubKey.GetOp(pc, opcode) || opcode != OP_DRIVECHAIN) {
        return false;
    }

    std::vector<unsigned char> vch;

    if (!scriptPubKey.GetOp(pc, opcode, vch) || vch.size() != 1) {
        return false;
    }
    uint8_t sidechain_id = vch[0];

    if (!scriptPubKey.GetOp(pc, opcode, vch) || vch.size() != 32) {
        return false;
    }
    uint256 payload;
    std::copy(vch.begin(), vch.end(), payload.begin());

    if (!scriptPubKey.GetOp(pc, opcode, vch) || vch.size() != 1) {
        return false;
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
        return false;
    }

    if (pc != scriptPubKey.end()) {
        return false;
    }

    out_info = info;
    return true;
}

CScript MakeDrivechainScript(uint8_t sidechain_id,
                             const uint256& payload,
                             DrivechainScriptInfo::Kind kind)
{
    uint8_t tag;
    switch (kind) {
        case DrivechainScriptInfo::Kind::DEPOSIT:
            tag = 0x00;
            break;
        case DrivechainScriptInfo::Kind::BUNDLE_COMMIT:
            tag = 0x01;
            break;
        case DrivechainScriptInfo::Kind::VOTE_YES:
            tag = 0x02;
            break;
        case DrivechainScriptInfo::Kind::EXECUTE:
            tag = 0x03;
            break;
        default:
            // You *could* throw here; for now just use UNKNOWN → invalid script.
            tag = 0xff;
            break;
    }

    std::vector<unsigned char> sc_id_vec{sidechain_id};
    std::vector<unsigned char> payload_vec(payload.begin(), payload.end());
    std::vector<unsigned char> tag_vec{tag};

    CScript script;
    script << OP_DRIVECHAIN;
    script << sc_id_vec;
    script << payload_vec;
    script << tag_vec;
    return script;
}
