#include <drivechain/script.h>
#include <script/script.h>
#include <script/script_error.h>
#include <algorithm>

static uint32_t ReadLE32(const unsigned char* p)
{
    return ((uint32_t)p[0]) |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

bool DecodeDrivechainScript(const CScript& scriptPubKey, DrivechainScriptInfo& out_info)
{
    // Layout:
    // [0]: OP_DRIVECHAIN
    // [1]: PUSHDATA(1)   -> sidechain_id
    // [2]: PUSHDATA(32)  -> payload (bundle_hash / etc)
    // [3]: PUSHDATA(1)   -> kind_tag
    // [4]: (EXECUTE only) PUSHDATA(4) -> n_withdrawals (LE32)

    CScript::const_iterator pc = scriptPubKey.begin();
    opcodetype opcode;

    if (!scriptPubKey.GetOp(pc, opcode) || opcode != OP_DRIVECHAIN) {
        return false;
    }

    std::vector<unsigned char> vch;

    if (!scriptPubKey.GetOp(pc, opcode, vch) || vch.size() != 1) {
        return false;
    }
    const uint8_t sidechain_id = vch[0];

    if (!scriptPubKey.GetOp(pc, opcode, vch) || vch.size() != 32) {
        return false;
    }
    uint256 payload;
    std::copy(vch.begin(), vch.end(), payload.begin());

    if (!scriptPubKey.GetOp(pc, opcode, vch) || vch.size() != 1) {
        return false;
    }
    const uint8_t tag = vch[0];

    DrivechainScriptInfo info;
    info.sidechain_id = sidechain_id;
    info.payload = payload;
    info.n_withdrawals = 0;

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

    // EXECUTE has one extra push: n_withdrawals (4 bytes little-endian)
    if (info.kind == DrivechainScriptInfo::Kind::EXECUTE) {
        if (!scriptPubKey.GetOp(pc, opcode, vch) || vch.size() != 4) {
            return false;
        }
        info.n_withdrawals = ReadLE32(vch.data());
        if (info.n_withdrawals == 0) { // disallow zero to avoid ambiguity
            return false;
        }
    }

    // No extra data allowed.
    if (pc != scriptPubKey.end()) {
        return false;
    }

    out_info = info;
    return true;
}

static void WriteLE32(std::vector<unsigned char>& out, uint32_t v)
{
    out.resize(4);
    out[0] = (v >> 0) & 0xff;
    out[1] = (v >> 8) & 0xff;
    out[2] = (v >> 16) & 0xff;
    out[3] = (v >> 24) & 0xff;
}

CScript BuildDrivechainExecuteScript(uint8_t scid, const uint256& bundle_hash, uint32_t n_withdrawals)
{
    std::vector<unsigned char> scid_v{scid};

    std::vector<unsigned char> payload(32);
    std::copy(bundle_hash.begin(), bundle_hash.end(), payload.begin());

    std::vector<unsigned char> tag{0x03};

    std::vector<unsigned char> n_le;
    WriteLE32(n_le, n_withdrawals);

    CScript s;
    s << OP_DRIVECHAIN << scid_v << payload << tag << n_le;
    return s;
}
