#include <drivechain/state.h>
#include <drivechain/script.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/standard.h>

DrivechainState g_drivechain_state;

const Sidechain* DrivechainState::GetSidechain(uint8_t id) const
{
    auto it = sidechains.find(id);
    if (it == sidechains.end()) return nullptr;
    return &it->second;
}

void DrivechainState::ConnectBlock(const CBlock& block, const CBlockIndex* pindex)
{
    int height = pindex->nHeight;

    for (const auto& tx : block.vtx) {
        for (const auto& txout : tx->vout) {
            auto info = DecodeDrivechainScript(txout.scriptPubKey);
            if (!info) continue;

            if (info->kind == DrivechainScriptInfo::Kind::DEPOSIT) {
                auto& sc = sidechains[info->sidechain_id];
                if (sc.creation_height == -1) {
                    sc.id = info->sidechain_id;
                    sc.creation_height = height;
                    sc.is_active = true;
                }
                sc.escrow_balance += txout.nValue;
            }
        }
    }
}

void DrivechainState::DisconnectBlock(const CBlock& block, const CBlockIndex* pindex)
{
    int height = pindex->nHeight;

    for (const auto& tx : block.vtx) {
        for (const auto& txout : tx->vout) {
            auto info = DecodeDrivechainScript(txout.scriptPubKey);
            if (!info) continue;

            if (info->kind == DrivechainScriptInfo::Kind::DEPOSIT) {
                auto it = sidechains.find(info->sidechain_id);
                if (it == sidechains.end()) continue;

                it->second.escrow_balance -= txout.nValue;
            }
        }
    }
}
