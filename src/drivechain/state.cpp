#include <drivechain/state.h>
#include <drivechain/script.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/standard.h>

DrivechainState g_drivechain_state;

// TODO: tune these parameters; for now they're simple, regtest-friendly values.
static constexpr int DRIVECHAIN_VOTE_WINDOW    = 1000;
static constexpr int DRIVECHAIN_VOTE_THRESHOLD = 10;

Sidechain& DrivechainState::GetOrCreateSidechain(uint8_t id, int height)
{
    auto& sc = sidechains[id];
    if (sc.creation_height == -1) {
        sc.id = id;
        sc.creation_height = height;
        sc.is_active = true;
    }
    return sc;
}

Bundle& DrivechainState::GetOrCreateBundle(Sidechain& sc, const uint256& hash, int height)
{
    auto& bundle = sc.bundles[hash];
    if (bundle.first_seen_height == -1) {
        bundle.hash = hash;
        bundle.first_seen_height = height;
    }
    return bundle;
}

const Sidechain* DrivechainState::GetSidechain(uint8_t id) const
{
    auto it = sidechains.find(id);
    if (it == sidechains.end()) return nullptr;
    return &it->second;
}

void DrivechainState::ConnectBlock(const CBlock& block, const CBlockIndex* pindex)
{
    const int height = pindex->nHeight;

    for (size_t tx_index = 0; tx_index < block.vtx.size(); ++tx_index) {
        const auto& tx = block.vtx[tx_index];

        const bool is_coinbase = (tx_index == 0);

        for (const auto& txout : tx->vout) {
            auto info = DecodeDrivechainScript(txout.scriptPubKey);
            if (!info) continue;

            switch (info->kind) {
                case DrivechainScriptInfo::Kind::DEPOSIT: {
                    auto& sc = GetOrCreateSidechain(info->sidechain_id, height);
                    sc.escrow_balance += txout.nValue;
                    break;
                }

                case DrivechainScriptInfo::Kind::BUNDLE_COMMIT: {
                    auto& sc = GetOrCreateSidechain(info->sidechain_id, height);
                    auto& bundle = GetOrCreateBundle(sc, info->payload, height);
                    (void)bundle;
                    break;
                }

                case DrivechainScriptInfo::Kind::VOTE_YES: {
                    if (!is_coinbase) {
                        break;
                    }

                    auto& sc = GetOrCreateSidechain(info->sidechain_id, height);
                    auto& bundle = GetOrCreateBundle(sc, info->payload, height);

                    if (height - bundle.first_seen_height <= DRIVECHAIN_VOTE_WINDOW) {
                        ++bundle.yes_votes;

                        if (!bundle.approved && bundle.yes_votes >= DRIVECHAIN_VOTE_THRESHOLD) {
                            bundle.approved = true;
                        }
                    }
                    break;
                }

                case DrivechainScriptInfo::Kind::EXECUTE:
                    break;

                case DrivechainScriptInfo::Kind::UNKNOWN:
                default:
                    break;
            }
        }
    }
}

void DrivechainState::DisconnectBlock(const CBlock& block, const CBlockIndex* pindex)
{
    const int height = pindex->nHeight;

    for (size_t tx_index = 0; tx_index < block.vtx.size(); ++tx_index) {
        const auto& tx = block.vtx[tx_index];
        const bool is_coinbase = (tx_index == 0);

        for (const auto& txout : tx->vout) {
            auto info = DecodeDrivechainScript(txout.scriptPubKey);
            if (!info) continue;

            auto sc_it = sidechains.find(info->sidechain_id);
            if (sc_it == sidechains.end()) continue;
            auto& sc = sc_it->second;

            switch (info->kind) {
                case DrivechainScriptInfo::Kind::DEPOSIT: {
                    sc.escrow_balance -= txout.nValue;
                    break;
                }

                case DrivechainScriptInfo::Kind::BUNDLE_COMMIT: {
                    auto b_it = sc.bundles.find(info->payload);
                    if (b_it != sc.bundles.end()) {
                        if (b_it->second.first_seen_height == height) {
                            sc.bundles.erase(b_it);
                        }
                    }
                    break;
                }

                case DrivechainScriptInfo::Kind::VOTE_YES: {
                    if (!is_coinbase) {
                        break;
                    }
                    auto b_it = sc.bundles.find(info->payload);
                    if (b_it != sc.bundles.end()) {
                        Bundle& bundle = b_it->second;

                        if (height - bundle.first_seen_height <= DRIVECHAIN_VOTE_WINDOW) {
                            if (bundle.yes_votes > 0) {
                                --bundle.yes_votes;
                            }
                            if (bundle.approved && bundle.yes_votes < DRIVECHAIN_VOTE_THRESHOLD) {
                                bundle.approved = false;
                            }
                        }
                    }
                    break;
                }

                case DrivechainScriptInfo::Kind::EXECUTE:
                    break;

                case DrivechainScriptInfo::Kind::UNKNOWN:
                default:
                    break;
            }
        }
    }
}
