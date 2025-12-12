#include <drivechain/state.h>
#include <drivechain/script.h>

#include <chain.h>
#include <consensus/validation.h>
#include <hash.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/standard.h>
#include <span.h>

#include <vector>

DrivechainState g_drivechain_state;

// TODO: tune these parameters; for now they're simple, regtest-friendly values.
static constexpr int DRIVECHAIN_VOTE_WINDOW    = 1000;
static constexpr int DRIVECHAIN_VOTE_THRESHOLD = 10;

namespace {

static inline bool IsDrivechainOutput(const CScript& spk)
{
    DrivechainScriptInfo tmp;
    return DecodeDrivechainScript(spk, tmp);
}

static inline void AppendLE64(std::vector<unsigned char>& out, uint64_t v)
{
    for (int i = 0; i < 8; ++i) {
        out.push_back((unsigned char)((v >> (8 * i)) & 0xff));
    }
}

static uint256 ComputeExecuteBundleHash(const CTransaction& tx, int marker_index, uint32_t n_withdrawals)
{
    std::vector<unsigned char> buf;
    buf.reserve((size_t)n_withdrawals * 64);

    for (uint32_t k = 0; k < n_withdrawals; ++k) {
        const CTxOut& w = tx.vout[(size_t)marker_index + 1 + k];

        AppendLE64(buf, (uint64_t)w.nValue);

        const size_t slen = w.scriptPubKey.size();
        buf.push_back((unsigned char)(slen & 0xff));
        buf.insert(buf.end(), w.scriptPubKey.begin(), w.scriptPubKey.end());
    }

    uint256 out;
    CHash256().Write(MakeUCharSpan(buf)).Finalize(out);
    return out;
}

} // namespace

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

bool DrivechainState::ConnectBlock(const CBlock& block, const CBlockIndex* pindex, BlockValidationState& state)
{
    const int height = pindex->nHeight;

    for (size_t tx_index = 0; tx_index < block.vtx.size(); ++tx_index) {
        const auto& tx = block.vtx[tx_index];
        const bool is_coinbase = (tx_index == 0);

        int execute_marker_index = -1;
        DrivechainScriptInfo execute_info;

        for (size_t out_i = 0; out_i < tx->vout.size(); ++out_i) {
            const auto& txout = tx->vout[out_i];

            DrivechainScriptInfo info;
            if (!DecodeDrivechainScript(txout.scriptPubKey, info)) continue;

            switch (info.kind) {
                case DrivechainScriptInfo::Kind::DEPOSIT: {
                    auto& sc = GetOrCreateSidechain(info.sidechain_id, height);
                    sc.escrow_balance += txout.nValue;
                    break;
                }

                case DrivechainScriptInfo::Kind::BUNDLE_COMMIT: {
                    auto& sc = GetOrCreateSidechain(info.sidechain_id, height);
                    GetOrCreateBundle(sc, info.payload, height);
                    break;
                }

                case DrivechainScriptInfo::Kind::VOTE_YES: {
                    if (!is_coinbase) break;

                    auto& sc = GetOrCreateSidechain(info.sidechain_id, height);
                    auto& bundle = GetOrCreateBundle(sc, info.payload, height);

                    if (height - bundle.first_seen_height <= DRIVECHAIN_VOTE_WINDOW) {
                        ++bundle.yes_votes;
                        if (!bundle.approved && bundle.yes_votes >= DRIVECHAIN_VOTE_THRESHOLD) {
                            bundle.approved = true;
                        }
                    }
                    break;
                }

                case DrivechainScriptInfo::Kind::EXECUTE: {
                    if (execute_marker_index != -1) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                             "drivechain-multi-execute");
                    }
                    if (info.n_withdrawals == 0) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                             "drivechain-zero-withdrawals");
                    }
                    execute_marker_index = (int)out_i;
                    execute_info = info;
                    break;
                }

                default:
                    break;
            }
        }

        if (execute_marker_index != -1) {
            const uint32_t n = execute_info.n_withdrawals;
            const size_t m = (size_t)execute_marker_index;

            if (m + 1 + (size_t)n > tx->vout.size()) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                     "drivechain-withdrawals-oob");
            }

            auto& sc = GetOrCreateSidechain(execute_info.sidechain_id, height);
            auto& bundle = GetOrCreateBundle(sc, execute_info.payload, height);

            if (!bundle.approved) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                     "drivechain-execute-unapproved");
            }
            if (bundle.executed) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                     "drivechain-already-executed");
            }

            CAmount withdraw_sum = 0;
            for (uint32_t k = 0; k < n; ++k) {
                const CTxOut& w = tx->vout[m + 1 + (size_t)k];

                if (IsDrivechainOutput(w.scriptPubKey)) {
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                         "drivechain-withdrawal-is-drivechain");
                }
                if (w.scriptPubKey.size() > 255) {
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                         "drivechain-withdrawal-script-too-big");
                }
                withdraw_sum += w.nValue;
            }

            for (size_t j = m + 1 + (size_t)n; j < tx->vout.size(); ++j) {
                if (IsDrivechainOutput(tx->vout[j].scriptPubKey)) {
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                         "drivechain-post-withdrawal-is-drivechain");
                }
            }

            const uint256 computed = ComputeExecuteBundleHash(*tx, (int)m, n);
            if (computed != execute_info.payload) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                     "drivechain-bundlehash-mismatch");
            }

            if (sc.escrow_balance < withdraw_sum) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                     "drivechain-escrow-insufficient");
            }

            sc.escrow_balance -= withdraw_sum;
            bundle.executed = true;
        }
    }

    return true;
}

void DrivechainState::DisconnectBlock(const CBlock& block, const CBlockIndex* pindex)
{
    const int height = pindex->nHeight;

    for (size_t tx_index = 0; tx_index < block.vtx.size(); ++tx_index) {
        const auto& tx = block.vtx[tx_index];
        const bool is_coinbase = (tx_index == 0);

        int execute_marker_index = -1;
        DrivechainScriptInfo execute_info;

        for (size_t out_i = 0; out_i < tx->vout.size(); ++out_i) {
            const auto& txout = tx->vout[out_i];
            DrivechainScriptInfo info;
            if (!DecodeDrivechainScript(txout.scriptPubKey, info)) continue;

            auto sc_it = sidechains.find(info.sidechain_id);
            if (sc_it == sidechains.end()) continue;
            auto& sc = sc_it->second;

            switch (info.kind) {
                case DrivechainScriptInfo::Kind::DEPOSIT:
                    sc.escrow_balance -= txout.nValue;
                    break;

                case DrivechainScriptInfo::Kind::EXECUTE:
                    execute_marker_index = (int)out_i;
                    execute_info = info;
                    break;

                default:
                    break;
            }
        }

        if (execute_marker_index != -1) {
            auto sc_it = sidechains.find(execute_info.sidechain_id);
            if (sc_it == sidechains.end()) continue;
            auto& sc = sc_it->second;

            const uint32_t n = execute_info.n_withdrawals;
            const size_t m = (size_t)execute_marker_index;

            CAmount withdraw_sum = 0;
            for (uint32_t k = 0; k < n; ++k) {
                withdraw_sum += tx->vout[m + 1 + (size_t)k].nValue;
            }

            sc.escrow_balance += withdraw_sum;
            sc.bundles[execute_info.payload].executed = false;
        }
    }
}
