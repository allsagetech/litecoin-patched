#include <drivechain/state.h>
#include <drivechain/script.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/standard.h>
#include <chain.h>
#include <hash.h>
#include <consensus/validation.h>

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
    out.push_back((unsigned char)(v & 0xff));
    out.push_back((unsigned char)((v >> 8) & 0xff));
    out.push_back((unsigned char)((v >> 16) & 0xff));
    out.push_back((unsigned char)((v >> 24) & 0xff));
    out.push_back((unsigned char)((v >> 32) & 0xff));
    out.push_back((unsigned char)((v >> 40) & 0xff));
    out.push_back((unsigned char)((v >> 48) & 0xff));
    out.push_back((unsigned char)((v >> 56) & 0xff));
}

static uint256 ComputeExecuteBundleHash(const CTransaction& tx, int marker_index, uint32_t n_withdrawals)
{
    std::vector<unsigned char> buf;
    buf.reserve((size_t)n_withdrawals * 64);

    for (uint32_t k = 0; k < n_withdrawals; ++k) {
        const CTxOut& w = tx.vout[(size_t)marker_index + 1 + k];

        AppendLE64(buf, (uint64_t)w.nValue);

        const size_t slen = w.scriptPubKey.size();
        // Consensus rule elsewhere enforces <= 255; keep safe here too.
        buf.push_back((unsigned char)(slen & 0xff));
        buf.insert(buf.end(), w.scriptPubKey.begin(), w.scriptPubKey.end());
    }

    return Hash(buf.begin(), buf.end());
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

        for (const auto& txout : tx->vout) {
            int execute_marker_index = -1;
            DrivechainScriptInfo execute_info;

            for (size_t out_i = 0; out_i < tx->vout.size(); ++out_i) {
                const auto& txout = tx->vout[out_i];
                DrivechainScriptInfo info;
                if (!DecodeDrivechainScript(txout.scriptPubKey, info)) {
                    continue;
                }

                switch (info.kind) {
                    case DrivechainScriptInfo::Kind::DEPOSIT: {
                        auto& sc = GetOrCreateSidechain(info.sidechain_id, height);
                        sc.escrow_balance += txout.nValue;
                        break;
                    }

                    case DrivechainScriptInfo::Kind::BUNDLE_COMMIT: {
                        auto& sc = GetOrCreateSidechain(info.sidechain_id, height);
                        auto& bundle = GetOrCreateBundle(sc, info.payload, height);
                        (void)bundle;
                        break;
                    }

                    case DrivechainScriptInfo::Kind::VOTE_YES: {
                        if (!is_coinbase) {
                            break;
                        }

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
                            return state.Invalid(false, REJECT_INVALID, "drivechain-multi-execute");
                        }
                        if (info.n_withdrawals == 0) {
                            return state.Invalid(false, REJECT_INVALID, "drivechain-zero-withdrawals");
                        }
                        execute_marker_index = (int)out_i;
                        execute_info = info;
                        break;
                    }

                    case DrivechainScriptInfo::Kind::UNKNOWN:
                    default:
                        break;
                }
            }
        }
        // Enforce EXECUTE consensus rules (marker + N ordered withdrawals + optional change).
        if (execute_marker_index != -1) {
            const uint32_t n = execute_info.n_withdrawals;
            const size_t m = (size_t)execute_marker_index;

            // Require outputs [m+1..m+n] exist.
            if (m + 1 + (size_t)n > tx->vout.size()) {
                return state.Invalid(false, REJECT_INVALID, "drivechain-withdrawals-oob");
            }

            // Bundle must exist, must be approved, must not be executed yet.
            auto& sc = GetOrCreateSidechain(execute_info.sidechain_id, height);
            auto& bundle = GetOrCreateBundle(sc, execute_info.payload, height);

            if (!bundle.approved) {
                return state.Invalid(false, REJECT_INVALID, "drivechain-execute-unapproved");
            }
            if (bundle.executed) {
                return state.Invalid(false, REJECT_INVALID, "drivechain-already-executed");
            }

            CAmount withdraw_sum = 0;

            // Withdrawals: enforce constraints and sum.
            for (uint32_t k = 0; k < n; ++k) {
                const CTxOut& w = tx->vout[m + 1 + (size_t)k];

                if (IsDrivechainOutput(w.scriptPubKey)) {
                    return state.Invalid(false, REJECT_INVALID, "drivechain-withdrawal-is-drivechain");
                }
                if (w.scriptPubKey.size() > 255) {
                    return state.Invalid(false, REJECT_INVALID, "drivechain-withdrawal-script-too-big");
                }

                withdraw_sum += w.nValue;
            }

            // Trailing outputs (change etc.) are allowed, but must not be drivechain outputs.
            for (size_t j = m + 1 + (size_t)n; j < tx->vout.size(); ++j) {
                if (IsDrivechainOutput(tx->vout[j].scriptPubKey)) {
                    return state.Invalid(false, REJECT_INVALID, "drivechain-post-withdrawal-is-drivechain");
                }
            }

            // Verify canonical bundle hash matches marker payload.
            const uint256 computed = ComputeExecuteBundleHash(*tx, (int)m, n);
            if (computed != execute_info.payload) {
                return state.Invalid(false, REJECT_INVALID, "drivechain-bundlehash-mismatch");
            }

            // Debit escrow by withdrawals sum (marker output value is ignored).
            if (sc.escrow_balance < withdraw_sum) {
                return state.Invalid(false, REJECT_INVALID, "drivechain-escrow-insufficient");
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

        // Find EXECUTE marker if present so we can reverse the escrow debit correctly.
        int execute_marker_index = -1;
        DrivechainScriptInfo execute_info;

        for (size_t out_i = 0; out_i < tx->vout.size(); ++out_i) {
            const auto& txout = tx->vout[out_i];
            DrivechainScriptInfo info;
            if (!DecodeDrivechainScript(txout.scriptPubKey, info)) {
                continue;
            }

            auto sc_it = sidechains.find(info.sidechain_id);
            if (sc_it == sidechains.end()) continue;
            auto& sc = sc_it->second;

            switch (info.kind) {
                case DrivechainScriptInfo::Kind::DEPOSIT: {
                    sc.escrow_balance -= txout.nValue;
                    break;
                }

                case DrivechainScriptInfo::Kind::BUNDLE_COMMIT: {
                    auto b_it = sc.bundles.find(info.payload);
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
                    auto b_it = sc.bundles.find(info.payload);
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

                case DrivechainScriptInfo::Kind::EXECUTE: {
                    // Defer reversal until after scan so we can recompute withdraw_sum.
                    if (execute_marker_index == -1) {
                        execute_marker_index = (int)out_i;
                        execute_info = info;
                    }
                    break;
                }

                case DrivechainScriptInfo::Kind::UNKNOWN:
                default:
                    break;
            }
        }
        if (execute_marker_index != -1) {
            // Only reverse if sidechain still exists.
            auto sc_it = sidechains.find(execute_info.sidechain_id);
            if (sc_it == sidechains.end()) continue;
            auto& sc = sc_it->second;

            const uint32_t n = execute_info.n_withdrawals;
            const size_t m = (size_t)execute_marker_index;
            if (n > 0 && m + 1 + (size_t)n <= tx->vout.size()) {
                CAmount withdraw_sum = 0;
                for (uint32_t k = 0; k < n; ++k) {
                    withdraw_sum += tx->vout[m + 1 + (size_t)k].nValue;
                }
                sc.escrow_balance += withdraw_sum;
            }

            auto b_it = sc.bundles.find(execute_info.payload);
            if (b_it != sc.bundles.end()) {
                b_it->second.executed = false;
            }
        }
    }
}
