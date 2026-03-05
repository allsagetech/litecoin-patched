// Copyright (c) 2025-2026 AllSageTech, LLC
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <drivechain/state.h>
#include <drivechain/script.h>

#include <chain.h>
#include <consensus/validation.h>
#include <hash.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/standard.h>
#include <span.h>

#include <set>
#include <vector>

namespace {

static int64_t FloorDiv(int64_t a, int64_t b)
{
    int64_t q = a / b;
    const int64_t r = a % b;
    if (r != 0 && ((r > 0) != (b > 0))) {
        --q;
    }
    return q;
}

}

bool ComputeDrivechainBundleSchedule(
    const Consensus::Params& params,
    int first_seen_height,
    DrivechainBundleSchedule& out_schedule)
{
    if (first_seen_height < 0 ||
        params.nDrivechainVoteWindow <= 0 ||
        params.nDrivechainFinalizationDelay <= 0) {
        return false;
    }

    const int64_t vote_window = params.nDrivechainVoteWindow;
    const int64_t epoch_start = params.vDeployments[Consensus::DEPLOYMENT_DRIVECHAIN].nStartHeight;
    const int64_t delta = int64_t{first_seen_height} - epoch_start;

    // Voting always starts at the next fixed boundary after first_seen_height.
    const int64_t window_index = FloorDiv(delta, vote_window) + 1;

    out_schedule.vote_start_height = epoch_start + (window_index * vote_window);
    out_schedule.vote_end_height = out_schedule.vote_start_height + vote_window - 1;
    out_schedule.approval_height = out_schedule.vote_end_height + 1;
    out_schedule.executable_height = out_schedule.vote_end_height + params.nDrivechainFinalizationDelay + 1;
    return true;
}

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

    static uint256 ComputeExecuteBundleHash(
        const CTransaction& tx,
        uint8_t sidechain_id,
        int marker_index,
        uint32_t n_withdrawals)
    {
        std::vector<unsigned char> buf;

        buf.reserve(1 + 4 + (size_t)n_withdrawals * 64);

        buf.push_back(sidechain_id);

        for (int i = 0; i < 4; ++i) {
            buf.push_back((unsigned char)((n_withdrawals >> (8 * i)) & 0xff));
        }

        for (uint32_t k = 0; k < n_withdrawals; ++k) {
            const CTxOut& w = tx.vout[(size_t)marker_index + 1 + k];

            AppendLE64(buf, (uint64_t)w.nValue);

            const size_t slen = w.scriptPubKey.size();
            buf.push_back((unsigned char)(slen & 0xff));
            buf.insert(buf.end(), w.scriptPubKey.begin(), w.scriptPubKey.end());
        }

        uint256 out;
        CHash256().Write(MakeUCharSpan(buf)).Finalize(out); // SHA256d
        return out;
    }

    static void PruneFailedBundles(
        std::map<uint8_t, Sidechain>& sidechains,
        const Consensus::Params& params,
        int height)
    {
        for (auto& sc_it : sidechains) {
            auto& bundles = sc_it.second.bundles;
            for (auto b_it = bundles.begin(); b_it != bundles.end();) {
                DrivechainBundleSchedule schedule;
                const Bundle& bundle = b_it->second;
                if (!ComputeDrivechainBundleSchedule(params, bundle.first_seen_height, schedule) ||
                    (!bundle.approved && !bundle.executed && height >= schedule.approval_height)) {
                    b_it = bundles.erase(b_it);
                } else {
                    ++b_it;
                }
            }
        }
    }

}

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

const Bundle* DrivechainState::GetBundle(uint8_t sidechain_id, const uint256& hash) const
{
    const Sidechain* sc = GetSidechain(sidechain_id);
    if (sc == nullptr) return nullptr;
    auto it = sc->bundles.find(hash);
    if (it == sc->bundles.end()) return nullptr;
    return &it->second;
}

bool DrivechainState::ConnectBlock(
    const CBlock& block,
    const CBlockIndex* pindex,
    const Consensus::Params& params,
    BlockValidationState& state)
{
    if (params.nDrivechainVoteWindow <= 0 ||
        params.nDrivechainApprovalThreshold <= 0 ||
        params.nDrivechainFinalizationDelay <= 0) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "drivechain-invalid-params");
    }

    const int height = pindex->nHeight;
    std::map<uint8_t, CAmount> deposits_in_block_total;
    std::map<uint8_t, CAmount> executes_in_block;
    std::map<uint8_t, CAmount> escrow_before;
    std::set<std::pair<uint8_t, uint256>> executed_bundles_in_block;
    std::set<uint8_t> voted_sidechains_in_coinbase;
    std::set<uint8_t> registered_sidechains_in_block;

    for (const auto& it : sidechains) {
        escrow_before[it.first] = it.second.escrow_balance;
    }

    for (const auto& tx : block.vtx) {
        for (const auto& txout : tx->vout) {
            DrivechainScriptInfo info;
            if (!DecodeDrivechainScript(txout.scriptPubKey, info)) continue;
            if (info.kind == DrivechainScriptInfo::Kind::DEPOSIT) {
                deposits_in_block_total[info.sidechain_id] += txout.nValue;
            }
        }
    }

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
                    if (registered_sidechains_in_block.count(info.sidechain_id) != 0) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                             "drivechain-register-confirmation-required");
                    }
                    auto sc_it = sidechains.find(info.sidechain_id);
                    if (sc_it == sidechains.end()) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                             "drivechain-unknown-sidechain");
                    }
                    Sidechain& sc = sc_it->second;
                    sc.escrow_balance += txout.nValue;
                    break;
                }

                case DrivechainScriptInfo::Kind::REGISTER: {
                    if (info.payload.IsNull()) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                             "drivechain-register-null-owner");
                    }
                    if (txout.nValue < params.nDrivechainMinRegisterAmount) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                             "drivechain-register-amount-too-low");
                    }
                    if (sidechains.find(info.sidechain_id) != sidechains.end()) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                             "drivechain-register-sidechain-exists");
                    }
                    if (info.auth_sig.empty()) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                             "drivechain-register-auth-missing");
                    }
                    if (!VerifyDrivechainRegisterAuthSig(info.sidechain_id, info.payload, info.auth_sig)) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                             "drivechain-register-auth-invalid");
                    }
                    auto& sc = GetOrCreateSidechain(info.sidechain_id, height);
                    sc.owner_key_hash = info.payload;
                    sc.owner_auth_required = true;
                    registered_sidechains_in_block.insert(info.sidechain_id);
                    break;
                }

                case DrivechainScriptInfo::Kind::BUNDLE_COMMIT: {
                    if (registered_sidechains_in_block.count(info.sidechain_id) != 0) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                             "drivechain-register-confirmation-required");
                    }
                    auto sc_it = sidechains.find(info.sidechain_id);
                    if (sc_it == sidechains.end()) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                             "drivechain-unknown-sidechain");
                    }
                    Sidechain& sc = sc_it->second;
                    if (sc.owner_auth_required) {
                        if (info.auth_sig.empty()) {
                            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                                 "drivechain-owner-auth-missing");
                        }
                        if (!VerifyDrivechainBundleAuthSig(sc.owner_key_hash, info.sidechain_id, info.payload, info.auth_sig)) {
                            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                                 "drivechain-owner-auth-invalid");
                        }
                    }

                    for (auto it = sc.bundles.begin(); it != sc.bundles.end();) {
                        if (it->first == info.payload) {
                            ++it;
                            continue;
                        }

                        const Bundle& b = it->second;
                        if (b.approved && !b.executed) {
                            return state.Invalid(
                                BlockValidationResult::BLOCK_CONSENSUS,
                                "drivechain-approved-bundle-pending");
                        }

                        // New commits replace older unapproved candidates.
                        if (!b.approved) {
                            it = sc.bundles.erase(it);
                            continue;
                        }
                        ++it;
                    }

                    GetOrCreateBundle(sc, info.payload, height);
                    break;
                }

                case DrivechainScriptInfo::Kind::VOTE_YES:
                case DrivechainScriptInfo::Kind::VOTE_NO: {
                    if (!is_coinbase) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                             "dc-vote-not-coinbase");
                    }
                    if (!voted_sidechains_in_coinbase.insert(info.sidechain_id).second) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                             "dc-vote-duplicate-sidechain");
                    }

                    auto sc_it = sidechains.find(info.sidechain_id);
                    if (sc_it == sidechains.end()) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                             "dc-vote-unknown-sidechain");
                    }
                    auto b_it = sc_it->second.bundles.find(info.payload);
                    if (b_it == sc_it->second.bundles.end()) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                             "dc-vote-unknown-bundle");
                    }

                    Bundle& bundle = b_it->second;
                    if (bundle.approved || bundle.executed) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                             "dc-vote-finalized-bundle");
                    }
                    DrivechainBundleSchedule schedule;
                    if (!ComputeDrivechainBundleSchedule(params, bundle.first_seen_height, schedule)) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                             "drivechain-vote-window-invalid");
                    }

                    if (height < schedule.vote_start_height || height > schedule.vote_end_height) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                             "drivechain-vote-outside-window");
                    }

                    if (info.kind == DrivechainScriptInfo::Kind::VOTE_YES) {
                        ++bundle.yes_votes;
                    } else {
                        ++bundle.no_votes;
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
            const auto execute_key = std::make_pair(execute_info.sidechain_id, execute_info.payload);

            if (m + 1 + (size_t)n > tx->vout.size()) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                     "drivechain-withdrawals-oob");
            }
            if (!executed_bundles_in_block.insert(execute_key).second) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                     "dc-exec-duplicate-bundle");
            }

            auto sc_it = sidechains.find(execute_info.sidechain_id);
            if (sc_it == sidechains.end()) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                     "drivechain-unknown-sidechain");
            }
            Sidechain& sc = sc_it->second;

            auto b_it = sc.bundles.find(execute_info.payload);
            if (b_it == sc.bundles.end()) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                     "drivechain-unknown-bundle");
            }
            Bundle& bundle = b_it->second;

            if (!bundle.approved) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                     "drivechain-execute-unapproved");
            }
            if (bundle.executed) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                     "drivechain-already-executed");
            }

            DrivechainBundleSchedule schedule;
            if (!ComputeDrivechainBundleSchedule(params, bundle.first_seen_height, schedule)) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                     "drivechain-vote-window-invalid");
            }
            if (height <= schedule.vote_end_height) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                     "drivechain-execute-window-open");
            }
            if (height < schedule.executable_height) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                     "drivechain-execute-finalizing");
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

            const uint256 computed = ComputeExecuteBundleHash(*tx, execute_info.sidechain_id, (int)m, n);
            if (computed != execute_info.payload) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                     "drivechain-bundlehash-mismatch");
            }

            const uint8_t sc_id = execute_info.sidechain_id;
            CAmount esc_before = 0;
            auto it_esc_before = escrow_before.find(sc_id);
            if (it_esc_before != escrow_before.end()) esc_before = it_esc_before->second;

            CAmount dep_total = 0;
            auto it_dep_total = deposits_in_block_total.find(sc_id);
            if (it_dep_total != deposits_in_block_total.end()) dep_total = it_dep_total->second;

            const CAmount exec_so_far = executes_in_block[sc_id];
            if (esc_before + dep_total < exec_so_far + withdraw_sum) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                     "drivechain-escrow-insufficient");
            }

            executes_in_block[sc_id] = exec_so_far + withdraw_sum;
            sc.escrow_balance -= withdraw_sum;
            bundle.executed = true;
        }
    }

    for (auto& sc_it : sidechains) {
        for (auto& bundle_it : sc_it.second.bundles) {
            Bundle& bundle = bundle_it.second;
            if (bundle.approved || bundle.executed) {
                continue;
            }

            DrivechainBundleSchedule schedule;
            if (!ComputeDrivechainBundleSchedule(params, bundle.first_seen_height, schedule)) {
                continue;
            }

            if (height >= schedule.approval_height &&
                bundle.yes_votes >= params.nDrivechainApprovalThreshold) {
                bundle.approved = true;
            }
        }
    }

    PruneFailedBundles(sidechains, params, height);
    return true;
}

