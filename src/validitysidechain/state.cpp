// Copyright (c) 2026 AllSageTech, LLC
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <validitysidechain/state.h>

#include <chain.h>
#include <hash.h>
#include <validitysidechain/registry.h>
#include <validitysidechain/script.h>

#include <consensus/validation.h>
#include <primitives/block.h>

namespace {

static constexpr unsigned char QUEUE_APPEND_MAGIC[] = {'V', 'S', 'C', 'Q', 'A', 0x01};
static constexpr unsigned char QUEUE_TOMBSTONE_MAGIC[] = {'V', 'S', 'C', 'Q', 'T', 0x01};

static bool DepositsEqual(const ValiditySidechainDepositData& lhs, const ValiditySidechainDepositData& rhs)
{
    return lhs.deposit_id == rhs.deposit_id &&
           lhs.amount == rhs.amount &&
           lhs.destination_commitment == rhs.destination_commitment &&
           lhs.refund_script_commitment == rhs.refund_script_commitment &&
           lhs.nonce == rhs.nonce;
}

static uint64_t NextQueueIndex(const ValiditySidechain& sidechain)
{
    if (sidechain.queue_entries.empty()) {
        return 0;
    }
    return sidechain.queue_entries.rbegin()->first + 1;
}

static uint256 ComputeQueueAppendRoot(
    uint8_t sidechain_id,
    const uint256& prior_root,
    const ValiditySidechainQueueEntry& entry)
{
    CHashWriter hw(SER_GETHASH, 0);
    hw.write((const char*)QUEUE_APPEND_MAGIC, sizeof(QUEUE_APPEND_MAGIC));
    hw << sidechain_id;
    hw << prior_root;
    hw << entry.queue_index;
    hw << entry.message_kind;
    hw << entry.message_id;
    hw << entry.message_hash;
    return hw.GetHash();
}

static uint256 ComputeQueueTombstoneRoot(
    uint8_t sidechain_id,
    const uint256& prior_root,
    const ValiditySidechainQueueEntry& entry)
{
    CHashWriter hw(SER_GETHASH, 0);
    hw.write((const char*)QUEUE_TOMBSTONE_MAGIC, sizeof(QUEUE_TOMBSTONE_MAGIC));
    hw << sidechain_id;
    hw << prior_root;
    hw << entry.queue_index;
    hw << entry.message_kind;
    hw << entry.message_id;
    hw << entry.message_hash;
    return hw.GetHash();
}

static uint256 ComputeScriptCommitment(const CScript& script)
{
    return Hash(script.begin(), script.end());
}

static void RefreshQueueState(ValiditySidechain& sidechain, int height)
{
    sidechain.queue_state.pending_message_count = 0;
    sidechain.queue_state.pending_deposit_count = 0;
    sidechain.queue_state.pending_force_exit_count = 0;
    sidechain.queue_state.reclaimable_deposit_count = 0;

    for (const auto& [queue_index, entry] : sidechain.queue_entries) {
        (void)queue_index;
        if (entry.status != ValiditySidechainQueueEntry::STATUS_PENDING) {
            continue;
        }

        ++sidechain.queue_state.pending_message_count;
        if (entry.message_kind == ValiditySidechainQueueEntry::MESSAGE_DEPOSIT) {
            ++sidechain.queue_state.pending_deposit_count;
        } else if (entry.message_kind == ValiditySidechainQueueEntry::MESSAGE_FORCE_EXIT) {
            ++sidechain.queue_state.pending_force_exit_count;
        }
    }

    sidechain.queue_state.head_index = 0;
    while (true) {
        const auto it = sidechain.queue_entries.find(sidechain.queue_state.head_index);
        if (it == sidechain.queue_entries.end()) {
            break;
        }
        if (it->second.status == ValiditySidechainQueueEntry::STATUS_PENDING) {
            break;
        }
        ++sidechain.queue_state.head_index;
    }

    for (const auto& [deposit_id, pending_deposit] : sidechain.pending_deposits) {
        (void)deposit_id;
        if (height >= pending_deposit.deposit_height + static_cast<int>(sidechain.config.deposit_reclaim_delay)) {
            ++sidechain.queue_state.reclaimable_deposit_count;
        }
    }
}

static int CountValiditySidechainOutputs(const CTransaction& tx)
{
    int count = 0;
    for (const auto& txout : tx.vout) {
        ValiditySidechainScriptInfo info;
        if (DecodeValiditySidechainScript(txout.scriptPubKey, info)) {
            ++count;
        }
    }
    return count;
}

static bool FindUniqueRefundOutput(
    const CTransaction& tx,
    int marker_index,
    const ValiditySidechainDepositData& deposit)
{
    int refund_output_index = -1;

    for (size_t out_i = 0; out_i < tx.vout.size(); ++out_i) {
        if (static_cast<int>(out_i) == marker_index) {
            continue;
        }

        const CTxOut& txout = tx.vout[out_i];
        if (txout.nValue != deposit.amount) {
            continue;
        }
        if (ComputeScriptCommitment(txout.scriptPubKey) != deposit.refund_script_commitment) {
            continue;
        }
        if (refund_output_index != -1) {
            return false;
        }
        refund_output_index = static_cast<int>(out_i);
    }

    return refund_output_index != -1;
}

} // namespace

const ValiditySidechain* ValiditySidechainState::GetSidechain(uint8_t id) const
{
    const auto it = sidechains.find(id);
    return it == sidechains.end() ? nullptr : &it->second;
}

ValiditySidechain* ValiditySidechainState::GetSidechain(uint8_t id)
{
    const auto it = sidechains.find(id);
    return it == sidechains.end() ? nullptr : &it->second;
}

const ValiditySidechainPendingDeposit* ValiditySidechainState::GetPendingDeposit(uint8_t sidechain_id, const uint256& deposit_id) const
{
    const ValiditySidechain* sidechain = GetSidechain(sidechain_id);
    if (sidechain == nullptr) {
        return nullptr;
    }

    const auto it = sidechain->pending_deposits.find(deposit_id);
    return it == sidechain->pending_deposits.end() ? nullptr : &it->second;
}

ValiditySidechain& ValiditySidechainState::GetOrCreateSidechain(uint8_t id, int registration_height)
{
    auto [it, inserted] = sidechains.emplace(id, ValiditySidechain{});
    ValiditySidechain& sidechain = it->second;
    if (inserted) {
        sidechain.id = id;
        sidechain.registration_height = registration_height;
        sidechain.is_active = true;
        sidechain.current_state_root = sidechain.config.initial_state_root;
        sidechain.current_withdrawal_root = sidechain.config.initial_withdrawal_root;
    } else if (sidechain.registration_height < 0 && registration_height >= 0) {
        sidechain.registration_height = registration_height;
    }
    return sidechain;
}

bool ValiditySidechainState::RegisterSidechain(
    uint8_t id,
    int registration_height,
    const ValiditySidechainConfig& config,
    std::string* error)
{
    if (registration_height < 0) {
        if (error != nullptr) {
            *error = "registration height must be non-negative";
        }
        return false;
    }
    if (!ValidateValiditySidechainConfig(config, error)) {
        return false;
    }
    if (sidechains.count(id) != 0) {
        if (error != nullptr) {
            *error = "sidechain id already registered";
        }
        return false;
    }

    ValiditySidechain sidechain;
    sidechain.id = id;
    sidechain.registration_height = registration_height;
    sidechain.is_active = true;
    sidechain.config = config;
    sidechain.current_state_root = config.initial_state_root;
    sidechain.current_withdrawal_root = config.initial_withdrawal_root;
    RefreshQueueState(sidechain, registration_height);

    sidechains.emplace(id, sidechain);
    if (error != nullptr) {
        error->clear();
    }
    return true;
}

bool ValiditySidechainState::AddDeposit(
    uint8_t sidechain_id,
    int deposit_height,
    const ValiditySidechainDepositData& deposit,
    std::string* error)
{
    if (deposit_height < 0) {
        if (error != nullptr) {
            *error = "deposit height must be non-negative";
        }
        return false;
    }
    if (!MoneyRange(deposit.amount) || deposit.amount <= 0) {
        if (error != nullptr) {
            *error = "deposit amount out of range";
        }
        return false;
    }

    ValiditySidechain* sidechain = GetSidechain(sidechain_id);
    if (sidechain == nullptr || !sidechain->is_active) {
        if (error != nullptr) {
            *error = "unknown validity sidechain";
        }
        return false;
    }
    if (sidechain->pending_deposits.count(deposit.deposit_id) != 0) {
        if (error != nullptr) {
            *error = "deposit id already pending";
        }
        return false;
    }
    if (sidechain->escrow_balance < 0 ||
        sidechain->escrow_balance > MAX_MONEY - deposit.amount) {
        if (error != nullptr) {
            *error = "escrow balance out of range";
        }
        return false;
    }

    ValiditySidechainQueueEntry entry;
    entry.queue_index = NextQueueIndex(*sidechain);
    entry.message_kind = ValiditySidechainQueueEntry::MESSAGE_DEPOSIT;
    entry.status = ValiditySidechainQueueEntry::STATUS_PENDING;
    entry.message_id = deposit.deposit_id;
    entry.message_hash = ComputeValiditySidechainDepositMessageHash(sidechain_id, deposit);
    entry.created_height = deposit_height;

    ValiditySidechainPendingDeposit pending_deposit;
    pending_deposit.deposit = deposit;
    pending_deposit.deposit_height = deposit_height;
    pending_deposit.queue_index = entry.queue_index;
    pending_deposit.message_hash = entry.message_hash;

    sidechain->queue_state.root = ComputeQueueAppendRoot(sidechain_id, sidechain->queue_state.root, entry);
    sidechain->queue_entries.emplace(entry.queue_index, entry);
    sidechain->pending_deposits.emplace(deposit.deposit_id, pending_deposit);
    sidechain->escrow_balance += deposit.amount;
    RefreshQueueState(*sidechain, deposit_height);
    if (error != nullptr) {
        error->clear();
    }
    return true;
}

bool ValiditySidechainState::ReclaimDeposit(
    uint8_t sidechain_id,
    int reclaim_height,
    const ValiditySidechainDepositData& deposit,
    std::string* error)
{
    ValiditySidechain* sidechain = GetSidechain(sidechain_id);
    if (sidechain == nullptr || !sidechain->is_active) {
        if (error != nullptr) {
            *error = "unknown validity sidechain";
        }
        return false;
    }

    auto pending_it = sidechain->pending_deposits.find(deposit.deposit_id);
    if (pending_it == sidechain->pending_deposits.end()) {
        if (error != nullptr) {
            *error = "deposit id is not pending";
        }
        return false;
    }

    const ValiditySidechainPendingDeposit& pending_deposit = pending_it->second;
    if (!DepositsEqual(pending_deposit.deposit, deposit)) {
        if (error != nullptr) {
            *error = "deposit reclaim metadata does not match pending deposit";
        }
        return false;
    }
    if (reclaim_height < pending_deposit.deposit_height + static_cast<int>(sidechain->config.deposit_reclaim_delay)) {
        if (error != nullptr) {
            *error = "deposit reclaim delay not reached";
        }
        return false;
    }
    if (sidechain->escrow_balance < deposit.amount) {
        if (error != nullptr) {
            *error = "escrow balance insufficient for reclaim";
        }
        return false;
    }

    auto queue_it = sidechain->queue_entries.find(pending_deposit.queue_index);
    if (queue_it == sidechain->queue_entries.end()) {
        if (error != nullptr) {
            *error = "pending deposit queue entry missing";
        }
        return false;
    }
    if (queue_it->second.status != ValiditySidechainQueueEntry::STATUS_PENDING) {
        if (error != nullptr) {
            *error = "pending deposit queue entry already finalized";
        }
        return false;
    }

    queue_it->second.status = ValiditySidechainQueueEntry::STATUS_TOMBSTONED;
    sidechain->queue_state.root = ComputeQueueTombstoneRoot(sidechain_id, sidechain->queue_state.root, queue_it->second);
    sidechain->escrow_balance -= deposit.amount;
    sidechain->pending_deposits.erase(pending_it);
    RefreshQueueState(*sidechain, reclaim_height);
    if (error != nullptr) {
        error->clear();
    }
    return true;
}

bool ValiditySidechainState::ConnectBlock(const CBlock& block, const CBlockIndex* pindex, BlockValidationState& state)
{
    const int height = pindex->nHeight;

    for (const auto& tx : block.vtx) {
        if (CountValiditySidechainOutputs(*tx) > 1) {
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "validitysidechain-multi-marker");
        }

        for (size_t out_i = 0; out_i < tx->vout.size(); ++out_i) {
            const CTxOut& txout = tx->vout[out_i];
            ValiditySidechainScriptInfo info;
            if (!DecodeValiditySidechainScript(txout.scriptPubKey, info)) {
                continue;
            }

            switch (info.kind) {
                case ValiditySidechainScriptInfo::Kind::REGISTER_VALIDITY_SIDECHAIN: {
                    ValiditySidechainConfig config;
                    if (!DecodeValiditySidechainConfig(info.primary_metadata, config)) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "validitysidechain-register-config-bad");
                    }
                    if (ComputeValiditySidechainConfigHash(config) != info.payload) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "validitysidechain-register-config-mismatch");
                    }

                    std::string error;
                    if (!RegisterSidechain(info.sidechain_id, height, config, &error)) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "validitysidechain-register-invalid", error);
                    }
                    break;
                }

                case ValiditySidechainScriptInfo::Kind::DEPOSIT_TO_VALIDITY_SIDECHAIN: {
                    ValiditySidechainDepositData deposit;
                    if (!DecodeValiditySidechainDepositData(info.primary_metadata, deposit)) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "validitysidechain-deposit-data-bad");
                    }
                    if (ComputeValiditySidechainDepositMessageHash(info.sidechain_id, deposit) != info.payload) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "validitysidechain-deposit-hash-mismatch");
                    }
                    if (txout.nValue != deposit.amount) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "validitysidechain-deposit-amount-mismatch");
                    }

                    std::string error;
                    if (!AddDeposit(info.sidechain_id, height, deposit, &error)) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "validitysidechain-deposit-invalid", error);
                    }
                    break;
                }

                case ValiditySidechainScriptInfo::Kind::RECLAIM_STALE_DEPOSIT: {
                    if (txout.nValue != 0) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "validitysidechain-reclaim-marker-value");
                    }

                    ValiditySidechainDepositData deposit;
                    if (!DecodeValiditySidechainDepositData(info.primary_metadata, deposit)) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "validitysidechain-reclaim-data-bad");
                    }
                    if (deposit.deposit_id != info.payload) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "validitysidechain-reclaim-payload-mismatch");
                    }
                    if (!FindUniqueRefundOutput(*tx, static_cast<int>(out_i), deposit)) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "validitysidechain-reclaim-refund-output");
                    }

                    std::string error;
                    if (!ReclaimDeposit(info.sidechain_id, height, deposit, &error)) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "validitysidechain-reclaim-invalid", error);
                    }
                    break;
                }

                default:
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "validitysidechain-kind-not-enabled");
            }
        }
    }

    for (auto& [sidechain_id, sidechain] : sidechains) {
        (void)sidechain_id;
        RefreshQueueState(sidechain, height);
    }

    return true;
}

void ValiditySidechainState::Reset()
{
    sidechains.clear();
}
