// Copyright (c) 2026 AllSageTech, LLC
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <validitysidechain/state.h>

#include <chain.h>
#include <drivechain/script.h>
#include <hash.h>
#include <validitysidechain/registry.h>
#include <validitysidechain/script.h>
#include <validitysidechain/verifier.h>

#include <consensus/validation.h>
#include <primitives/block.h>

namespace {

static constexpr unsigned char QUEUE_APPEND_MAGIC[] = {'V', 'S', 'C', 'Q', 'A', 0x01};
static constexpr unsigned char QUEUE_CONSUME_MAGIC[] = {'V', 'S', 'C', 'Q', 'C', 0x01};
static constexpr unsigned char QUEUE_PREFIX_COMMITMENT_MAGIC[] = {'V', 'S', 'C', 'Q', 'P', 0x01};
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

static uint256 ComputeQueueConsumeRoot(
    uint8_t sidechain_id,
    const uint256& prior_root,
    const ValiditySidechainQueueEntry& entry)
{
    CHashWriter hw(SER_GETHASH, 0);
    hw.write((const char*)QUEUE_CONSUME_MAGIC, sizeof(QUEUE_CONSUME_MAGIC));
    hw << sidechain_id;
    hw << prior_root;
    hw << entry.queue_index;
    hw << entry.message_kind;
    hw << entry.message_id;
    hw << entry.message_hash;
    return hw.GetHash();
}

static uint256 ComputeQueuePrefixCommitmentStep(
    uint8_t sidechain_id,
    const uint256& prior_commitment,
    const ValiditySidechainQueueEntry& entry)
{
    CHashWriter hw(SER_GETHASH, 0);
    hw.write((const char*)QUEUE_PREFIX_COMMITMENT_MAGIC, sizeof(QUEUE_PREFIX_COMMITMENT_MAGIC));
    hw << sidechain_id;
    hw << prior_commitment;
    hw << entry.queue_index;
    hw << entry.message_kind;
    hw << entry.message_id;
    hw << entry.message_hash;
    return hw.GetHash();
}

static uint256 ComputeScriptCommitment(const CScript& script)
{
    return Hash(script);
}

static void RefreshQueueState(ValiditySidechain& sidechain, int height)
{
    sidechain.queue_state.pending_message_count = 0;
    sidechain.queue_state.pending_deposit_count = 0;
    sidechain.queue_state.pending_force_exit_count = 0;
    sidechain.queue_state.matured_force_exit_count = 0;
    sidechain.queue_state.reclaimable_deposit_count = 0;

    for (const auto& [queue_index, entry] : sidechain.queue_entries) {
        (void)queue_index;
        if (entry.status != ValiditySidechainQueueEntry::QUEUE_STATUS_PENDING) {
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
        if (it->second.status == ValiditySidechainQueueEntry::QUEUE_STATUS_PENDING) {
            break;
        }
        ++sidechain.queue_state.head_index;
    }

    for (const auto& [deposit_id, pending_deposit] : sidechain.pending_deposits) {
        (void)deposit_id;
        const auto queue_it = sidechain.queue_entries.find(pending_deposit.queue_index);
        if (queue_it == sidechain.queue_entries.end() ||
            queue_it->second.status != ValiditySidechainQueueEntry::QUEUE_STATUS_PENDING) {
            continue;
        }
        if (height >= pending_deposit.deposit_height + static_cast<int>(sidechain.config.deposit_reclaim_delay)) {
            ++sidechain.queue_state.reclaimable_deposit_count;
        }
    }

    for (const auto& [request_hash, pending_force_exit] : sidechain.pending_force_exits) {
        (void)request_hash;
        const auto queue_it = sidechain.queue_entries.find(pending_force_exit.queue_index);
        if (queue_it == sidechain.queue_entries.end() ||
            queue_it->second.status != ValiditySidechainQueueEntry::QUEUE_STATUS_PENDING) {
            continue;
        }
        if (height >= pending_force_exit.request_height + static_cast<int>(sidechain.config.force_inclusion_delay)) {
            ++sidechain.queue_state.matured_force_exit_count;
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

static bool MatchWithdrawalOutputs(
    const CTransaction& tx,
    int marker_index,
    const std::vector<ValiditySidechainWithdrawalProof>& withdrawal_proofs)
{
    if (withdrawal_proofs.empty()) {
        return false;
    }

    const size_t start = static_cast<size_t>(marker_index) + 1;
    if (tx.vout.size() < start + withdrawal_proofs.size()) {
        return false;
    }

    for (size_t i = 0; i < withdrawal_proofs.size(); ++i) {
        const CTxOut& txout = tx.vout[start + i];
        const ValiditySidechainWithdrawalLeaf& withdrawal = withdrawal_proofs[i].withdrawal;
        ValiditySidechainScriptInfo validity_info;
        DrivechainScriptInfo drivechain_info;
        if (DecodeValiditySidechainScript(txout.scriptPubKey, validity_info) ||
            DecodeDrivechainScript(txout.scriptPubKey, drivechain_info) ||
            txout.nValue != withdrawal.amount) {
            return false;
        }
        if (ComputeScriptCommitment(txout.scriptPubKey) != withdrawal.destination_commitment) {
            return false;
        }
    }

    return true;
}

static bool MatchEscapeExitOutputs(
    const CTransaction& tx,
    int marker_index,
    const std::vector<ValiditySidechainEscapeExitProof>& exit_proofs)
{
    if (exit_proofs.empty()) {
        return false;
    }

    const size_t start = static_cast<size_t>(marker_index) + 1;
    if (tx.vout.size() < start + exit_proofs.size()) {
        return false;
    }

    for (size_t i = 0; i < exit_proofs.size(); ++i) {
        const CTxOut& txout = tx.vout[start + i];
        const ValiditySidechainEscapeExitLeaf& exit = exit_proofs[i].exit;
        ValiditySidechainScriptInfo validity_info;
        DrivechainScriptInfo drivechain_info;
        if (DecodeValiditySidechainScript(txout.scriptPubKey, validity_info) ||
            DecodeDrivechainScript(txout.scriptPubKey, drivechain_info) ||
            txout.nValue != exit.amount) {
            return false;
        }
        if (ComputeScriptCommitment(txout.scriptPubKey) != exit.destination_commitment) {
            return false;
        }
    }

    return true;
}

static int GetLastProgressHeight(const ValiditySidechain& sidechain)
{
    if (sidechain.latest_batch_number == 0) {
        return sidechain.registration_height;
    }
    const auto it = sidechain.accepted_batches.find(sidechain.latest_batch_number);
    if (it == sidechain.accepted_batches.end()) {
        return sidechain.registration_height;
    }
    return it->second.accepted_height;
}

static bool ComputeConsumedQueueRoot(
    const ValiditySidechain& sidechain,
    uint8_t sidechain_id,
    uint32_t consumed_queue_messages,
    uint256& out_root,
    std::string* error)
{
    out_root = sidechain.queue_state.root;
    uint64_t next_queue_index = sidechain.queue_state.head_index;

    for (uint32_t i = 0; i < consumed_queue_messages; ++i) {
        const auto queue_it = sidechain.queue_entries.find(next_queue_index);
        if (queue_it == sidechain.queue_entries.end()) {
            if (error != nullptr) {
                *error = "batch references missing queue entry";
            }
            return false;
        }
        if (queue_it->second.status != ValiditySidechainQueueEntry::QUEUE_STATUS_PENDING) {
            if (error != nullptr) {
                *error = "batch queue consumption is not a contiguous pending prefix";
            }
            return false;
        }

        out_root = ComputeQueueConsumeRoot(sidechain_id, out_root, queue_it->second);
        ++next_queue_index;
    }

    return true;
}

static bool ComputeQueuePrefixCommitment(
    const ValiditySidechain& sidechain,
    uint8_t sidechain_id,
    uint32_t consumed_queue_messages,
    uint256& out_commitment,
    std::string* error)
{
    out_commitment.SetNull();
    uint64_t next_queue_index = sidechain.queue_state.head_index;

    for (uint32_t i = 0; i < consumed_queue_messages; ++i) {
        const auto queue_it = sidechain.queue_entries.find(next_queue_index);
        if (queue_it == sidechain.queue_entries.end()) {
            if (error != nullptr) {
                *error = "batch references missing queue entry";
            }
            return false;
        }
        if (queue_it->second.status != ValiditySidechainQueueEntry::QUEUE_STATUS_PENDING) {
            if (error != nullptr) {
                *error = "batch queue consumption is not a contiguous pending prefix";
            }
            return false;
        }

        out_commitment = ComputeQueuePrefixCommitmentStep(sidechain_id, out_commitment, queue_it->second);
        ++next_queue_index;
    }

    return true;
}

static bool ConsumeQueuePrefix(
    ValiditySidechain& sidechain,
    uint8_t sidechain_id,
    uint32_t consumed_queue_messages,
    std::string* error)
{
    uint256 root_after;
    if (!ComputeConsumedQueueRoot(sidechain, sidechain_id, consumed_queue_messages, root_after, error)) {
        return false;
    }

    std::vector<uint256> consumed_deposit_ids;
    std::vector<uint256> consumed_force_exit_ids;
    consumed_deposit_ids.reserve(consumed_queue_messages);
    consumed_force_exit_ids.reserve(consumed_queue_messages);

    uint64_t next_queue_index = sidechain.queue_state.head_index;
    for (uint32_t i = 0; i < consumed_queue_messages; ++i) {
        const auto queue_it = sidechain.queue_entries.find(next_queue_index);
        if (queue_it == sidechain.queue_entries.end() ||
            queue_it->second.status != ValiditySidechainQueueEntry::QUEUE_STATUS_PENDING) {
            if (error != nullptr) {
                *error = "batch queue entry changed during consumption";
            }
            return false;
        }

        switch (queue_it->second.message_kind) {
            case ValiditySidechainQueueEntry::MESSAGE_DEPOSIT: {
                const auto pending_it = sidechain.pending_deposits.find(queue_it->second.message_id);
                if (pending_it == sidechain.pending_deposits.end()) {
                    if (error != nullptr) {
                        *error = "pending deposit record missing for consumed queue entry";
                    }
                    return false;
                }
                if (pending_it->second.queue_index != queue_it->second.queue_index ||
                    pending_it->second.message_hash != queue_it->second.message_hash) {
                    if (error != nullptr) {
                        *error = "pending deposit record does not match consumed queue entry";
                    }
                    return false;
                }
                consumed_deposit_ids.push_back(queue_it->second.message_id);
                break;
            }

            case ValiditySidechainQueueEntry::MESSAGE_FORCE_EXIT: {
                const auto pending_it = sidechain.pending_force_exits.find(queue_it->second.message_id);
                if (pending_it == sidechain.pending_force_exits.end()) {
                    if (error != nullptr) {
                        *error = "pending force-exit record missing for consumed queue entry";
                    }
                    return false;
                }
                if (pending_it->second.queue_index != queue_it->second.queue_index ||
                    pending_it->second.request_hash != queue_it->second.message_hash) {
                    if (error != nullptr) {
                        *error = "pending force-exit record does not match consumed queue entry";
                    }
                    return false;
                }
                consumed_force_exit_ids.push_back(queue_it->second.message_id);
                break;
            }

            default:
                if (error != nullptr) {
                    *error = "unknown queue entry kind in consumed prefix";
                }
                return false;
        }
        ++next_queue_index;
    }

    next_queue_index = sidechain.queue_state.head_index;
    for (uint32_t i = 0; i < consumed_queue_messages; ++i) {
        auto queue_it = sidechain.queue_entries.find(next_queue_index);
        if (queue_it == sidechain.queue_entries.end() ||
            queue_it->second.status != ValiditySidechainQueueEntry::QUEUE_STATUS_PENDING) {
            if (error != nullptr) {
                *error = "batch queue entry changed during consumption";
            }
            return false;
        }
        queue_it->second.status = ValiditySidechainQueueEntry::QUEUE_STATUS_CONSUMED;
        ++next_queue_index;
    }

    for (const auto& deposit_id : consumed_deposit_ids) {
        sidechain.pending_deposits.erase(deposit_id);
    }
    for (const auto& request_hash : consumed_force_exit_ids) {
        sidechain.pending_force_exits.erase(request_hash);
    }

    sidechain.queue_state.root = root_after;
    return true;
}

static bool ComputeRequiredConsumedQueueMessages(
    const ValiditySidechain& sidechain,
    int accepted_height,
    uint32_t& out_required,
    std::string* error)
{
    if (accepted_height < 0) {
        if (error != nullptr) {
            *error = "accepted height must be non-negative";
        }
        return false;
    }

    out_required = 0;
    uint32_t reachable_prefix_size = 0;
    uint64_t next_queue_index = sidechain.queue_state.head_index;

    while (true) {
        const auto queue_it = sidechain.queue_entries.find(next_queue_index);
        if (queue_it == sidechain.queue_entries.end() ||
            queue_it->second.status != ValiditySidechainQueueEntry::QUEUE_STATUS_PENDING) {
            break;
        }

        ++reachable_prefix_size;
        switch (queue_it->second.message_kind) {
            case ValiditySidechainQueueEntry::MESSAGE_DEPOSIT: {
                const auto pending_it = sidechain.pending_deposits.find(queue_it->second.message_id);
                if (pending_it == sidechain.pending_deposits.end()) {
                    if (error != nullptr) {
                        *error = "pending deposit record missing for queue entry";
                    }
                    return false;
                }
                if (pending_it->second.queue_index != queue_it->second.queue_index ||
                    pending_it->second.message_hash != queue_it->second.message_hash) {
                    if (error != nullptr) {
                        *error = "pending deposit record does not match queue entry";
                    }
                    return false;
                }
                break;
            }

            case ValiditySidechainQueueEntry::MESSAGE_FORCE_EXIT: {
                const auto pending_it = sidechain.pending_force_exits.find(queue_it->second.message_id);
                if (pending_it == sidechain.pending_force_exits.end()) {
                    if (error != nullptr) {
                        *error = "pending force-exit record missing for queue entry";
                    }
                    return false;
                }
                if (pending_it->second.queue_index != queue_it->second.queue_index ||
                    pending_it->second.request_hash != queue_it->second.message_hash) {
                    if (error != nullptr) {
                        *error = "pending force-exit record does not match queue entry";
                    }
                    return false;
                }
                if (accepted_height >= pending_it->second.request_height + static_cast<int>(sidechain.config.force_inclusion_delay)) {
                    out_required = reachable_prefix_size;
                }
                break;
            }

            default:
                if (error != nullptr) {
                    *error = "unknown queue entry kind";
                }
                return false;
        }
        ++next_queue_index;
    }

    return true;
}

} // namespace

bool ComputeValiditySidechainQueuePrefixCommitment(
    const ValiditySidechain& sidechain,
    uint8_t sidechain_id,
    uint32_t consumed_queue_messages,
    uint256& out_commitment,
    std::string* error)
{
    return ComputeQueuePrefixCommitment(
        sidechain,
        sidechain_id,
        consumed_queue_messages,
        out_commitment,
        error);
}

bool GetValiditySidechainConsumedQueueEntries(
    const ValiditySidechain& sidechain,
    uint32_t consumed_queue_messages,
    std::vector<ValiditySidechainQueueEntry>& out_entries,
    std::string* error)
{
    out_entries.clear();
    out_entries.reserve(consumed_queue_messages);

    uint64_t next_queue_index = sidechain.queue_state.head_index;
    for (uint32_t i = 0; i < consumed_queue_messages; ++i) {
        const auto queue_it = sidechain.queue_entries.find(next_queue_index);
        if (queue_it == sidechain.queue_entries.end()) {
            if (error != nullptr) {
                *error = "batch references missing queue entry";
            }
            return false;
        }
        if (queue_it->second.status != ValiditySidechainQueueEntry::QUEUE_STATUS_PENDING) {
            if (error != nullptr) {
                *error = "batch queue consumption is not a contiguous pending prefix";
            }
            return false;
        }

        out_entries.push_back(queue_it->second);
        ++next_queue_index;
    }

    return true;
}

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

const ValiditySidechainAcceptedBatch* ValiditySidechainState::GetAcceptedBatch(uint8_t sidechain_id, uint32_t batch_number) const
{
    const ValiditySidechain* sidechain = GetSidechain(sidechain_id);
    if (sidechain == nullptr) {
        return nullptr;
    }

    const auto it = sidechain->accepted_batches.find(batch_number);
    return it == sidechain->accepted_batches.end() ? nullptr : &it->second;
}

const ValiditySidechainAcceptedBatch* ValiditySidechainState::GetAcceptedBatchById(uint8_t sidechain_id, const uint256& accepted_batch_id) const
{
    const ValiditySidechain* sidechain = GetSidechain(sidechain_id);
    if (sidechain == nullptr) {
        return nullptr;
    }

    for (const auto& entry : sidechain->accepted_batches) {
        const ValiditySidechainAcceptedBatch& batch = entry.second;
        if (ComputeValiditySidechainAcceptedBatchId(sidechain_id, batch.batch_number, batch.withdrawal_root) == accepted_batch_id) {
            return &batch;
        }
    }

    return nullptr;
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

const ValiditySidechainPendingForceExit* ValiditySidechainState::GetPendingForceExit(uint8_t sidechain_id, const uint256& request_hash) const
{
    const ValiditySidechain* sidechain = GetSidechain(sidechain_id);
    if (sidechain == nullptr) {
        return nullptr;
    }

    const auto it = sidechain->pending_force_exits.find(request_hash);
    return it == sidechain->pending_force_exits.end() ? nullptr : &it->second;
}

bool ValiditySidechainState::HasExecutedWithdrawal(uint8_t sidechain_id, const uint256& withdrawal_id) const
{
    const ValiditySidechain* sidechain = GetSidechain(sidechain_id);
    if (sidechain == nullptr) {
        return false;
    }
    return sidechain->executed_withdrawal_ids.count(withdrawal_id) != 0;
}

bool ValiditySidechainState::HasExecutedEscapeExit(uint8_t sidechain_id, const uint256& exit_id) const
{
    const ValiditySidechain* sidechain = GetSidechain(sidechain_id);
    if (sidechain == nullptr) {
        return false;
    }
    return sidechain->executed_escape_exit_ids.count(exit_id) != 0;
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
    entry.status = ValiditySidechainQueueEntry::QUEUE_STATUS_PENDING;
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

bool ValiditySidechainState::AddForceExitRequest(
    uint8_t sidechain_id,
    int request_height,
    const ValiditySidechainForceExitData& request,
    std::string* error)
{
    if (request_height < 0) {
        if (error != nullptr) {
            *error = "force-exit request height must be non-negative";
        }
        return false;
    }
    if (!MoneyRange(request.max_exit_amount) || request.max_exit_amount <= 0) {
        if (error != nullptr) {
            *error = "force-exit amount out of range";
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

    const uint256 request_hash = ComputeValiditySidechainForceExitHash(sidechain_id, request);
    if (sidechain->pending_force_exits.count(request_hash) != 0) {
        if (error != nullptr) {
            *error = "force-exit request already pending";
        }
        return false;
    }

    ValiditySidechainQueueEntry entry;
    entry.queue_index = NextQueueIndex(*sidechain);
    entry.message_kind = ValiditySidechainQueueEntry::MESSAGE_FORCE_EXIT;
    entry.status = ValiditySidechainQueueEntry::QUEUE_STATUS_PENDING;
    entry.message_id = request_hash;
    entry.message_hash = request_hash;
    entry.created_height = request_height;

    ValiditySidechainPendingForceExit pending_request;
    pending_request.request = request;
    pending_request.request_height = request_height;
    pending_request.queue_index = entry.queue_index;
    pending_request.request_hash = request_hash;

    sidechain->queue_state.root = ComputeQueueAppendRoot(sidechain_id, sidechain->queue_state.root, entry);
    sidechain->queue_entries.emplace(entry.queue_index, entry);
    sidechain->pending_force_exits.emplace(request_hash, pending_request);
    RefreshQueueState(*sidechain, request_height);
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
    if (queue_it->second.status != ValiditySidechainQueueEntry::QUEUE_STATUS_PENDING) {
        if (error != nullptr) {
            *error = "pending deposit queue entry already finalized";
        }
        return false;
    }

    queue_it->second.status = ValiditySidechainQueueEntry::QUEUE_STATUS_TOMBSTONED;
    sidechain->queue_state.root = ComputeQueueTombstoneRoot(sidechain_id, sidechain->queue_state.root, queue_it->second);
    sidechain->escrow_balance -= deposit.amount;
    sidechain->pending_deposits.erase(pending_it);
    RefreshQueueState(*sidechain, reclaim_height);
    if (error != nullptr) {
        error->clear();
    }
    return true;
}

bool ValiditySidechainState::AcceptBatch(
    uint8_t sidechain_id,
    int accepted_height,
    const ValiditySidechainBatchPublicInputs& public_inputs,
    const std::vector<unsigned char>& proof_bytes,
    const std::vector<std::vector<unsigned char>>& data_chunks,
    std::string* error)
{
    if (accepted_height < 0) {
        if (error != nullptr) {
            *error = "accepted height must be non-negative";
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
    if (public_inputs.batch_number == 0) {
        if (error != nullptr) {
            *error = "batch number must be non-zero";
        }
        return false;
    }
    if (public_inputs.batch_number <= sidechain->latest_batch_number ||
        sidechain->accepted_batches.count(public_inputs.batch_number) != 0) {
        if (error != nullptr) {
            *error = "batch number is not strictly monotonic";
        }
        return false;
    }
    if (public_inputs.prior_state_root != sidechain->current_state_root) {
        if (error != nullptr) {
            *error = "prior state root does not match current state root";
        }
        return false;
    }
    if (public_inputs.l1_message_root_before != sidechain->queue_state.root) {
        if (error != nullptr) {
            *error = "batch queue root before does not match current queue root";
        }
        return false;
    }
    if (IsValiditySidechainSingleEntryExperimentalQueueProfile(sidechain->config) &&
        public_inputs.consumed_queue_messages > 1) {
        if (error != nullptr) {
            *error = "experimental real profile currently supports at most one consumed queue message";
        }
        return false;
    }

    ValiditySidechainBatchVerifierMode verifier_mode;
    std::string verifier_error;
    if (!VerifyValiditySidechainBatch(
            sidechain->config,
            sidechain_id,
            public_inputs,
            proof_bytes,
            data_chunks,
            sidechain->current_state_root,
            sidechain->current_withdrawal_root,
            sidechain->current_data_root,
            sidechain->queue_state.root,
            &verifier_error,
            &verifier_mode)) {
        if (error != nullptr) {
            *error = verifier_error;
        }
        return false;
    }
    (void)verifier_mode;

    uint256 expected_l1_message_root_after;
    uint256 expected_queue_prefix_commitment;
    std::string queue_error;
    uint32_t required_consumed_queue_messages = 0;
    if (!ComputeRequiredConsumedQueueMessages(*sidechain, accepted_height, required_consumed_queue_messages, &queue_error)) {
        if (error != nullptr) {
            *error = queue_error;
        }
        return false;
    }
    if (public_inputs.consumed_queue_messages < required_consumed_queue_messages) {
        if (error != nullptr) {
            *error = "batch must consume all matured force-exit requests in reachable queue prefix";
        }
        return false;
    }

    if (!ComputeConsumedQueueRoot(*sidechain, sidechain_id, public_inputs.consumed_queue_messages, expected_l1_message_root_after, &queue_error)) {
        if (error != nullptr) {
            *error = queue_error;
        }
        return false;
    }
    if (!ComputeQueuePrefixCommitment(*sidechain, sidechain_id, public_inputs.consumed_queue_messages, expected_queue_prefix_commitment, &queue_error)) {
        if (error != nullptr) {
            *error = queue_error;
        }
        return false;
    }
    if (expected_l1_message_root_after != public_inputs.l1_message_root_after) {
        if (error != nullptr) {
            *error = "batch queue root after does not match consumed prefix";
        }
        return false;
    }
    if (expected_queue_prefix_commitment != public_inputs.queue_prefix_commitment) {
        if (error != nullptr) {
            *error = "batch queue prefix commitment does not match consumed prefix";
        }
        return false;
    }

    if (!ConsumeQueuePrefix(*sidechain, sidechain_id, public_inputs.consumed_queue_messages, &queue_error)) {
        if (error != nullptr) {
            *error = queue_error;
        }
        return false;
    }

    sidechain->current_state_root = public_inputs.new_state_root;
    sidechain->current_withdrawal_root = public_inputs.withdrawal_root;
    sidechain->current_data_root = public_inputs.data_root;
    sidechain->latest_batch_number = public_inputs.batch_number;

    ValiditySidechainAcceptedBatch batch;
    batch.batch_number = public_inputs.batch_number;
    batch.prior_state_root = public_inputs.prior_state_root;
    batch.new_state_root = public_inputs.new_state_root;
    batch.l1_message_root_before = public_inputs.l1_message_root_before;
    batch.l1_message_root_after = public_inputs.l1_message_root_after;
    batch.consumed_queue_messages = public_inputs.consumed_queue_messages;
    batch.queue_prefix_commitment = public_inputs.queue_prefix_commitment;
    batch.withdrawal_root = public_inputs.withdrawal_root;
    batch.data_root = public_inputs.data_root;
    batch.accepted_height = accepted_height;
    sidechain->accepted_batches.emplace(batch.batch_number, batch);

    RefreshQueueState(*sidechain, accepted_height);
    if (error != nullptr) {
        error->clear();
    }
    return true;
}

bool ValiditySidechainState::ExecuteWithdrawals(
    uint8_t sidechain_id,
    const uint256& accepted_batch_id,
    const std::vector<ValiditySidechainWithdrawalProof>& withdrawal_proofs,
    std::string* error)
{
    ValiditySidechain* sidechain = GetSidechain(sidechain_id);
    if (sidechain == nullptr || !sidechain->is_active) {
        if (error != nullptr) {
            *error = "unknown validity sidechain";
        }
        return false;
    }
    if (withdrawal_proofs.empty()) {
        if (error != nullptr) {
            *error = "withdrawal execution metadata is empty";
        }
        return false;
    }

    const ValiditySidechainAcceptedBatch* accepted_batch = GetAcceptedBatchById(sidechain_id, accepted_batch_id);
    if (accepted_batch == nullptr) {
        if (error != nullptr) {
            *error = "accepted batch not found";
        }
        return false;
    }

    CAmount total_amount = 0;
    std::set<uint256> new_ids;
    for (const auto& proof : withdrawal_proofs) {
        const ValiditySidechainWithdrawalLeaf& withdrawal = proof.withdrawal;
        if (!VerifyValiditySidechainWithdrawalProof(proof, accepted_batch->withdrawal_root)) {
            if (error != nullptr) {
                *error = "withdrawal proof does not match accepted withdrawal root";
            }
            return false;
        }
        if (!MoneyRange(withdrawal.amount) || withdrawal.amount <= 0) {
            if (error != nullptr) {
                *error = "withdrawal amount out of range";
            }
            return false;
        }
        if (!new_ids.insert(withdrawal.withdrawal_id).second) {
            if (error != nullptr) {
                *error = "duplicate withdrawal id in execution";
            }
            return false;
        }
        if (sidechain->executed_withdrawal_ids.count(withdrawal.withdrawal_id) != 0) {
            if (error != nullptr) {
                *error = "withdrawal id already executed";
            }
            return false;
        }
        if (total_amount > MAX_MONEY - withdrawal.amount) {
            if (error != nullptr) {
                *error = "withdrawal total out of range";
            }
            return false;
        }
        total_amount += withdrawal.amount;
    }
    if (!MoneyRange(total_amount) || sidechain->escrow_balance < total_amount) {
        if (error != nullptr) {
            *error = "escrow balance insufficient for withdrawals";
        }
        return false;
    }

    sidechain->escrow_balance -= total_amount;
    sidechain->executed_withdrawal_ids.insert(new_ids.begin(), new_ids.end());
    sidechain->executed_withdrawal_count += new_ids.size();
    if (error != nullptr) {
        error->clear();
    }
    return true;
}

bool ValiditySidechainState::ExecuteEscapeExits(
    uint8_t sidechain_id,
    int execution_height,
    const uint256& state_root_reference,
    const std::vector<ValiditySidechainEscapeExitProof>& exit_proofs,
    std::string* error)
{
    if (execution_height < 0) {
        if (error != nullptr) {
            *error = "escape-exit execution height must be non-negative";
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
    if (!IsValiditySidechainScaffoldingOnlyProfile(sidechain->config)) {
        if (error != nullptr) {
            *error = "escape exits are not implemented for non-scaffold profiles";
        }
        return false;
    }
    if (exit_proofs.empty()) {
        if (error != nullptr) {
            *error = "escape-exit metadata is empty";
        }
        return false;
    }
    if (state_root_reference != sidechain->current_state_root) {
        if (error != nullptr) {
            *error = "escape-exit state root does not match current state root";
        }
        return false;
    }

    const int last_progress_height = GetLastProgressHeight(*sidechain);
    if (execution_height < last_progress_height + static_cast<int>(sidechain->config.escape_hatch_delay)) {
        if (error != nullptr) {
            *error = "escape hatch delay not reached";
        }
        return false;
    }

    CAmount total_amount = 0;
    std::set<uint256> new_ids;
    for (const auto& proof : exit_proofs) {
        const ValiditySidechainEscapeExitLeaf& exit = proof.exit;
        if (!VerifyValiditySidechainEscapeExitProof(proof, state_root_reference)) {
            if (error != nullptr) {
                *error = "escape-exit proof does not match referenced state root";
            }
            return false;
        }
        if (!MoneyRange(exit.amount) || exit.amount <= 0) {
            if (error != nullptr) {
                *error = "escape-exit amount out of range";
            }
            return false;
        }
        if (!new_ids.insert(exit.exit_id).second) {
            if (error != nullptr) {
                *error = "duplicate escape-exit id in execution";
            }
            return false;
        }
        if (sidechain->executed_escape_exit_ids.count(exit.exit_id) != 0) {
            if (error != nullptr) {
                *error = "escape-exit id already executed";
            }
            return false;
        }
        if (total_amount > MAX_MONEY - exit.amount) {
            if (error != nullptr) {
                *error = "escape-exit total out of range";
            }
            return false;
        }
        total_amount += exit.amount;
    }
    if (!MoneyRange(total_amount) || sidechain->escrow_balance < total_amount) {
        if (error != nullptr) {
            *error = "escrow balance insufficient for escape exits";
        }
        return false;
    }

    sidechain->escrow_balance -= total_amount;
    sidechain->executed_escape_exit_ids.insert(new_ids.begin(), new_ids.end());
    sidechain->executed_escape_exit_count += new_ids.size();
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

                case ValiditySidechainScriptInfo::Kind::REQUEST_FORCE_EXIT: {
                    if (txout.nValue != 0) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "validitysidechain-force-exit-marker-value");
                    }

                    ValiditySidechainForceExitData request;
                    if (!DecodeValiditySidechainForceExitData(info.primary_metadata, request)) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "validitysidechain-force-exit-data-bad");
                    }
                    if (ComputeValiditySidechainForceExitHash(info.sidechain_id, request) != info.payload) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "validitysidechain-force-exit-hash-mismatch");
                    }

                    std::string error;
                    if (!AddForceExitRequest(info.sidechain_id, height, request, &error)) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "validitysidechain-force-exit-invalid", error);
                    }
                    break;
                }

                case ValiditySidechainScriptInfo::Kind::COMMIT_VALIDITY_BATCH: {
                    if (txout.nValue != 0) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "validitysidechain-batch-marker-value");
                    }

                    ValiditySidechainBatchPublicInputs public_inputs;
                    std::vector<unsigned char> proof_bytes;
                    std::vector<std::vector<unsigned char>> data_chunks;
                    if (!DecodeValiditySidechainCommitMetadata(info, public_inputs, proof_bytes, data_chunks)) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "validitysidechain-batch-metadata-bad");
                    }
                    if (ComputeValiditySidechainBatchCommitmentHash(info.sidechain_id, public_inputs) != info.payload) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "validitysidechain-batch-hash-mismatch");
                    }

                    std::string error;
                    if (!AcceptBatch(info.sidechain_id, height, public_inputs, proof_bytes, data_chunks, &error)) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "validitysidechain-batch-invalid", error);
                    }
                    break;
                }

                case ValiditySidechainScriptInfo::Kind::EXECUTE_VERIFIED_WITHDRAWALS: {
                    if (txout.nValue != 0) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "validitysidechain-execute-marker-value");
                    }

                    std::vector<ValiditySidechainWithdrawalProof> withdrawal_proofs;
                    if (!DecodeValiditySidechainExecuteMetadata(info, withdrawal_proofs)) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "validitysidechain-execute-metadata-bad");
                    }
                    if (!MatchWithdrawalOutputs(*tx, static_cast<int>(out_i), withdrawal_proofs)) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "validitysidechain-execute-payout-mismatch");
                    }

                    std::string error;
                    if (!ExecuteWithdrawals(info.sidechain_id, info.payload, withdrawal_proofs, &error)) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "validitysidechain-execute-invalid", error);
                    }
                    break;
                }

                case ValiditySidechainScriptInfo::Kind::EXECUTE_ESCAPE_EXIT: {
                    if (txout.nValue != 0) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "validitysidechain-escape-exit-marker-value");
                    }

                    std::vector<ValiditySidechainEscapeExitProof> exit_proofs;
                    if (!DecodeValiditySidechainEscapeExitMetadata(info, exit_proofs)) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "validitysidechain-escape-exit-metadata-bad");
                    }
                    if (!MatchEscapeExitOutputs(*tx, static_cast<int>(out_i), exit_proofs)) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "validitysidechain-escape-exit-payout-mismatch");
                    }

                    std::string error;
                    if (!ExecuteEscapeExits(info.sidechain_id, height, info.payload, exit_proofs, &error)) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "validitysidechain-escape-exit-invalid", error);
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
