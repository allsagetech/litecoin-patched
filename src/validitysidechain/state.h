// Copyright (c) 2026 AllSageTech, LLC
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VALIDITYSIDECHAIN_STATE_H
#define BITCOIN_VALIDITYSIDECHAIN_STATE_H

#include <amount.h>
#include <serialize.h>
#include <uint256.h>

#include <map>
#include <set>
#include <stdint.h>
#include <string>
#include <vector>

class CBlock;
class CBlockIndex;
class BlockValidationState;

struct ValiditySidechainConfig
{
    uint8_t version{1};
    uint8_t proof_system_id{0};
    uint8_t circuit_family_id{0};
    uint8_t verifier_id{0};
    uint8_t public_input_version{0};
    uint8_t state_root_format{0};
    uint8_t deposit_message_format{0};
    uint8_t withdrawal_leaf_format{0};
    uint8_t balance_leaf_format{0};
    uint8_t data_availability_mode{0};
    uint32_t max_batch_data_bytes{0};
    uint32_t max_proof_bytes{0};
    uint32_t force_inclusion_delay{0};
    uint32_t deposit_reclaim_delay{0};
    uint32_t escape_hatch_delay{0};
    uint256 initial_state_root;
    uint256 initial_withdrawal_root;

    SERIALIZE_METHODS(ValiditySidechainConfig, obj)
    {
        READWRITE(obj.version,
                  obj.proof_system_id,
                  obj.circuit_family_id,
                  obj.verifier_id,
                  obj.public_input_version,
                  obj.state_root_format,
                  obj.deposit_message_format,
                  obj.withdrawal_leaf_format,
                  obj.balance_leaf_format,
                  obj.data_availability_mode,
                  obj.max_batch_data_bytes,
                  obj.max_proof_bytes,
                  obj.force_inclusion_delay,
                  obj.deposit_reclaim_delay,
                  obj.escape_hatch_delay,
                  obj.initial_state_root,
                  obj.initial_withdrawal_root);
    }
};

struct ValiditySidechainDepositData
{
    uint256 deposit_id;
    CAmount amount{0};
    uint256 destination_commitment;
    uint256 refund_script_commitment;
    uint64_t nonce{0};

    SERIALIZE_METHODS(ValiditySidechainDepositData, obj)
    {
        READWRITE(obj.deposit_id,
                  obj.amount,
                  obj.destination_commitment,
                  obj.refund_script_commitment,
                  obj.nonce);
    }
};

struct ValiditySidechainBatchPublicInputs
{
    uint32_t batch_number{0};
    uint256 prior_state_root;
    uint256 new_state_root;
    uint256 l1_message_root_before;
    uint256 l1_message_root_after;
    uint32_t consumed_queue_messages{0};
    uint256 withdrawal_root;
    uint256 data_root;
    uint32_t data_size{0};

    SERIALIZE_METHODS(ValiditySidechainBatchPublicInputs, obj)
    {
        READWRITE(obj.batch_number,
                  obj.prior_state_root,
                  obj.new_state_root,
                  obj.l1_message_root_before,
                  obj.l1_message_root_after,
                  obj.consumed_queue_messages,
                  obj.withdrawal_root,
                  obj.data_root,
                  obj.data_size);
    }
};

struct ValiditySidechainForceExitData
{
    uint256 account_id;
    uint256 exit_asset_id;
    CAmount max_exit_amount{0};
    uint256 destination_commitment;
    uint64_t nonce{0};

    SERIALIZE_METHODS(ValiditySidechainForceExitData, obj)
    {
        READWRITE(obj.account_id,
                  obj.exit_asset_id,
                  obj.max_exit_amount,
                  obj.destination_commitment,
                  obj.nonce);
    }
};

struct ValiditySidechainWithdrawalLeaf
{
    uint256 withdrawal_id;
    CAmount amount{0};
    uint256 destination_commitment;

    SERIALIZE_METHODS(ValiditySidechainWithdrawalLeaf, obj)
    {
        READWRITE(obj.withdrawal_id,
                  obj.amount,
                  obj.destination_commitment);
    }
};

struct ValiditySidechainAcceptedBatch
{
    uint32_t batch_number{0};
    uint256 prior_state_root;
    uint256 new_state_root;
    uint256 l1_message_root_before;
    uint256 l1_message_root_after;
    uint32_t consumed_queue_messages{0};
    uint256 withdrawal_root;
    uint256 data_root;
    int accepted_height{-1};

    SERIALIZE_METHODS(ValiditySidechainAcceptedBatch, obj)
    {
        READWRITE(obj.batch_number,
                  obj.prior_state_root,
                  obj.new_state_root,
                  obj.l1_message_root_before,
                  obj.l1_message_root_after,
                  obj.consumed_queue_messages,
                  obj.withdrawal_root,
                  obj.data_root,
                  obj.accepted_height);
    }
};

struct ValiditySidechainQueueEntry
{
    enum MessageKind : uint8_t {
        MESSAGE_DEPOSIT = 1,
        MESSAGE_FORCE_EXIT = 2,
    };

    enum Status : uint8_t {
        STATUS_PENDING = 0,
        STATUS_CONSUMED = 1,
        STATUS_TOMBSTONED = 2,
    };

    uint64_t queue_index{0};
    uint8_t message_kind{0};
    uint8_t status{STATUS_PENDING};
    uint256 message_id;
    uint256 message_hash;
    int created_height{-1};

    SERIALIZE_METHODS(ValiditySidechainQueueEntry, obj)
    {
        READWRITE(obj.queue_index,
                  obj.message_kind,
                  obj.status,
                  obj.message_id,
                  obj.message_hash,
                  obj.created_height);
    }
};

struct ValiditySidechainPendingDeposit
{
    ValiditySidechainDepositData deposit;
    int deposit_height{-1};
    uint64_t queue_index{0};
    uint256 message_hash;

    SERIALIZE_METHODS(ValiditySidechainPendingDeposit, obj)
    {
        READWRITE(obj.deposit,
                  obj.deposit_height,
                  obj.queue_index,
                  obj.message_hash);
    }
};

struct ValiditySidechainPendingForceExit
{
    ValiditySidechainForceExitData request;
    int request_height{-1};
    uint64_t queue_index{0};
    uint256 request_hash;

    SERIALIZE_METHODS(ValiditySidechainPendingForceExit, obj)
    {
        READWRITE(obj.request,
                  obj.request_height,
                  obj.queue_index,
                  obj.request_hash);
    }
};

struct ValiditySidechainQueueState
{
    uint256 root;
    uint64_t head_index{0};
    uint64_t pending_message_count{0};
    uint64_t pending_deposit_count{0};
    uint64_t pending_force_exit_count{0};
    uint64_t matured_force_exit_count{0};
    uint64_t reclaimable_deposit_count{0};

    SERIALIZE_METHODS(ValiditySidechainQueueState, obj)
    {
        READWRITE(obj.root,
                  obj.head_index,
                  obj.pending_message_count,
                  obj.pending_deposit_count,
                  obj.pending_force_exit_count,
                  obj.matured_force_exit_count,
                  obj.reclaimable_deposit_count);
    }
};

struct ValiditySidechain
{
    uint8_t id{0};
    int registration_height{-1};
    bool is_active{false};
    CAmount escrow_balance{0};
    ValiditySidechainConfig config;
    uint256 current_state_root;
    uint256 current_withdrawal_root;
    uint256 current_data_root;
    uint32_t latest_batch_number{0};
    ValiditySidechainQueueState queue_state;
    std::map<uint64_t, ValiditySidechainQueueEntry> queue_entries;
    std::map<uint256, ValiditySidechainPendingDeposit> pending_deposits;
    std::map<uint256, ValiditySidechainPendingForceExit> pending_force_exits;
    std::set<uint256> executed_withdrawal_ids;
    uint64_t executed_withdrawal_count{0};
    uint64_t executed_escape_exit_count{0};
    std::map<uint32_t, ValiditySidechainAcceptedBatch> accepted_batches;

    SERIALIZE_METHODS(ValiditySidechain, obj)
    {
        READWRITE(obj.id,
                  obj.registration_height,
                  obj.is_active,
                  obj.escrow_balance,
                  obj.config,
                  obj.current_state_root,
                  obj.current_withdrawal_root,
                  obj.current_data_root,
                  obj.latest_batch_number,
                  obj.queue_state,
                  obj.queue_entries,
                  obj.pending_deposits,
                  obj.pending_force_exits,
                  obj.executed_withdrawal_ids,
                  obj.executed_withdrawal_count,
                  obj.executed_escape_exit_count,
                  obj.accepted_batches);
    }
};

class ValiditySidechainState
{
public:
    std::map<uint8_t, ValiditySidechain> sidechains;

    SERIALIZE_METHODS(ValiditySidechainState, obj)
    {
        READWRITE(obj.sidechains);
    }

    const ValiditySidechain* GetSidechain(uint8_t id) const;
    ValiditySidechain* GetSidechain(uint8_t id);
    const ValiditySidechainAcceptedBatch* GetAcceptedBatch(uint8_t sidechain_id, uint32_t batch_number) const;
    const ValiditySidechainAcceptedBatch* GetAcceptedBatchById(uint8_t sidechain_id, const uint256& accepted_batch_id) const;
    const ValiditySidechainPendingDeposit* GetPendingDeposit(uint8_t sidechain_id, const uint256& deposit_id) const;
    const ValiditySidechainPendingForceExit* GetPendingForceExit(uint8_t sidechain_id, const uint256& request_hash) const;
    bool HasExecutedWithdrawal(uint8_t sidechain_id, const uint256& withdrawal_id) const;
    ValiditySidechain& GetOrCreateSidechain(uint8_t id, int registration_height);
    bool ConnectBlock(const CBlock& block, const CBlockIndex* pindex, BlockValidationState& state);
    bool RegisterSidechain(uint8_t id, int registration_height, const ValiditySidechainConfig& config, std::string* error = nullptr);
    bool AddDeposit(uint8_t sidechain_id, int deposit_height, const ValiditySidechainDepositData& deposit, std::string* error = nullptr);
    bool AddForceExitRequest(uint8_t sidechain_id, int request_height, const ValiditySidechainForceExitData& request, std::string* error = nullptr);
    bool ReclaimDeposit(uint8_t sidechain_id, int reclaim_height, const ValiditySidechainDepositData& deposit, std::string* error = nullptr);
    bool AcceptBatch(
        uint8_t sidechain_id,
        int accepted_height,
        const ValiditySidechainBatchPublicInputs& public_inputs,
        const std::vector<unsigned char>& proof_bytes,
        const std::vector<std::vector<unsigned char>>& data_chunks,
        std::string* error = nullptr);
    bool ExecuteWithdrawals(
        uint8_t sidechain_id,
        const uint256& accepted_batch_id,
        const std::vector<ValiditySidechainWithdrawalLeaf>& withdrawals,
        std::string* error = nullptr);
    void Reset();
};

#endif // BITCOIN_VALIDITYSIDECHAIN_STATE_H
