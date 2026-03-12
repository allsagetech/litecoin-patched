// Copyright (c) 2026 AllSageTech, LLC
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VALIDITYSIDECHAIN_STATE_H
#define BITCOIN_VALIDITYSIDECHAIN_STATE_H

#include <amount.h>
#include <serialize.h>
#include <uint256.h>

#include <map>
#include <stdint.h>

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

struct ValiditySidechainAcceptedBatch
{
    uint32_t batch_number{0};
    uint256 prior_state_root;
    uint256 new_state_root;
    uint256 withdrawal_root;
    uint256 data_root;
    int accepted_height{-1};

    SERIALIZE_METHODS(ValiditySidechainAcceptedBatch, obj)
    {
        READWRITE(obj.batch_number,
                  obj.prior_state_root,
                  obj.new_state_root,
                  obj.withdrawal_root,
                  obj.data_root,
                  obj.accepted_height);
    }
};

struct ValiditySidechainQueueState
{
    uint256 root;
    uint64_t head_index{0};
    uint64_t pending_message_count{0};
    uint64_t pending_deposit_count{0};
    uint64_t pending_force_exit_count{0};
    uint64_t reclaimable_deposit_count{0};

    SERIALIZE_METHODS(ValiditySidechainQueueState, obj)
    {
        READWRITE(obj.root,
                  obj.head_index,
                  obj.pending_message_count,
                  obj.pending_deposit_count,
                  obj.pending_force_exit_count,
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
    ValiditySidechain& GetOrCreateSidechain(uint8_t id, int registration_height);
    void Reset();
};

#endif // BITCOIN_VALIDITYSIDECHAIN_STATE_H
