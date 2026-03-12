// Copyright (c) 2026 AllSageTech, LLC
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <consensus/validation.h>
#include <hash.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <validitysidechain/registry.h>
#include <validitysidechain/script.h>
#include <validitysidechain/state.h>

#include <boost/test/unit_test.hpp>

#include <string>

namespace {

ValiditySidechainConfig MakeSupportedConfig()
{
    const SupportedValiditySidechainConfig& supported = GetSupportedValiditySidechainConfigs().front();

    ValiditySidechainConfig config;
    config.version = supported.version;
    config.proof_system_id = supported.proof_system_id;
    config.circuit_family_id = supported.circuit_family_id;
    config.verifier_id = supported.verifier_id;
    config.public_input_version = supported.public_input_version;
    config.state_root_format = supported.state_root_format;
    config.deposit_message_format = supported.deposit_message_format;
    config.withdrawal_leaf_format = supported.withdrawal_leaf_format;
    config.balance_leaf_format = supported.balance_leaf_format;
    config.data_availability_mode = supported.data_availability_mode;
    config.max_batch_data_bytes = supported.max_batch_data_bytes_limit;
    config.max_proof_bytes = supported.max_proof_bytes_limit;
    config.force_inclusion_delay = supported.min_force_inclusion_delay;
    config.deposit_reclaim_delay = supported.min_deposit_reclaim_delay;
    config.escape_hatch_delay = supported.min_escape_hatch_delay;
    config.initial_state_root = uint256S("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    config.initial_withdrawal_root = uint256S("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    return config;
}

ValiditySidechainDepositData MakeDeposit(const uint256& deposit_id, const CScript& refund_script, CAmount amount = 5 * COIN)
{
    ValiditySidechainDepositData deposit;
    deposit.deposit_id = deposit_id;
    deposit.amount = amount;
    deposit.destination_commitment = uint256S("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    deposit.refund_script_commitment = Hash(refund_script.begin(), refund_script.end());
    deposit.nonce = 12;
    return deposit;
}

ValiditySidechainBatchPublicInputs MakeNoopBatchPublicInputs(const ValiditySidechain& sidechain, uint32_t batch_number)
{
    ValiditySidechainBatchPublicInputs public_inputs;
    public_inputs.batch_number = batch_number;
    public_inputs.prior_state_root = sidechain.current_state_root;
    public_inputs.new_state_root = sidechain.current_state_root;
    public_inputs.l1_message_root_before = sidechain.queue_state.root;
    public_inputs.l1_message_root_after = sidechain.queue_state.root;
    public_inputs.consumed_queue_messages = 0;
    public_inputs.withdrawal_root = sidechain.current_withdrawal_root;
    public_inputs.data_root = sidechain.current_data_root;
    public_inputs.data_size = 0;
    return public_inputs;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(validitysidechain_state_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(supported_registry_accepts_scaffold_profile)
{
    const auto& supported_configs = GetSupportedValiditySidechainConfigs();
    BOOST_REQUIRE_EQUAL(supported_configs.size(), 1U);
    BOOST_CHECK_EQUAL(std::string(supported_configs.front().profile_name), "scaffold_onchain_da_v1");
    BOOST_CHECK(supported_configs.front().scaffolding_only);

    const ValiditySidechainConfig config = MakeSupportedConfig();
    std::string error;
    BOOST_CHECK(ValidateValiditySidechainConfig(config, &error));
    BOOST_CHECK(error.empty());
    BOOST_REQUIRE(FindSupportedValiditySidechainConfig(config) != nullptr);
}

BOOST_AUTO_TEST_CASE(validation_rejects_invalid_profiles_and_limits)
{
    const SupportedValiditySidechainConfig& supported = GetSupportedValiditySidechainConfigs().front();

    {
        ValiditySidechainConfig config = MakeSupportedConfig();
        config.verifier_id = supported.verifier_id + 1;

        std::string error;
        BOOST_CHECK(!ValidateValiditySidechainConfig(config, &error));
        BOOST_CHECK_EQUAL(error, "unsupported proof configuration tuple");
    }

    {
        ValiditySidechainConfig config = MakeSupportedConfig();
        config.max_proof_bytes = supported.max_proof_bytes_limit + 1;

        std::string error;
        BOOST_CHECK(!ValidateValiditySidechainConfig(config, &error));
        BOOST_CHECK_EQUAL(error, "max_proof_bytes exceeds supported limit");
    }

    {
        ValiditySidechainConfig config = MakeSupportedConfig();
        config.force_inclusion_delay = supported.min_force_inclusion_delay - 1;

        std::string error;
        BOOST_CHECK(!ValidateValiditySidechainConfig(config, &error));
        BOOST_CHECK_EQUAL(error, "force_inclusion_delay outside supported range");
    }
}

BOOST_AUTO_TEST_CASE(register_sidechain_initializes_state_and_rejects_duplicates)
{
    ValiditySidechainState state;
    const ValiditySidechainConfig config = MakeSupportedConfig();

    std::string error;
    BOOST_CHECK(state.RegisterSidechain(/* id= */ 4, /* registration_height= */ 125, config, &error));
    BOOST_CHECK(error.empty());

    const ValiditySidechain* sidechain = state.GetSidechain(4);
    BOOST_REQUIRE(sidechain != nullptr);
    BOOST_CHECK(sidechain->is_active);
    BOOST_CHECK_EQUAL(sidechain->registration_height, 125);
    BOOST_CHECK(sidechain->config.initial_state_root == config.initial_state_root);
    BOOST_CHECK(sidechain->current_state_root == config.initial_state_root);
    BOOST_CHECK(sidechain->current_withdrawal_root == config.initial_withdrawal_root);
    BOOST_CHECK_EQUAL(sidechain->latest_batch_number, 0U);
    BOOST_CHECK_EQUAL(sidechain->escrow_balance, 0);

    BOOST_CHECK(!state.RegisterSidechain(/* id= */ 4, /* registration_height= */ 126, config, &error));
    BOOST_CHECK_EQUAL(error, "sidechain id already registered");
}

BOOST_AUTO_TEST_CASE(register_sidechain_rejects_invalid_height)
{
    ValiditySidechainState state;
    const ValiditySidechainConfig config = MakeSupportedConfig();

    std::string error;
    BOOST_CHECK(!state.RegisterSidechain(/* id= */ 2, /* registration_height= */ -1, config, &error));
    BOOST_CHECK_EQUAL(error, "registration height must be non-negative");
}

BOOST_AUTO_TEST_CASE(connect_block_registers_validity_sidechain)
{
    ValiditySidechainState state;
    const ValiditySidechainConfig config = MakeSupportedConfig();

    CMutableTransaction tx;
    tx.vout.emplace_back(/* nValueIn= */ 1, BuildValiditySidechainRegisterScript(/* scid= */ 6, config));

    CBlock block;
    block.vtx.push_back(MakeTransactionRef(tx));

    CBlockIndex index;
    index.nHeight = 220;

    BlockValidationState validation_state;
    BOOST_REQUIRE(state.ConnectBlock(block, &index, validation_state));

    const ValiditySidechain* sidechain = state.GetSidechain(6);
    BOOST_REQUIRE(sidechain != nullptr);
    BOOST_CHECK_EQUAL(sidechain->registration_height, 220);
    BOOST_CHECK(sidechain->current_state_root == config.initial_state_root);
    BOOST_CHECK(sidechain->current_withdrawal_root == config.initial_withdrawal_root);
}

BOOST_AUTO_TEST_CASE(connect_block_rejects_multiple_validity_registers_in_one_tx)
{
    ValiditySidechainState state;
    const ValiditySidechainConfig config = MakeSupportedConfig();

    CMutableTransaction tx;
    tx.vout.emplace_back(/* nValueIn= */ 1, BuildValiditySidechainRegisterScript(/* scid= */ 9, config));
    tx.vout.emplace_back(/* nValueIn= */ 1, BuildValiditySidechainRegisterScript(/* scid= */ 10, config));

    CBlock block;
    block.vtx.push_back(MakeTransactionRef(tx));

    CBlockIndex index;
    index.nHeight = 221;

    BlockValidationState validation_state;
    BOOST_CHECK(!state.ConnectBlock(block, &index, validation_state));
    BOOST_CHECK_EQUAL(validation_state.GetRejectReason(), "validitysidechain-multi-marker");
    BOOST_CHECK(state.sidechains.empty());
}

BOOST_AUTO_TEST_CASE(add_deposit_and_reclaim_updates_queue_state)
{
    ValiditySidechainState state;
    const ValiditySidechainConfig config = MakeSupportedConfig();
    BOOST_REQUIRE(state.RegisterSidechain(/* id= */ 3, /* registration_height= */ 100, config));

    const CScript refund_script = CScript() << OP_TRUE;
    const ValiditySidechainDepositData deposit = MakeDeposit(
        uint256S("0101010101010101010101010101010101010101010101010101010101010101"),
        refund_script);

    std::string error;
    BOOST_REQUIRE(state.AddDeposit(/* sidechain_id= */ 3, /* deposit_height= */ 125, deposit, &error));
    BOOST_CHECK(error.empty());

    const ValiditySidechain* sidechain = state.GetSidechain(3);
    BOOST_REQUIRE(sidechain != nullptr);
    BOOST_CHECK_EQUAL(sidechain->escrow_balance, deposit.amount);
    BOOST_CHECK_EQUAL(sidechain->queue_state.pending_message_count, 1U);
    BOOST_CHECK_EQUAL(sidechain->queue_state.pending_deposit_count, 1U);
    BOOST_CHECK_EQUAL(sidechain->queue_state.reclaimable_deposit_count, 0U);
    BOOST_REQUIRE(state.GetPendingDeposit(3, deposit.deposit_id) != nullptr);
    BOOST_REQUIRE_EQUAL(sidechain->queue_entries.size(), 1U);
    BOOST_REQUIRE_EQUAL(sidechain->pending_deposits.size(), 1U);
    BOOST_CHECK(sidechain->queue_state.root != uint256());

    CBlock idle_block;
    CBlockIndex idle_index;
    idle_index.nHeight = 125 + config.deposit_reclaim_delay;
    BlockValidationState validation_state;
    BOOST_REQUIRE(state.ConnectBlock(idle_block, &idle_index, validation_state));
    sidechain = state.GetSidechain(3);
    BOOST_REQUIRE(sidechain != nullptr);
    BOOST_CHECK_EQUAL(sidechain->queue_state.reclaimable_deposit_count, 1U);

    BOOST_CHECK(!state.ReclaimDeposit(/* sidechain_id= */ 3, /* reclaim_height= */ 125 + config.deposit_reclaim_delay - 1, deposit, &error));
    BOOST_CHECK_EQUAL(error, "deposit reclaim delay not reached");

    BOOST_REQUIRE(state.ReclaimDeposit(/* sidechain_id= */ 3, /* reclaim_height= */ 125 + config.deposit_reclaim_delay, deposit, &error));
    BOOST_CHECK(error.empty());

    sidechain = state.GetSidechain(3);
    BOOST_REQUIRE(sidechain != nullptr);
    BOOST_CHECK_EQUAL(sidechain->escrow_balance, 0);
    BOOST_CHECK_EQUAL(sidechain->queue_state.pending_message_count, 0U);
    BOOST_CHECK_EQUAL(sidechain->queue_state.pending_deposit_count, 0U);
    BOOST_CHECK_EQUAL(sidechain->queue_state.head_index, 1U);
    BOOST_REQUIRE(state.GetPendingDeposit(3, deposit.deposit_id) == nullptr);
    BOOST_REQUIRE_EQUAL(sidechain->pending_deposits.size(), 0U);
    BOOST_REQUIRE(sidechain->queue_entries.at(0).status == ValiditySidechainQueueEntry::STATUS_TOMBSTONED);
}

BOOST_AUTO_TEST_CASE(connect_block_handles_deposit_and_reclaim)
{
    ValiditySidechainState state;
    const ValiditySidechainConfig config = MakeSupportedConfig();
    BOOST_REQUIRE(state.RegisterSidechain(/* id= */ 4, /* registration_height= */ 200, config));

    const CScript refund_script = CScript() << OP_1 << OP_DROP;
    const ValiditySidechainDepositData deposit = MakeDeposit(
        uint256S("0202020202020202020202020202020202020202020202020202020202020202"),
        refund_script,
        7 * COIN);

    CMutableTransaction deposit_tx;
    deposit_tx.vout.emplace_back(deposit.amount, BuildValiditySidechainDepositScript(/* scid= */ 4, deposit));

    CBlock deposit_block;
    deposit_block.vtx.push_back(MakeTransactionRef(deposit_tx));

    CBlockIndex deposit_index;
    deposit_index.nHeight = 205;

    BlockValidationState validation_state;
    BOOST_REQUIRE(state.ConnectBlock(deposit_block, &deposit_index, validation_state));
    BOOST_REQUIRE(state.GetPendingDeposit(4, deposit.deposit_id) != nullptr);

    CMutableTransaction reclaim_tx;
    reclaim_tx.vout.emplace_back(/* nValueIn= */ 0, BuildValiditySidechainReclaimDepositScript(/* scid= */ 4, deposit));
    reclaim_tx.vout.emplace_back(deposit.amount, refund_script);

    CBlock reclaim_block;
    reclaim_block.vtx.push_back(MakeTransactionRef(reclaim_tx));

    CBlockIndex reclaim_index;
    reclaim_index.nHeight = 205 + config.deposit_reclaim_delay;

    validation_state = BlockValidationState();
    BOOST_REQUIRE(state.ConnectBlock(reclaim_block, &reclaim_index, validation_state));
    BOOST_REQUIRE(state.GetPendingDeposit(4, deposit.deposit_id) == nullptr);
}

BOOST_AUTO_TEST_CASE(accept_batch_records_noop_scaffold_batch)
{
    ValiditySidechainState state;
    const ValiditySidechainConfig config = MakeSupportedConfig();
    BOOST_REQUIRE(state.RegisterSidechain(/* id= */ 5, /* registration_height= */ 300, config));

    const ValiditySidechain* sidechain = state.GetSidechain(5);
    BOOST_REQUIRE(sidechain != nullptr);

    const ValiditySidechainBatchPublicInputs public_inputs = MakeNoopBatchPublicInputs(*sidechain, /* batch_number= */ 1);
    std::string error;
    BOOST_REQUIRE(state.AcceptBatch(/* sidechain_id= */ 5, /* accepted_height= */ 320, public_inputs, {}, {}, &error));
    BOOST_CHECK(error.empty());

    sidechain = state.GetSidechain(5);
    BOOST_REQUIRE(sidechain != nullptr);
    BOOST_CHECK_EQUAL(sidechain->latest_batch_number, 1U);
    BOOST_REQUIRE_EQUAL(sidechain->accepted_batches.size(), 1U);
    const ValiditySidechainAcceptedBatch* batch = state.GetAcceptedBatch(5, 1);
    BOOST_REQUIRE(batch != nullptr);
    BOOST_CHECK_EQUAL(batch->consumed_queue_messages, 0U);
    BOOST_CHECK(batch->l1_message_root_before == public_inputs.l1_message_root_before);
    BOOST_CHECK(batch->l1_message_root_after == public_inputs.l1_message_root_after);
}

BOOST_AUTO_TEST_CASE(connect_block_handles_noop_batch_commit)
{
    ValiditySidechainState state;
    const ValiditySidechainConfig config = MakeSupportedConfig();
    BOOST_REQUIRE(state.RegisterSidechain(/* id= */ 7, /* registration_height= */ 330, config));

    const ValiditySidechain* sidechain = state.GetSidechain(7);
    BOOST_REQUIRE(sidechain != nullptr);
    const ValiditySidechainBatchPublicInputs public_inputs = MakeNoopBatchPublicInputs(*sidechain, /* batch_number= */ 1);

    CMutableTransaction batch_tx;
    batch_tx.vout.emplace_back(
        /* nValueIn= */ 0,
        BuildValiditySidechainCommitScript(
            /* scid= */ 7,
            public_inputs,
            std::vector<unsigned char>{},
            std::vector<std::vector<unsigned char>>{}));

    CBlock block;
    block.vtx.push_back(MakeTransactionRef(batch_tx));

    CBlockIndex index;
    index.nHeight = 331;

    BlockValidationState validation_state;
    BOOST_REQUIRE(state.ConnectBlock(block, &index, validation_state));

    const ValiditySidechainAcceptedBatch* batch = state.GetAcceptedBatch(7, 1);
    BOOST_REQUIRE(batch != nullptr);
    BOOST_CHECK_EQUAL(batch->accepted_height, 331);
}

BOOST_AUTO_TEST_CASE(accept_batch_rejects_scaffold_state_or_queue_changes)
{
    ValiditySidechainState state;
    const ValiditySidechainConfig config = MakeSupportedConfig();
    BOOST_REQUIRE(state.RegisterSidechain(/* id= */ 6, /* registration_height= */ 310, config));

    const CScript refund_script = CScript() << OP_TRUE;
    const ValiditySidechainDepositData deposit = MakeDeposit(
        uint256S("0303030303030303030303030303030303030303030303030303030303030303"),
        refund_script);
    BOOST_REQUIRE(state.AddDeposit(/* sidechain_id= */ 6, /* deposit_height= */ 311, deposit));

    const ValiditySidechain* sidechain = state.GetSidechain(6);
    BOOST_REQUIRE(sidechain != nullptr);

    {
        ValiditySidechainBatchPublicInputs public_inputs = MakeNoopBatchPublicInputs(*sidechain, /* batch_number= */ 1);
        public_inputs.new_state_root = uint256S("0404040404040404040404040404040404040404040404040404040404040404");

        std::string error;
        BOOST_CHECK(!state.AcceptBatch(/* sidechain_id= */ 6, /* accepted_height= */ 312, public_inputs, {}, {}, &error));
        BOOST_CHECK_EQUAL(error, "scaffold verifier only allows no-op state root updates");
    }

    {
        sidechain = state.GetSidechain(6);
        BOOST_REQUIRE(sidechain != nullptr);
        ValiditySidechainBatchPublicInputs public_inputs = MakeNoopBatchPublicInputs(*sidechain, /* batch_number= */ 1);
        public_inputs.consumed_queue_messages = 1;
        public_inputs.l1_message_root_after = uint256S("0505050505050505050505050505050505050505050505050505050505050505");

        std::string error;
        BOOST_CHECK(!state.AcceptBatch(/* sidechain_id= */ 6, /* accepted_height= */ 312, public_inputs, {}, {}, &error));
        BOOST_CHECK_EQUAL(error, "scaffold verifier does not allow queue consumption yet");
    }
}

BOOST_AUTO_TEST_SUITE_END()
