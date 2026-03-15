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
#include <validitysidechain/blst_backend.h>
#include <validitysidechain/registry.h>
#include <validitysidechain/script.h>
#include <validitysidechain/state.h>
#include <validitysidechain/verifier.h>

#include <boost/test/unit_test.hpp>

#include <string>

namespace {

static constexpr unsigned char TEST_QUEUE_CONSUME_MAGIC[] = {'V', 'S', 'C', 'Q', 'C', 0x01};

ValiditySidechainConfig MakeSupportedConfig(size_t supported_index = 0)
{
    const auto& supported_configs = GetSupportedValiditySidechainConfigs();
    if (supported_index >= supported_configs.size()) {
        BOOST_FAIL("requested unsupported config index");
        return ValiditySidechainConfig{};
    }
    const SupportedValiditySidechainConfig& supported = supported_configs.at(supported_index);

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
    deposit.refund_script_commitment = Hash(refund_script);
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
    public_inputs.queue_prefix_commitment.SetNull();
    public_inputs.withdrawal_root = sidechain.current_withdrawal_root;
    public_inputs.data_root = sidechain.current_data_root;
    public_inputs.data_size = 0;
    return public_inputs;
}

ValiditySidechainWithdrawalLeaf MakeWithdrawalLeaf(const uint256& withdrawal_id, const CScript& destination_script, CAmount amount)
{
    ValiditySidechainWithdrawalLeaf withdrawal;
    withdrawal.withdrawal_id = withdrawal_id;
    withdrawal.amount = amount;
    withdrawal.destination_commitment = Hash(destination_script);
    return withdrawal;
}

std::vector<ValiditySidechainWithdrawalProof> BuildWithdrawalProofsForTest(
    const std::vector<ValiditySidechainWithdrawalLeaf>& withdrawals)
{
    std::vector<ValiditySidechainWithdrawalProof> proofs;
    proofs.reserve(withdrawals.size());
    for (uint32_t i = 0; i < withdrawals.size(); ++i) {
        ValiditySidechainWithdrawalProof proof;
        if (!BuildValiditySidechainWithdrawalProof(withdrawals, i, proof)) {
            BOOST_FAIL("failed to build withdrawal proof for test");
            return {};
        }
        proofs.push_back(std::move(proof));
    }
    return proofs;
}

std::vector<ValiditySidechainEscapeExitProof> BuildEscapeExitProofsForTest(
    const std::vector<ValiditySidechainEscapeExitLeaf>& exits)
{
    std::vector<ValiditySidechainEscapeExitProof> proofs;
    proofs.reserve(exits.size());
    for (uint32_t i = 0; i < exits.size(); ++i) {
        ValiditySidechainEscapeExitProof proof;
        if (!BuildValiditySidechainEscapeExitProof(exits, i, proof)) {
            BOOST_FAIL("failed to build escape-exit proof for test");
            return {};
        }
        proofs.push_back(std::move(proof));
    }
    return proofs;
}

std::vector<unsigned char> BuildScaffoldBatchProofForTest(
    uint8_t sidechain_id,
    const ValiditySidechain& sidechain,
    const ValiditySidechainBatchPublicInputs& public_inputs)
{
    return BuildValiditySidechainScaffoldBatchProof(
        sidechain_id,
        public_inputs,
        sidechain.current_state_root,
        sidechain.current_withdrawal_root,
        sidechain.current_data_root,
        sidechain.queue_state.root);
}

ValiditySidechainForceExitData MakeForceExitRequest(const uint256& account_id, const CScript& destination_script, CAmount amount = 2 * COIN)
{
    ValiditySidechainForceExitData request;
    request.account_id = account_id;
    request.exit_asset_id = uint256S("2424242424242424242424242424242424242424242424242424242424242424");
    request.max_exit_amount = amount;
    request.destination_commitment = Hash(destination_script);
    request.nonce = 77;
    return request;
}

ValiditySidechainEscapeExitLeaf MakeEscapeExitLeaf(const uint256& exit_id, const CScript& destination_script, CAmount amount)
{
    ValiditySidechainEscapeExitLeaf exit;
    exit.exit_id = exit_id;
    exit.amount = amount;
    exit.destination_commitment = Hash(destination_script);
    return exit;
}

uint256 ComputeQueueConsumeRootForTest(
    uint8_t sidechain_id,
    const uint256& prior_root,
    const ValiditySidechainQueueEntry& entry)
{
    CHashWriter hw(SER_GETHASH, 0);
    hw.write((const char*)TEST_QUEUE_CONSUME_MAGIC, sizeof(TEST_QUEUE_CONSUME_MAGIC));
    hw << sidechain_id;
    hw << prior_root;
    hw << entry.queue_index;
    hw << entry.message_kind;
    hw << entry.message_id;
    hw << entry.message_hash;
    return hw.GetHash();
}

uint256 ComputeConsumedQueueRootForTest(
    const ValiditySidechain& sidechain,
    uint8_t sidechain_id,
    uint32_t consumed_queue_messages)
{
    uint256 root = sidechain.queue_state.root;
    uint64_t next_queue_index = sidechain.queue_state.head_index;

    for (uint32_t i = 0; i < consumed_queue_messages; ++i) {
        const auto queue_it = sidechain.queue_entries.find(next_queue_index);
        if (queue_it == sidechain.queue_entries.end()) {
            BOOST_FAIL("missing queue entry while computing test queue root");
            return uint256();
        }
        if (queue_it->second.status != ValiditySidechainQueueEntry::QUEUE_STATUS_PENDING) {
            BOOST_FAIL("non-pending queue entry while computing test queue root");
            return uint256();
        }
        root = ComputeQueueConsumeRootForTest(sidechain_id, root, queue_it->second);
        ++next_queue_index;
    }

    return root;
}

uint256 ComputeQueuePrefixCommitmentForTest(
    const ValiditySidechain& sidechain,
    uint8_t sidechain_id,
    uint32_t consumed_queue_messages)
{
    uint256 commitment;
    std::string error;
    if (!ComputeValiditySidechainQueuePrefixCommitment(
            sidechain,
            sidechain_id,
            consumed_queue_messages,
            commitment,
            &error)) {
        BOOST_FAIL("failed to compute test queue prefix commitment: " + error);
        return uint256();
    }
    return commitment;
}

void InstallAcceptedWithdrawalBatch(
    ValiditySidechainState& state,
    uint8_t sidechain_id,
    uint32_t batch_number,
    const std::vector<ValiditySidechainWithdrawalLeaf>& withdrawals,
    int accepted_height)
{
    ValiditySidechain* sidechain = state.GetSidechain(sidechain_id);
    BOOST_REQUIRE(sidechain != nullptr);

    const uint256 withdrawal_root = ComputeValiditySidechainWithdrawalRoot(withdrawals);
    sidechain->current_withdrawal_root = withdrawal_root;
    sidechain->latest_batch_number = batch_number;
    ValiditySidechainAcceptedBatch batch;
    batch.batch_number = batch_number;
    batch.prior_state_root = sidechain->current_state_root;
    batch.new_state_root = sidechain->current_state_root;
    batch.l1_message_root_before = sidechain->queue_state.root;
    batch.l1_message_root_after = sidechain->queue_state.root;
    batch.consumed_queue_messages = 0;
    batch.queue_prefix_commitment.SetNull();
    batch.withdrawal_root = withdrawal_root;
    batch.data_root = sidechain->current_data_root;
    batch.accepted_height = accepted_height;
    sidechain->accepted_batches.emplace(batch_number, batch);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(validitysidechain_state_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(supported_registry_accepts_scaffold_profile)
{
    const auto& supported_configs = GetSupportedValiditySidechainConfigs();
    BOOST_REQUIRE_EQUAL(supported_configs.size(), 5U);
    BOOST_CHECK_EQUAL(std::string(supported_configs.front().profile_name), "scaffold_onchain_da_v1");
    BOOST_CHECK(supported_configs.front().scaffolding_only);
    BOOST_CHECK_EQUAL(
        GetValiditySidechainBatchVerifierMode(MakeSupportedConfig(/* supported_index= */ 0)),
        ValiditySidechainBatchVerifierMode::SCAFFOLD_QUEUE_PREFIX_ONLY);
    BOOST_CHECK_EQUAL(std::string(supported_configs.at(1).profile_name), "scaffold_transition_da_v1");
    BOOST_CHECK(supported_configs.at(1).scaffolding_only);
    BOOST_CHECK_EQUAL(
        GetValiditySidechainBatchVerifierMode(MakeSupportedConfig(/* supported_index= */ 1)),
        ValiditySidechainBatchVerifierMode::SCAFFOLD_TRANSITION_COMMITMENT);
    BOOST_CHECK_EQUAL(std::string(supported_configs.at(2).profile_name), "gnark_groth16_toy_batch_transition_v1");
    BOOST_CHECK(!supported_configs.at(2).scaffolding_only);
    BOOST_CHECK(supported_configs.at(2).requires_external_verifier_assets);
    BOOST_CHECK(supported_configs.at(2).supports_external_prover);
    BOOST_CHECK_EQUAL(
        GetValiditySidechainBatchVerifierMode(MakeSupportedConfig(/* supported_index= */ 2)),
        ValiditySidechainBatchVerifierMode::GNARK_GROTH16_TOY_BATCH_TRANSITION_V1);
    BOOST_CHECK_EQUAL(std::string(supported_configs.at(3).profile_name), "native_blst_groth16_toy_batch_transition_v1");
    BOOST_CHECK(!supported_configs.at(3).scaffolding_only);
    BOOST_CHECK(supported_configs.at(3).requires_external_verifier_assets);
    BOOST_CHECK(!supported_configs.at(3).supports_external_prover);
    BOOST_CHECK_EQUAL(
        GetValiditySidechainBatchVerifierMode(MakeSupportedConfig(/* supported_index= */ 3)),
        ValiditySidechainBatchVerifierMode::NATIVE_GROTH16_TOY_BATCH_TRANSITION_V1);
    BOOST_CHECK_EQUAL(std::string(supported_configs.back().profile_name), "groth16_bls12_381_poseidon_v1");
    BOOST_CHECK(!supported_configs.back().scaffolding_only);
    BOOST_CHECK(supported_configs.back().requires_external_verifier_assets);
    BOOST_CHECK(supported_configs.back().supports_external_prover);
    BOOST_CHECK_EQUAL(
        GetValiditySidechainBatchVerifierMode(MakeSupportedConfig(/* supported_index= */ 4)),
        ValiditySidechainBatchVerifierMode::GROTH16_BLS12_381_POSEIDON_V1);

    const ValiditySidechainConfig config = MakeSupportedConfig();
    std::string error;
    BOOST_CHECK(ValidateValiditySidechainConfig(config, &error));
    BOOST_CHECK(error.empty());
    BOOST_REQUIRE(FindSupportedValiditySidechainConfig(config) != nullptr);
}

BOOST_AUTO_TEST_CASE(real_profile_reports_native_backend_ready_when_assets_exist)
{
    const ValiditySidechainConfig config = MakeSupportedConfig(/* supported_index= */ 4);
    ValiditySidechainVerifierAssetsStatus status;
    BOOST_CHECK(GetValiditySidechainVerifierAssetsStatus(config, status));
    BOOST_CHECK(status.requires_external_assets);
    BOOST_CHECK(status.assets_present);
    BOOST_CHECK(status.prover_assets_present);
    BOOST_CHECK(status.backend_ready);
    BOOST_CHECK(status.native_backend_available);
    BOOST_CHECK(status.native_backend_self_test_passed);
    BOOST_CHECK_GT(status.native_backend_pairing_context_bytes, 0U);
    BOOST_CHECK_EQUAL(status.native_backend_status, "native blst backend available");
    BOOST_CHECK_EQUAL(status.artifact_name, "groth16_bls12_381_poseidon_v1");
    if (status.profile_manifest_parsed) {
        BOOST_CHECK(status.profile_manifest_name_matches);
        BOOST_CHECK(status.profile_manifest_backend_matches);
        BOOST_CHECK(status.profile_manifest_key_layout_matches);
        BOOST_CHECK(status.profile_manifest_tuple_matches);
        BOOST_CHECK(status.profile_manifest_public_inputs_match);
        BOOST_CHECK(status.valid_proof_vectors_present);
        BOOST_CHECK(status.invalid_proof_vectors_present);
        BOOST_CHECK_EQUAL(status.profile_manifest_name, "groth16_bls12_381_poseidon_v1");
        BOOST_CHECK_GE(status.valid_proof_vector_count, 1U);
        BOOST_CHECK_GE(status.invalid_proof_vector_count, 1U);
        BOOST_CHECK_EQUAL(status.profile_manifest_public_input_count, 11U);
    }
    BOOST_CHECK_EQUAL(status.status, "native blst Groth16 verifier ready");
}

BOOST_AUTO_TEST_CASE(native_toy_profile_reports_native_backend_ready_when_assets_exist)
{
    const ValiditySidechainConfig config = MakeSupportedConfig(/* supported_index= */ 3);
    ValiditySidechainVerifierAssetsStatus status;
    BOOST_CHECK(GetValiditySidechainVerifierAssetsStatus(config, status));
    BOOST_CHECK(status.requires_external_assets);
    BOOST_CHECK(status.assets_present);
    BOOST_CHECK(status.backend_ready);
    BOOST_CHECK(status.native_backend_available);
    BOOST_CHECK(status.native_backend_self_test_passed);
    BOOST_CHECK_EQUAL(status.artifact_name, "native_blst_groth16_toy_batch_transition_v1");
    if (status.profile_manifest_parsed) {
        BOOST_CHECK(status.profile_manifest_name_matches);
        BOOST_CHECK(status.profile_manifest_backend_matches);
        BOOST_CHECK(status.profile_manifest_key_layout_matches);
        BOOST_CHECK(status.profile_manifest_tuple_matches);
        BOOST_CHECK(status.profile_manifest_public_inputs_match);
        BOOST_CHECK(status.valid_proof_vectors_present);
        BOOST_CHECK(status.invalid_proof_vectors_present);
        BOOST_CHECK_EQUAL(status.profile_manifest_name, "native_blst_groth16_toy_batch_transition_v1");
        BOOST_CHECK_EQUAL(status.profile_manifest_public_input_count, 7U);
    }
    BOOST_CHECK_EQUAL(status.status, "native blst Groth16 verifier ready");
}

BOOST_AUTO_TEST_CASE(native_blst_backend_self_test_passes)
{
    ValiditySidechainNativeBlstBackendStatus status;
    BOOST_CHECK(GetValiditySidechainNativeBlstBackendStatus(status));
    BOOST_CHECK(status.available);
    BOOST_CHECK(status.self_test_passed);
    BOOST_CHECK_GT(status.pairing_context_bytes, 0U);
    BOOST_CHECK_EQUAL(status.status, "native blst backend available");
}

BOOST_AUTO_TEST_CASE(toy_profile_requires_external_command_or_assets)
{
    const ValiditySidechainConfig config = MakeSupportedConfig(/* supported_index= */ 2);
    ValiditySidechainVerifierAssetsStatus status;
    BOOST_CHECK(GetValiditySidechainVerifierAssetsStatus(config, status));
    BOOST_CHECK(status.requires_external_assets);
    BOOST_CHECK_EQUAL(status.artifact_name, "gnark_groth16_toy_batch_transition_v1");
    if (status.profile_manifest_parsed) {
        BOOST_CHECK(status.profile_manifest_name_matches);
        BOOST_CHECK(status.profile_manifest_backend_matches);
        BOOST_CHECK(status.profile_manifest_key_layout_matches);
        BOOST_CHECK(status.profile_manifest_tuple_matches);
        BOOST_CHECK(status.profile_manifest_public_inputs_match);
        BOOST_CHECK(status.valid_proof_vectors_present);
        BOOST_CHECK(status.invalid_proof_vectors_present);
        BOOST_CHECK_EQUAL(status.profile_manifest_name, "gnark_groth16_toy_batch_transition_v1");
        BOOST_CHECK_EQUAL(status.profile_manifest_backend, "external_gnark_command");
        BOOST_CHECK_EQUAL(status.valid_proof_vector_count, 1U);
        BOOST_CHECK_EQUAL(status.invalid_proof_vector_count, 2U);
        BOOST_CHECK_EQUAL(status.profile_manifest_public_input_count, 7U);
    }
    BOOST_CHECK(
        status.status == "missing profile manifest" ||
        status.status == "missing verifying key" ||
        status.status == "missing proving key" ||
        status.status == "verifier command not configured" ||
        status.status == "profile manifest valid proof vector missing" ||
        status.status == "profile manifest invalid proof vector missing");
}

BOOST_AUTO_TEST_CASE(validation_rejects_invalid_profiles_and_limits)
{
    const SupportedValiditySidechainConfig& supported = GetSupportedValiditySidechainConfigs().front();

    {
        ValiditySidechainConfig config = MakeSupportedConfig();
        config.verifier_id = 255;

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
    BOOST_REQUIRE(sidechain->queue_entries.at(0).status == ValiditySidechainQueueEntry::QUEUE_STATUS_TOMBSTONED);
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

BOOST_AUTO_TEST_CASE(add_force_exit_request_updates_queue_state_and_maturity)
{
    ValiditySidechainState state;
    const ValiditySidechainConfig config = MakeSupportedConfig();
    BOOST_REQUIRE(state.RegisterSidechain(/* id= */ 10, /* registration_height= */ 360, config));

    const CScript destination_script = CScript() << OP_TRUE << OP_DROP;
    const ValiditySidechainForceExitData request = MakeForceExitRequest(
        uint256S("2525252525252525252525252525252525252525252525252525252525252525"),
        destination_script);

    std::string error;
    BOOST_REQUIRE(state.AddForceExitRequest(/* sidechain_id= */ 10, /* request_height= */ 365, request, &error));
    BOOST_CHECK(error.empty());

    const uint256 request_hash = ComputeValiditySidechainForceExitHash(/* scid= */ 10, request);
    const ValiditySidechain* sidechain = state.GetSidechain(10);
    BOOST_REQUIRE(sidechain != nullptr);
    BOOST_REQUIRE(state.GetPendingForceExit(10, request_hash) != nullptr);
    BOOST_CHECK_EQUAL(sidechain->queue_state.pending_force_exit_count, 1U);
    BOOST_CHECK_EQUAL(sidechain->queue_state.matured_force_exit_count, 0U);

    CBlock idle_block;
    CBlockIndex idle_index;
    idle_index.nHeight = 365 + config.force_inclusion_delay;
    BlockValidationState validation_state;
    BOOST_REQUIRE(state.ConnectBlock(idle_block, &idle_index, validation_state));

    sidechain = state.GetSidechain(10);
    BOOST_REQUIRE(sidechain != nullptr);
    BOOST_CHECK_EQUAL(sidechain->queue_state.pending_force_exit_count, 1U);
    BOOST_CHECK_EQUAL(sidechain->queue_state.matured_force_exit_count, 1U);
}

BOOST_AUTO_TEST_CASE(connect_block_handles_force_exit_request)
{
    ValiditySidechainState state;
    const ValiditySidechainConfig config = MakeSupportedConfig();
    BOOST_REQUIRE(state.RegisterSidechain(/* id= */ 11, /* registration_height= */ 370, config));

    const CScript destination_script = CScript() << OP_5;
    const ValiditySidechainForceExitData request = MakeForceExitRequest(
        uint256S("2626262626262626262626262626262626262626262626262626262626262626"),
        destination_script,
        4 * COIN);

    CMutableTransaction tx;
    tx.vout.emplace_back(/* nValueIn= */ 0, BuildValiditySidechainForceExitScript(/* scid= */ 11, request));

    CBlock block;
    block.vtx.push_back(MakeTransactionRef(tx));

    CBlockIndex index;
    index.nHeight = 371;

    BlockValidationState validation_state;
    BOOST_REQUIRE(state.ConnectBlock(block, &index, validation_state));

    const uint256 request_hash = ComputeValiditySidechainForceExitHash(/* scid= */ 11, request);
    BOOST_REQUIRE(state.GetPendingForceExit(11, request_hash) != nullptr);
}

BOOST_AUTO_TEST_CASE(accept_batch_records_noop_scaffold_batch)
{
    ValiditySidechainState state;
    const ValiditySidechainConfig config = MakeSupportedConfig();
    BOOST_REQUIRE(state.RegisterSidechain(/* id= */ 5, /* registration_height= */ 300, config));

    const ValiditySidechain* sidechain = state.GetSidechain(5);
    BOOST_REQUIRE(sidechain != nullptr);

    const ValiditySidechainBatchPublicInputs public_inputs = MakeNoopBatchPublicInputs(*sidechain, /* batch_number= */ 1);
    const std::vector<unsigned char> proof_bytes = BuildScaffoldBatchProofForTest(/* sidechain_id= */ 5, *sidechain, public_inputs);
    std::string error;
    BOOST_REQUIRE(state.AcceptBatch(/* sidechain_id= */ 5, /* accepted_height= */ 320, public_inputs, proof_bytes, {}, &error));
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
    BOOST_CHECK(batch->queue_prefix_commitment == public_inputs.queue_prefix_commitment);
}

BOOST_AUTO_TEST_CASE(connect_block_handles_noop_batch_commit)
{
    ValiditySidechainState state;
    const ValiditySidechainConfig config = MakeSupportedConfig();
    BOOST_REQUIRE(state.RegisterSidechain(/* id= */ 7, /* registration_height= */ 330, config));

    const ValiditySidechain* sidechain = state.GetSidechain(7);
    BOOST_REQUIRE(sidechain != nullptr);
    const ValiditySidechainBatchPublicInputs public_inputs = MakeNoopBatchPublicInputs(*sidechain, /* batch_number= */ 1);
    const std::vector<unsigned char> proof_bytes = BuildScaffoldBatchProofForTest(/* sidechain_id= */ 7, *sidechain, public_inputs);

    CMutableTransaction batch_tx;
    batch_tx.vout.emplace_back(
        /* nValueIn= */ 0,
        BuildValiditySidechainCommitScript(
            /* scid= */ 7,
            public_inputs,
            proof_bytes,
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
        const std::vector<unsigned char> proof_bytes = BuildScaffoldBatchProofForTest(/* sidechain_id= */ 6, *sidechain, public_inputs);

        std::string error;
        BOOST_CHECK(!state.AcceptBatch(/* sidechain_id= */ 6, /* accepted_height= */ 312, public_inputs, proof_bytes, {}, &error));
        BOOST_CHECK_EQUAL(error, "scaffold verifier only allows no-op state root updates");
    }

    {
        sidechain = state.GetSidechain(6);
        BOOST_REQUIRE(sidechain != nullptr);
        ValiditySidechainBatchPublicInputs public_inputs = MakeNoopBatchPublicInputs(*sidechain, /* batch_number= */ 1);
        public_inputs.consumed_queue_messages = 1;
        public_inputs.l1_message_root_after = sidechain->queue_state.root;
        const std::vector<unsigned char> proof_bytes = BuildScaffoldBatchProofForTest(/* sidechain_id= */ 6, *sidechain, public_inputs);

        std::string error;
        BOOST_CHECK(!state.AcceptBatch(/* sidechain_id= */ 6, /* accepted_height= */ 312, public_inputs, proof_bytes, {}, &error));
        BOOST_CHECK_EQUAL(error, "batch queue root after does not match consumed prefix");
    }
}

BOOST_AUTO_TEST_CASE(transition_scaffold_batch_accepts_root_and_da_updates)
{
    ValiditySidechainState state;
    const ValiditySidechainConfig config = MakeSupportedConfig(/* supported_index= */ 1);
    BOOST_REQUIRE(state.RegisterSidechain(/* id= */ 26, /* registration_height= */ 700, config));
    BOOST_CHECK_EQUAL(
        GetValiditySidechainBatchVerifierMode(config),
        ValiditySidechainBatchVerifierMode::SCAFFOLD_TRANSITION_COMMITMENT);

    const CScript refund_script = CScript() << OP_TRUE;
    const ValiditySidechainDepositData deposit = MakeDeposit(
        uint256S("4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a"),
        refund_script,
        6 * COIN);
    BOOST_REQUIRE(state.AddDeposit(/* sidechain_id= */ 26, /* deposit_height= */ 701, deposit));

    const ValiditySidechain* sidechain = state.GetSidechain(26);
    BOOST_REQUIRE(sidechain != nullptr);

    const std::vector<std::vector<unsigned char>> data_chunks{
        {0xaa, 0xbb},
        {0xcc, 0xdd, 0xee},
    };

    ValiditySidechainBatchPublicInputs public_inputs = MakeNoopBatchPublicInputs(*sidechain, /* batch_number= */ 1);
    public_inputs.new_state_root = uint256S("4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b");
    public_inputs.withdrawal_root = uint256S("4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c");
    public_inputs.consumed_queue_messages = 1;
    public_inputs.l1_message_root_after = ComputeConsumedQueueRootForTest(*sidechain, /* sidechain_id= */ 26, /* consumed_queue_messages= */ 1);
    public_inputs.queue_prefix_commitment = ComputeQueuePrefixCommitmentForTest(*sidechain, /* sidechain_id= */ 26, /* consumed_queue_messages= */ 1);
    public_inputs.data_root = ComputeValiditySidechainDataRoot(data_chunks);
    public_inputs.data_size = 5;
    const std::vector<unsigned char> proof_bytes = BuildScaffoldBatchProofForTest(/* sidechain_id= */ 26, *sidechain, public_inputs);

    std::string error;
    BOOST_REQUIRE(state.AcceptBatch(/* sidechain_id= */ 26, /* accepted_height= */ 702, public_inputs, proof_bytes, data_chunks, &error));
    BOOST_CHECK(error.empty());

    sidechain = state.GetSidechain(26);
    BOOST_REQUIRE(sidechain != nullptr);
    BOOST_CHECK(sidechain->current_state_root == public_inputs.new_state_root);
    BOOST_CHECK(sidechain->current_withdrawal_root == public_inputs.withdrawal_root);
    BOOST_CHECK(sidechain->current_data_root == public_inputs.data_root);
    BOOST_CHECK_EQUAL(sidechain->latest_batch_number, 1U);
    BOOST_CHECK_EQUAL(sidechain->queue_state.head_index, 1U);
    BOOST_CHECK_EQUAL(sidechain->queue_state.pending_message_count, 0U);
    BOOST_REQUIRE(state.GetPendingDeposit(26, deposit.deposit_id) == nullptr);

    const ValiditySidechainAcceptedBatch* batch = state.GetAcceptedBatch(26, 1);
    BOOST_REQUIRE(batch != nullptr);
    BOOST_CHECK(batch->new_state_root == public_inputs.new_state_root);
    BOOST_CHECK(batch->withdrawal_root == public_inputs.withdrawal_root);
    BOOST_CHECK(batch->data_root == public_inputs.data_root);
    BOOST_CHECK_EQUAL(batch->consumed_queue_messages, 1U);
    BOOST_CHECK(batch->queue_prefix_commitment == public_inputs.queue_prefix_commitment);
}

BOOST_AUTO_TEST_CASE(real_profile_batch_rejects_invalid_native_proof_bytes)
{
    ValiditySidechainState state;
    const ValiditySidechainConfig config = MakeSupportedConfig(/* supported_index= */ 4);
    BOOST_REQUIRE(state.RegisterSidechain(/* id= */ 27, /* registration_height= */ 710, config));

    const ValiditySidechain* sidechain = state.GetSidechain(27);
    BOOST_REQUIRE(sidechain != nullptr);
    ValiditySidechainBatchPublicInputs public_inputs = MakeNoopBatchPublicInputs(*sidechain, /* batch_number= */ 1);
    public_inputs.new_state_root = uint256S("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a");
    public_inputs.withdrawal_root = uint256S("5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b");

    std::string error;
    BOOST_CHECK(!state.AcceptBatch(
        /* sidechain_id= */ 27,
        /* accepted_height= */ 711,
        public_inputs,
        std::vector<unsigned char>{0x01},
        {},
        &error));
    BOOST_CHECK_EQUAL(error, "Groth16 proof bytes have unexpected length");
}

BOOST_AUTO_TEST_CASE(real_profile_batch_rejects_more_than_one_consumed_queue_message)
{
    ValiditySidechainState state;
    const ValiditySidechainConfig config = MakeSupportedConfig(/* supported_index= */ 4);
    BOOST_REQUIRE(state.RegisterSidechain(/* id= */ 28, /* registration_height= */ 710, config));

    const ValiditySidechain* sidechain = state.GetSidechain(28);
    BOOST_REQUIRE(sidechain != nullptr);
    ValiditySidechainBatchPublicInputs public_inputs = MakeNoopBatchPublicInputs(*sidechain, /* batch_number= */ 1);
    public_inputs.new_state_root = uint256S("6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a");
    public_inputs.consumed_queue_messages = 2;

    std::string error;
    BOOST_CHECK(!state.AcceptBatch(
        /* sidechain_id= */ 28,
        /* accepted_height= */ 711,
        public_inputs,
        std::vector<unsigned char>{0x01},
        {},
        &error));
    BOOST_CHECK_EQUAL(error, "experimental real profile currently supports at most one consumed queue message");
}

BOOST_AUTO_TEST_CASE(real_profile_withdrawal_execution_rejects_more_than_one_leaf)
{
    ValiditySidechainState state;
    const ValiditySidechainConfig config = MakeSupportedConfig(/* supported_index= */ 4);
    BOOST_REQUIRE(state.RegisterSidechain(/* id= */ 29, /* registration_height= */ 710, config));

    ValiditySidechainAcceptedBatch batch;
    batch.batch_number = 1;
    batch.withdrawal_root = uint256S("7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b");
    batch.accepted_height = 711;
    ValiditySidechain* sidechain = state.GetSidechain(29);
    BOOST_REQUIRE(sidechain != nullptr);
    sidechain->accepted_batches.emplace(batch.batch_number, batch);

    ValiditySidechainWithdrawalProof proof_a;
    proof_a.withdrawal.withdrawal_id = uint256S("0101010101010101010101010101010101010101010101010101010101010101");
    proof_a.withdrawal.amount = COIN;
    ValiditySidechainWithdrawalProof proof_b;
    proof_b.withdrawal.withdrawal_id = uint256S("0202020202020202020202020202020202020202020202020202020202020202");
    proof_b.withdrawal.amount = COIN;

    std::string error;
    BOOST_CHECK(!state.ExecuteWithdrawals(
        /* sidechain_id= */ 29,
        ComputeValiditySidechainAcceptedBatchId(/* sidechain_id= */ 29, batch.batch_number, batch.withdrawal_root),
        {proof_a, proof_b},
        &error));
    BOOST_CHECK_EQUAL(error, "experimental real profile currently supports at most one executed withdrawal leaf");
}

BOOST_AUTO_TEST_CASE(real_profile_withdrawal_execution_rejects_non_single_leaf_proof_shape)
{
    ValiditySidechainState state;
    const ValiditySidechainConfig config = MakeSupportedConfig(/* supported_index= */ 4);
    BOOST_REQUIRE(state.RegisterSidechain(/* id= */ 30, /* registration_height= */ 710, config));

    const std::vector<ValiditySidechainWithdrawalLeaf> withdrawals = {
        {uint256S("1111111111111111111111111111111111111111111111111111111111111111"), COIN, uint256S("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")},
        {uint256S("2222222222222222222222222222222222222222222222222222222222222222"), COIN, uint256S("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")},
    };
    ValiditySidechainAcceptedBatch batch;
    batch.batch_number = 1;
    batch.withdrawal_root = ComputeValiditySidechainWithdrawalRoot(withdrawals);
    batch.accepted_height = 711;
    ValiditySidechain* sidechain = state.GetSidechain(30);
    BOOST_REQUIRE(sidechain != nullptr);
    sidechain->accepted_batches.emplace(batch.batch_number, batch);

    ValiditySidechainWithdrawalProof proof;
    BOOST_REQUIRE(BuildValiditySidechainWithdrawalProof(withdrawals, /* withdrawal_index= */ 0, proof));
    BOOST_CHECK_EQUAL(proof.leaf_count, 2U);
    BOOST_REQUIRE(!proof.sibling_hashes.empty());

    std::string error;
    BOOST_CHECK(!state.ExecuteWithdrawals(
        /* sidechain_id= */ 30,
        ComputeValiditySidechainAcceptedBatchId(/* sidechain_id= */ 30, batch.batch_number, batch.withdrawal_root),
        {proof},
        &error));
    BOOST_CHECK_EQUAL(error, "experimental real profile requires single-leaf withdrawal proofs");
}

BOOST_AUTO_TEST_CASE(accept_batch_rejects_invalid_scaffold_proof_envelope)
{
    ValiditySidechainState state;
    const ValiditySidechainConfig config = MakeSupportedConfig();
    BOOST_REQUIRE(state.RegisterSidechain(/* id= */ 18, /* registration_height= */ 620, config));

    const ValiditySidechain* sidechain = state.GetSidechain(18);
    BOOST_REQUIRE(sidechain != nullptr);

    const ValiditySidechainBatchPublicInputs public_inputs = MakeNoopBatchPublicInputs(*sidechain, /* batch_number= */ 1);
    std::vector<unsigned char> proof_bytes = BuildScaffoldBatchProofForTest(/* sidechain_id= */ 18, *sidechain, public_inputs);
    BOOST_REQUIRE(!proof_bytes.empty());
    proof_bytes.pop_back();

    std::string error;
    BOOST_CHECK(!state.AcceptBatch(/* sidechain_id= */ 18, /* accepted_height= */ 621, public_inputs, proof_bytes, {}, &error));
    BOOST_CHECK_EQUAL(error, "invalid scaffold proof envelope");
}

BOOST_AUTO_TEST_CASE(accept_batch_rejects_empty_proof_bytes)
{
    ValiditySidechainState state;
    const ValiditySidechainConfig config = MakeSupportedConfig();
    BOOST_REQUIRE(state.RegisterSidechain(/* id= */ 19, /* registration_height= */ 620, config));

    const ValiditySidechain* sidechain = state.GetSidechain(19);
    BOOST_REQUIRE(sidechain != nullptr);

    const ValiditySidechainBatchPublicInputs public_inputs = MakeNoopBatchPublicInputs(*sidechain, /* batch_number= */ 1);

    std::string error;
    BOOST_CHECK(!state.AcceptBatch(/* sidechain_id= */ 19, /* accepted_height= */ 621, public_inputs, {}, {}, &error));
    BOOST_CHECK_EQUAL(error, "proof bytes must be non-empty");
}

BOOST_AUTO_TEST_CASE(accept_batch_rejects_missing_data_chunks_for_nonzero_data_size)
{
    ValiditySidechainState state;
    const ValiditySidechainConfig config = MakeSupportedConfig();
    BOOST_REQUIRE(state.RegisterSidechain(/* id= */ 20, /* registration_height= */ 620, config));

    const ValiditySidechain* sidechain = state.GetSidechain(20);
    BOOST_REQUIRE(sidechain != nullptr);

    ValiditySidechainBatchPublicInputs public_inputs = MakeNoopBatchPublicInputs(*sidechain, /* batch_number= */ 1);
    public_inputs.data_root = uint256S("abababababababababababababababababababababababababababababababab");
    public_inputs.data_size = 4;
    const std::vector<unsigned char> proof_bytes = BuildScaffoldBatchProofForTest(/* sidechain_id= */ 20, *sidechain, public_inputs);

    std::string error;
    BOOST_CHECK(!state.AcceptBatch(/* sidechain_id= */ 20, /* accepted_height= */ 621, public_inputs, proof_bytes, {}, &error));
    BOOST_CHECK_EQUAL(error, "data chunks missing for non-zero data_size");
}

BOOST_AUTO_TEST_CASE(accept_batch_rejects_empty_data_chunk)
{
    ValiditySidechainState state;
    const ValiditySidechainConfig config = MakeSupportedConfig();
    BOOST_REQUIRE(state.RegisterSidechain(/* id= */ 21, /* registration_height= */ 620, config));

    const ValiditySidechain* sidechain = state.GetSidechain(21);
    BOOST_REQUIRE(sidechain != nullptr);

    ValiditySidechainBatchPublicInputs public_inputs = MakeNoopBatchPublicInputs(*sidechain, /* batch_number= */ 1);
    const std::vector<std::vector<unsigned char>> data_chunks{{}};
    public_inputs.data_root = ComputeValiditySidechainDataRoot(data_chunks);
    public_inputs.data_size = 0;
    const std::vector<unsigned char> proof_bytes = BuildScaffoldBatchProofForTest(/* sidechain_id= */ 21, *sidechain, public_inputs);

    std::string error;
    BOOST_CHECK(!state.AcceptBatch(/* sidechain_id= */ 21, /* accepted_height= */ 621, public_inputs, proof_bytes, data_chunks, &error));
    BOOST_CHECK_EQUAL(error, "data chunk must be non-empty");
}

BOOST_AUTO_TEST_CASE(accept_batch_rejects_mismatched_data_root)
{
    ValiditySidechainState state;
    const ValiditySidechainConfig config = MakeSupportedConfig();
    BOOST_REQUIRE(state.RegisterSidechain(/* id= */ 22, /* registration_height= */ 620, config));

    const ValiditySidechain* sidechain = state.GetSidechain(22);
    BOOST_REQUIRE(sidechain != nullptr);

    const std::vector<std::vector<unsigned char>> data_chunks{{0x01, 0x02}, {0x03, 0x04}};
    ValiditySidechainBatchPublicInputs public_inputs = MakeNoopBatchPublicInputs(*sidechain, /* batch_number= */ 1);
    public_inputs.data_root = uint256S("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd");
    public_inputs.data_size = 4;
    const std::vector<unsigned char> proof_bytes = BuildScaffoldBatchProofForTest(/* sidechain_id= */ 22, *sidechain, public_inputs);

    std::string error;
    BOOST_CHECK(!state.AcceptBatch(/* sidechain_id= */ 22, /* accepted_height= */ 621, public_inputs, proof_bytes, data_chunks, &error));
    BOOST_CHECK_EQUAL(error, "data root does not match published chunks");
}

BOOST_AUTO_TEST_CASE(accept_batch_rejects_oversized_proof_bytes)
{
    ValiditySidechainState state;
    const ValiditySidechainConfig config = MakeSupportedConfig();
    BOOST_REQUIRE(state.RegisterSidechain(/* id= */ 23, /* registration_height= */ 620, config));

    const ValiditySidechain* sidechain = state.GetSidechain(23);
    BOOST_REQUIRE(sidechain != nullptr);

    const ValiditySidechainBatchPublicInputs public_inputs = MakeNoopBatchPublicInputs(*sidechain, /* batch_number= */ 1);
    std::vector<unsigned char> proof_bytes(config.max_proof_bytes + 1, 0x42);

    std::string error;
    BOOST_CHECK(!state.AcceptBatch(/* sidechain_id= */ 23, /* accepted_height= */ 621, public_inputs, proof_bytes, {}, &error));
    BOOST_CHECK_EQUAL(error, "proof bytes exceed configured limit");
}

BOOST_AUTO_TEST_CASE(accept_batch_rejects_oversized_data_size)
{
    ValiditySidechainState state;
    const ValiditySidechainConfig config = MakeSupportedConfig();
    BOOST_REQUIRE(state.RegisterSidechain(/* id= */ 24, /* registration_height= */ 620, config));

    const ValiditySidechain* sidechain = state.GetSidechain(24);
    BOOST_REQUIRE(sidechain != nullptr);

    ValiditySidechainBatchPublicInputs public_inputs = MakeNoopBatchPublicInputs(*sidechain, /* batch_number= */ 1);
    public_inputs.data_size = config.max_batch_data_bytes + 1;
    const std::vector<unsigned char> proof_bytes = BuildScaffoldBatchProofForTest(/* sidechain_id= */ 24, *sidechain, public_inputs);

    std::string error;
    BOOST_CHECK(!state.AcceptBatch(/* sidechain_id= */ 24, /* accepted_height= */ 621, public_inputs, proof_bytes, {}, &error));
    BOOST_CHECK_EQUAL(error, "data size exceeds configured limit");
}

BOOST_AUTO_TEST_CASE(accept_batch_consumes_queue_prefix_and_clears_pending_records)
{
    ValiditySidechainState state;
    const ValiditySidechainConfig config = MakeSupportedConfig();
    BOOST_REQUIRE(state.RegisterSidechain(/* id= */ 14, /* registration_height= */ 500, config));

    const CScript refund_script = CScript() << OP_TRUE;
    const ValiditySidechainDepositData deposit = MakeDeposit(
        uint256S("3434343434343434343434343434343434343434343434343434343434343434"),
        refund_script,
        4 * COIN);
    BOOST_REQUIRE(state.AddDeposit(/* sidechain_id= */ 14, /* deposit_height= */ 501, deposit));

    const CScript destination_script = CScript() << OP_10;
    const ValiditySidechainForceExitData request = MakeForceExitRequest(
        uint256S("3535353535353535353535353535353535353535353535353535353535353535"),
        destination_script,
        2 * COIN);
    BOOST_REQUIRE(state.AddForceExitRequest(/* sidechain_id= */ 14, /* request_height= */ 502, request));

    const ValiditySidechain* sidechain = state.GetSidechain(14);
    BOOST_REQUIRE(sidechain != nullptr);

    ValiditySidechainBatchPublicInputs public_inputs = MakeNoopBatchPublicInputs(*sidechain, /* batch_number= */ 1);
    public_inputs.consumed_queue_messages = 2;
    public_inputs.l1_message_root_after = ComputeConsumedQueueRootForTest(*sidechain, /* sidechain_id= */ 14, /* consumed_queue_messages= */ 2);
    public_inputs.queue_prefix_commitment = ComputeQueuePrefixCommitmentForTest(*sidechain, /* sidechain_id= */ 14, /* consumed_queue_messages= */ 2);
    const std::vector<unsigned char> proof_bytes = BuildScaffoldBatchProofForTest(/* sidechain_id= */ 14, *sidechain, public_inputs);

    std::string error;
    BOOST_REQUIRE(state.AcceptBatch(/* sidechain_id= */ 14, /* accepted_height= */ 503, public_inputs, proof_bytes, {}, &error));
    BOOST_CHECK(error.empty());

    sidechain = state.GetSidechain(14);
    BOOST_REQUIRE(sidechain != nullptr);
    BOOST_CHECK_EQUAL(sidechain->latest_batch_number, 1U);
    BOOST_CHECK_EQUAL(sidechain->queue_state.head_index, 2U);
    BOOST_CHECK_EQUAL(sidechain->queue_state.pending_message_count, 0U);
    BOOST_CHECK_EQUAL(sidechain->queue_state.pending_deposit_count, 0U);
    BOOST_CHECK_EQUAL(sidechain->queue_state.pending_force_exit_count, 0U);
    BOOST_REQUIRE(state.GetPendingDeposit(14, deposit.deposit_id) == nullptr);
    BOOST_REQUIRE(state.GetPendingForceExit(14, ComputeValiditySidechainForceExitHash(/* scid= */ 14, request)) == nullptr);
    BOOST_REQUIRE(sidechain->queue_entries.at(0).status == ValiditySidechainQueueEntry::QUEUE_STATUS_CONSUMED);
    BOOST_REQUIRE(sidechain->queue_entries.at(1).status == ValiditySidechainQueueEntry::QUEUE_STATUS_CONSUMED);
}

BOOST_AUTO_TEST_CASE(accept_batch_requires_matured_force_exit_consumption)
{
    ValiditySidechainState state;
    const ValiditySidechainConfig config = MakeSupportedConfig();
    BOOST_REQUIRE(state.RegisterSidechain(/* id= */ 15, /* registration_height= */ 540, config));

    const CScript refund_script = CScript() << OP_TRUE << OP_DROP;
    const ValiditySidechainDepositData deposit = MakeDeposit(
        uint256S("3636363636363636363636363636363636363636363636363636363636363636"),
        refund_script,
        3 * COIN);
    BOOST_REQUIRE(state.AddDeposit(/* sidechain_id= */ 15, /* deposit_height= */ 541, deposit));

    const CScript destination_script = CScript() << OP_11;
    const ValiditySidechainForceExitData request = MakeForceExitRequest(
        uint256S("3737373737373737373737373737373737373737373737373737373737373737"),
        destination_script,
        1 * COIN);
    BOOST_REQUIRE(state.AddForceExitRequest(/* sidechain_id= */ 15, /* request_height= */ 542, request));

    CBlock idle_block;
    CBlockIndex idle_index;
    idle_index.nHeight = 542 + config.force_inclusion_delay;
    BlockValidationState validation_state;
    BOOST_REQUIRE(state.ConnectBlock(idle_block, &idle_index, validation_state));

    const ValiditySidechain* sidechain = state.GetSidechain(15);
    BOOST_REQUIRE(sidechain != nullptr);
    BOOST_CHECK_EQUAL(sidechain->queue_state.matured_force_exit_count, 1U);

    {
        ValiditySidechainBatchPublicInputs public_inputs = MakeNoopBatchPublicInputs(*sidechain, /* batch_number= */ 1);
        public_inputs.consumed_queue_messages = 1;
        public_inputs.l1_message_root_after = ComputeConsumedQueueRootForTest(*sidechain, /* sidechain_id= */ 15, /* consumed_queue_messages= */ 1);
        const std::vector<unsigned char> proof_bytes = BuildScaffoldBatchProofForTest(/* sidechain_id= */ 15, *sidechain, public_inputs);

        std::string error;
        BOOST_CHECK(!state.AcceptBatch(/* sidechain_id= */ 15, /* accepted_height= */ idle_index.nHeight, public_inputs, proof_bytes, {}, &error));
        BOOST_CHECK_EQUAL(error, "batch must consume all matured force-exit requests in reachable queue prefix");
    }

    {
        sidechain = state.GetSidechain(15);
        BOOST_REQUIRE(sidechain != nullptr);
        ValiditySidechainBatchPublicInputs public_inputs = MakeNoopBatchPublicInputs(*sidechain, /* batch_number= */ 1);
        public_inputs.consumed_queue_messages = 2;
        public_inputs.l1_message_root_after = ComputeConsumedQueueRootForTest(*sidechain, /* sidechain_id= */ 15, /* consumed_queue_messages= */ 2);
        public_inputs.queue_prefix_commitment = ComputeQueuePrefixCommitmentForTest(*sidechain, /* sidechain_id= */ 15, /* consumed_queue_messages= */ 2);
        const std::vector<unsigned char> proof_bytes = BuildScaffoldBatchProofForTest(/* sidechain_id= */ 15, *sidechain, public_inputs);

        std::string error;
        BOOST_REQUIRE(state.AcceptBatch(/* sidechain_id= */ 15, /* accepted_height= */ idle_index.nHeight, public_inputs, proof_bytes, {}, &error));
        BOOST_CHECK(error.empty());
    }
}

BOOST_AUTO_TEST_CASE(execute_withdrawals_marks_ids_and_reduces_escrow)
{
    ValiditySidechainState state;
    const ValiditySidechainConfig config = MakeSupportedConfig();
    BOOST_REQUIRE(state.RegisterSidechain(/* id= */ 8, /* registration_height= */ 340, config));

    ValiditySidechain* sidechain = state.GetSidechain(8);
    BOOST_REQUIRE(sidechain != nullptr);
    sidechain->escrow_balance = 10 * COIN;

    const CScript payout_a = CScript() << OP_1;
    const CScript payout_b = CScript() << OP_2;
    const std::vector<ValiditySidechainWithdrawalLeaf> withdrawals{
        MakeWithdrawalLeaf(uint256S("2020202020202020202020202020202020202020202020202020202020202020"), payout_a, 2 * COIN),
        MakeWithdrawalLeaf(uint256S("2121212121212121212121212121212121212121212121212121212121212121"), payout_b, 3 * COIN),
    };
    InstallAcceptedWithdrawalBatch(state, /* sidechain_id= */ 8, /* batch_number= */ 1, withdrawals, /* accepted_height= */ 341);

    const uint256 accepted_batch_id = ComputeValiditySidechainAcceptedBatchId(
        /* scid= */ 8,
        /* batch_number= */ 1,
        ComputeValiditySidechainWithdrawalRoot(withdrawals));
    const std::vector<ValiditySidechainWithdrawalProof> withdrawal_proofs = BuildWithdrawalProofsForTest(withdrawals);

    std::string error;
    BOOST_REQUIRE(state.ExecuteWithdrawals(/* sidechain_id= */ 8, accepted_batch_id, withdrawal_proofs, &error));
    BOOST_CHECK(error.empty());

    sidechain = state.GetSidechain(8);
    BOOST_REQUIRE(sidechain != nullptr);
    BOOST_CHECK_EQUAL(sidechain->escrow_balance, 5 * COIN);
    BOOST_CHECK_EQUAL(sidechain->executed_withdrawal_count, 2U);
    BOOST_CHECK(state.HasExecutedWithdrawal(8, withdrawals[0].withdrawal_id));
    BOOST_CHECK(state.HasExecutedWithdrawal(8, withdrawals[1].withdrawal_id));

    BOOST_CHECK(!state.ExecuteWithdrawals(/* sidechain_id= */ 8, accepted_batch_id, withdrawal_proofs, &error));
    BOOST_CHECK_EQUAL(error, "withdrawal id already executed");
}

BOOST_AUTO_TEST_CASE(execute_withdrawals_rejects_invalid_merkle_proof)
{
    ValiditySidechainState state;
    const ValiditySidechainConfig config = MakeSupportedConfig();
    BOOST_REQUIRE(state.RegisterSidechain(/* id= */ 16, /* registration_height= */ 560, config));

    ValiditySidechain* sidechain = state.GetSidechain(16);
    BOOST_REQUIRE(sidechain != nullptr);
    sidechain->escrow_balance = 5 * COIN;

    const CScript payout_a = CScript() << OP_12;
    const CScript payout_b = CScript() << OP_13;
    const std::vector<ValiditySidechainWithdrawalLeaf> withdrawals{
        MakeWithdrawalLeaf(uint256S("3838383838383838383838383838383838383838383838383838383838383838"), payout_a, 1 * COIN),
        MakeWithdrawalLeaf(uint256S("3939393939393939393939393939393939393939393939393939393939393939"), payout_b, 2 * COIN),
    };
    InstallAcceptedWithdrawalBatch(state, /* sidechain_id= */ 16, /* batch_number= */ 1, withdrawals, /* accepted_height= */ 561);

    const uint256 accepted_batch_id = ComputeValiditySidechainAcceptedBatchId(
        /* scid= */ 16,
        /* batch_number= */ 1,
        ComputeValiditySidechainWithdrawalRoot(withdrawals));
    std::vector<ValiditySidechainWithdrawalProof> withdrawal_proofs = BuildWithdrawalProofsForTest(withdrawals);
    BOOST_REQUIRE(!withdrawal_proofs.empty());
    BOOST_REQUIRE(!withdrawal_proofs.front().sibling_hashes.empty());
    withdrawal_proofs.front().sibling_hashes[0] = uint256S("3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a");

    std::string error;
    BOOST_CHECK(!state.ExecuteWithdrawals(/* sidechain_id= */ 16, accepted_batch_id, withdrawal_proofs, &error));
    BOOST_CHECK_EQUAL(error, "withdrawal proof does not match accepted withdrawal root");
}

BOOST_AUTO_TEST_CASE(connect_block_handles_verified_withdrawal_execution)
{
    ValiditySidechainState state;
    const ValiditySidechainConfig config = MakeSupportedConfig();
    BOOST_REQUIRE(state.RegisterSidechain(/* id= */ 9, /* registration_height= */ 350, config));

    ValiditySidechain* sidechain = state.GetSidechain(9);
    BOOST_REQUIRE(sidechain != nullptr);
    sidechain->escrow_balance = 6 * COIN;

    const CScript payout_a = CScript() << OP_3;
    const CScript payout_b = CScript() << OP_4;
    const std::vector<ValiditySidechainWithdrawalLeaf> withdrawals{
        MakeWithdrawalLeaf(uint256S("2222222222222222222222222222222222222222222222222222222222222222"), payout_a, 1 * COIN),
        MakeWithdrawalLeaf(uint256S("2323232323232323232323232323232323232323232323232323232323232323"), payout_b, 2 * COIN),
    };
    InstallAcceptedWithdrawalBatch(state, /* sidechain_id= */ 9, /* batch_number= */ 1, withdrawals, /* accepted_height= */ 351);
    const std::vector<ValiditySidechainWithdrawalProof> withdrawal_proofs = BuildWithdrawalProofsForTest(withdrawals);

    CMutableTransaction tx;
    tx.vout.emplace_back(
        /* nValueIn= */ 0,
        BuildValiditySidechainExecuteScript(
            /* scid= */ 9,
            /* batch_number= */ 1,
            ComputeValiditySidechainWithdrawalRoot(withdrawals),
            withdrawal_proofs));
    tx.vout.emplace_back(1 * COIN, payout_a);
    tx.vout.emplace_back(2 * COIN, payout_b);

    CBlock block;
    block.vtx.push_back(MakeTransactionRef(tx));

    CBlockIndex index;
    index.nHeight = 352;

    BlockValidationState validation_state;
    BOOST_REQUIRE(state.ConnectBlock(block, &index, validation_state));
    BOOST_CHECK(state.HasExecutedWithdrawal(9, withdrawals[0].withdrawal_id));
    BOOST_CHECK(state.HasExecutedWithdrawal(9, withdrawals[1].withdrawal_id));
}

BOOST_AUTO_TEST_CASE(execute_escape_exits_requires_halt_and_tracks_replay)
{
    ValiditySidechainState state;
    const ValiditySidechainConfig config = MakeSupportedConfig();
    BOOST_REQUIRE(state.RegisterSidechain(/* id= */ 12, /* registration_height= */ 400, config));

    ValiditySidechain* sidechain = state.GetSidechain(12);
    BOOST_REQUIRE(sidechain != nullptr);
    sidechain->escrow_balance = 9 * COIN;

    const CScript payout_a = CScript() << OP_6;
    const CScript payout_b = CScript() << OP_7;
    const std::vector<ValiditySidechainEscapeExitLeaf> exits{
        MakeEscapeExitLeaf(uint256S("3030303030303030303030303030303030303030303030303030303030303030"), payout_a, 2 * COIN),
        MakeEscapeExitLeaf(uint256S("3131313131313131313131313131313131313131313131313131313131313131"), payout_b, 3 * COIN),
    };
    const uint256 escape_root = ComputeValiditySidechainEscapeExitRoot(exits);
    const std::vector<ValiditySidechainEscapeExitProof> exit_proofs = BuildEscapeExitProofsForTest(exits);
    sidechain->current_state_root = escape_root;

    std::string error;
    BOOST_CHECK(!state.ExecuteEscapeExits(/* sidechain_id= */ 12, /* execution_height= */ 400 + config.escape_hatch_delay - 1, escape_root, exit_proofs, &error));
    BOOST_CHECK_EQUAL(error, "escape hatch delay not reached");

    BOOST_REQUIRE(state.ExecuteEscapeExits(/* sidechain_id= */ 12, /* execution_height= */ 400 + config.escape_hatch_delay, escape_root, exit_proofs, &error));
    BOOST_CHECK(error.empty());
    BOOST_CHECK_EQUAL(sidechain->escrow_balance, 4 * COIN);
    BOOST_CHECK_EQUAL(sidechain->executed_escape_exit_count, 2U);
    BOOST_CHECK(state.HasExecutedEscapeExit(12, exits[0].exit_id));
    BOOST_CHECK(state.HasExecutedEscapeExit(12, exits[1].exit_id));

    BOOST_CHECK(!state.ExecuteEscapeExits(/* sidechain_id= */ 12, /* execution_height= */ 400 + config.escape_hatch_delay, escape_root, exit_proofs, &error));
    BOOST_CHECK_EQUAL(error, "escape-exit id already executed");
}

BOOST_AUTO_TEST_CASE(connect_block_handles_escape_exit_execution)
{
    ValiditySidechainState state;
    const ValiditySidechainConfig config = MakeSupportedConfig();
    BOOST_REQUIRE(state.RegisterSidechain(/* id= */ 13, /* registration_height= */ 420, config));

    ValiditySidechain* sidechain = state.GetSidechain(13);
    BOOST_REQUIRE(sidechain != nullptr);
    sidechain->escrow_balance = 8 * COIN;

    const CScript payout_a = CScript() << OP_8;
    const CScript payout_b = CScript() << OP_9;
    const std::vector<ValiditySidechainEscapeExitLeaf> exits{
        MakeEscapeExitLeaf(uint256S("3232323232323232323232323232323232323232323232323232323232323232"), payout_a, 1 * COIN),
        MakeEscapeExitLeaf(uint256S("3333333333333333333333333333333333333333333333333333333333333333"), payout_b, 2 * COIN),
    };
    const uint256 escape_root = ComputeValiditySidechainEscapeExitRoot(exits);
    const std::vector<ValiditySidechainEscapeExitProof> exit_proofs = BuildEscapeExitProofsForTest(exits);
    sidechain->current_state_root = escape_root;

    CMutableTransaction tx;
    tx.vout.emplace_back(
        /* nValueIn= */ 0,
        BuildValiditySidechainEscapeExitScript(/* scid= */ 13, escape_root, exit_proofs));
    tx.vout.emplace_back(1 * COIN, payout_a);
    tx.vout.emplace_back(2 * COIN, payout_b);

    CBlock block;
    block.vtx.push_back(MakeTransactionRef(tx));

    CBlockIndex index;
    index.nHeight = 420 + config.escape_hatch_delay;

    BlockValidationState validation_state;
    BOOST_REQUIRE(state.ConnectBlock(block, &index, validation_state));
    BOOST_CHECK(state.HasExecutedEscapeExit(13, exits[0].exit_id));
    BOOST_CHECK(state.HasExecutedEscapeExit(13, exits[1].exit_id));
}

BOOST_AUTO_TEST_CASE(execute_escape_exits_rejects_invalid_merkle_proof)
{
    ValiditySidechainState state;
    const ValiditySidechainConfig config = MakeSupportedConfig();
    BOOST_REQUIRE(state.RegisterSidechain(/* id= */ 17, /* registration_height= */ 600, config));

    ValiditySidechain* sidechain = state.GetSidechain(17);
    BOOST_REQUIRE(sidechain != nullptr);
    sidechain->escrow_balance = 7 * COIN;

    const CScript payout_a = CScript() << OP_14;
    const CScript payout_b = CScript() << OP_15;
    const std::vector<ValiditySidechainEscapeExitLeaf> exits{
        MakeEscapeExitLeaf(uint256S("3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b"), payout_a, 2 * COIN),
        MakeEscapeExitLeaf(uint256S("3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c"), payout_b, 1 * COIN),
    };
    const uint256 escape_root = ComputeValiditySidechainEscapeExitRoot(exits);
    sidechain->current_state_root = escape_root;

    std::vector<ValiditySidechainEscapeExitProof> exit_proofs = BuildEscapeExitProofsForTest(exits);
    BOOST_REQUIRE(!exit_proofs.empty());
    BOOST_REQUIRE(!exit_proofs.front().sibling_hashes.empty());
    exit_proofs.front().sibling_hashes[0] = uint256S("3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d");

    std::string error;
    BOOST_CHECK(!state.ExecuteEscapeExits(/* sidechain_id= */ 17, /* execution_height= */ 600 + config.escape_hatch_delay, escape_root, exit_proofs, &error));
    BOOST_CHECK_EQUAL(error, "escape-exit proof does not match referenced state root");
}

BOOST_AUTO_TEST_CASE(execute_escape_exits_rejects_non_scaffold_profiles)
{
    ValiditySidechainState state;
    const ValiditySidechainConfig config = MakeSupportedConfig(/* supported_index= */ 4);
    BOOST_REQUIRE(state.RegisterSidechain(/* id= */ 18, /* registration_height= */ 620, config));

    ValiditySidechain* sidechain = state.GetSidechain(18);
    BOOST_REQUIRE(sidechain != nullptr);
    sidechain->escrow_balance = 4 * COIN;

    const CScript payout = CScript() << OP_16;
    const std::vector<ValiditySidechainEscapeExitLeaf> exits{
        MakeEscapeExitLeaf(uint256S("4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e"), payout, 1 * COIN),
    };
    const uint256 escape_root = ComputeValiditySidechainEscapeExitRoot(exits);
    const std::vector<ValiditySidechainEscapeExitProof> exit_proofs = BuildEscapeExitProofsForTest(exits);
    sidechain->current_state_root = escape_root;

    std::string error;
    BOOST_CHECK(!state.ExecuteEscapeExits(/* sidechain_id= */ 18, /* execution_height= */ 620 + config.escape_hatch_delay, escape_root, exit_proofs, &error));
    BOOST_CHECK_EQUAL(error, "escape exits are not implemented for non-scaffold profiles");
    BOOST_CHECK_EQUAL(sidechain->executed_escape_exit_count, 0U);
}

BOOST_AUTO_TEST_SUITE_END()
