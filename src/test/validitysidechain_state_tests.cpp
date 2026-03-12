// Copyright (c) 2026 AllSageTech, LLC
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <consensus/validation.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
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
    BOOST_CHECK_EQUAL(validation_state.GetRejectReason(), "validitysidechain-multi-register");
    BOOST_CHECK(state.sidechains.empty());
}

BOOST_AUTO_TEST_SUITE_END()
