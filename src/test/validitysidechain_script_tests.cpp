// Copyright (c) 2026 AllSageTech, LLC
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/script.h>
#include <primitives/transaction.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <validitysidechain/script.h>

#include <boost/test/unit_test.hpp>

namespace {

ValiditySidechainConfig MakeRegisterConfig()
{
    ValiditySidechainConfig config;
    config.version = 1;
    config.proof_system_id = 2;
    config.circuit_family_id = 3;
    config.verifier_id = 4;
    config.public_input_version = 1;
    config.state_root_format = 5;
    config.deposit_message_format = 6;
    config.withdrawal_leaf_format = 7;
    config.balance_leaf_format = 8;
    config.data_availability_mode = 9;
    config.max_batch_data_bytes = 4096;
    config.max_proof_bytes = 512;
    config.force_inclusion_delay = 144;
    config.deposit_reclaim_delay = 288;
    config.escape_hatch_delay = 432;
    config.initial_state_root = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    config.initial_withdrawal_root = uint256S("2222222222222222222222222222222222222222222222222222222222222222");
    return config;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(validitysidechain_script_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(register_script_roundtrip)
{
    const ValiditySidechainConfig config = MakeRegisterConfig();

    const uint8_t sidechain_id = 7;
    const CScript script = BuildValiditySidechainRegisterScript(sidechain_id, config);

    ValiditySidechainScriptInfo info;
    BOOST_REQUIRE(DecodeValiditySidechainScript(script, info));
    BOOST_CHECK(info.kind == ValiditySidechainScriptInfo::Kind::REGISTER_VALIDITY_SIDECHAIN);
    BOOST_CHECK_EQUAL(info.sidechain_id, sidechain_id);
    BOOST_REQUIRE_EQUAL(info.metadata_pushes.size(), 1U);

    ValiditySidechainConfig decoded_config;
    BOOST_REQUIRE(DecodeValiditySidechainConfig(info.primary_metadata, decoded_config));
    BOOST_CHECK_EQUAL(decoded_config.max_batch_data_bytes, config.max_batch_data_bytes);
    BOOST_CHECK_EQUAL(decoded_config.max_proof_bytes, config.max_proof_bytes);
    BOOST_CHECK_EQUAL(decoded_config.force_inclusion_delay, config.force_inclusion_delay);
    BOOST_CHECK(decoded_config.initial_state_root == config.initial_state_root);
    BOOST_CHECK(decoded_config.initial_withdrawal_root == config.initial_withdrawal_root);
    BOOST_CHECK(info.payload == ComputeValiditySidechainConfigHash(config));
    BOOST_CHECK(info.payload == ComputeValiditySidechainConfigHash(decoded_config));
}

BOOST_AUTO_TEST_CASE(register_script_is_classified_as_drivechain)
{
    const CScript script = BuildValiditySidechainRegisterScript(/* scid= */ 3, MakeRegisterConfig());
    BOOST_CHECK(script.IsDrivechain());
}

BOOST_AUTO_TEST_CASE(register_transaction_reports_drivechain_stuff)
{
    CMutableTransaction tx;
    tx.vout.emplace_back(/* nValueIn= */ 1, BuildValiditySidechainRegisterScript(/* scid= */ 4, MakeRegisterConfig()));
    BOOST_CHECK(CTransaction(tx).HasDrivechainStuff());
}

BOOST_AUTO_TEST_CASE(config_decode_rejects_zero_limits)
{
    ValiditySidechainConfig config;
    config.version = 1;
    config.proof_system_id = 1;
    config.circuit_family_id = 1;
    config.verifier_id = 1;
    config.public_input_version = 1;
    config.state_root_format = 1;
    config.deposit_message_format = 1;
    config.withdrawal_leaf_format = 1;
    config.balance_leaf_format = 1;
    config.data_availability_mode = 1;
    config.max_batch_data_bytes = 1024;
    config.max_proof_bytes = 256;
    config.force_inclusion_delay = 100;
    config.deposit_reclaim_delay = 200;
    config.escape_hatch_delay = 300;

    std::vector<unsigned char> encoded = EncodeValiditySidechainConfig(config);
    encoded[14] = 0x00;
    encoded[15] = 0x00;
    encoded[16] = 0x00;
    encoded[17] = 0x00;

    ValiditySidechainConfig decoded;
    BOOST_CHECK(!DecodeValiditySidechainConfig(encoded, decoded));
}

BOOST_AUTO_TEST_CASE(deposit_script_roundtrip)
{
    ValiditySidechainDepositData deposit;
    deposit.deposit_id = uint256S("3333333333333333333333333333333333333333333333333333333333333333");
    deposit.amount = 25 * COIN;
    deposit.destination_commitment = uint256S("4444444444444444444444444444444444444444444444444444444444444444");
    deposit.refund_script_commitment = uint256S("5555555555555555555555555555555555555555555555555555555555555555");
    deposit.nonce = 99;

    const uint8_t sidechain_id = 8;
    const CScript script = BuildValiditySidechainDepositScript(sidechain_id, deposit);

    ValiditySidechainScriptInfo info;
    BOOST_REQUIRE(DecodeValiditySidechainScript(script, info));
    BOOST_CHECK(info.kind == ValiditySidechainScriptInfo::Kind::DEPOSIT_TO_VALIDITY_SIDECHAIN);
    BOOST_CHECK_EQUAL(info.sidechain_id, sidechain_id);
    BOOST_REQUIRE_EQUAL(info.metadata_pushes.size(), 1U);

    ValiditySidechainDepositData decoded_deposit;
    BOOST_REQUIRE(DecodeValiditySidechainDepositData(info.primary_metadata, decoded_deposit));
    BOOST_CHECK(decoded_deposit.deposit_id == deposit.deposit_id);
    BOOST_CHECK_EQUAL(decoded_deposit.amount, deposit.amount);
    BOOST_CHECK(decoded_deposit.destination_commitment == deposit.destination_commitment);
    BOOST_CHECK(decoded_deposit.refund_script_commitment == deposit.refund_script_commitment);
    BOOST_CHECK_EQUAL(decoded_deposit.nonce, deposit.nonce);
    BOOST_CHECK(info.payload == ComputeValiditySidechainDepositMessageHash(sidechain_id, deposit));
}

BOOST_AUTO_TEST_CASE(commit_script_roundtrip)
{
    ValiditySidechainBatchPublicInputs public_inputs;
    public_inputs.batch_number = 12;
    public_inputs.prior_state_root = uint256S("6666666666666666666666666666666666666666666666666666666666666666");
    public_inputs.new_state_root = uint256S("7777777777777777777777777777777777777777777777777777777777777777");
    public_inputs.l1_message_root_before = uint256S("8888888888888888888888888888888888888888888888888888888888888888");
    public_inputs.l1_message_root_after = uint256S("9999999999999999999999999999999999999999999999999999999999999999");
    public_inputs.consumed_queue_messages = 3;
    public_inputs.withdrawal_root = uint256S("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    public_inputs.data_root = uint256S("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    public_inputs.data_size = 2048;

    const std::vector<unsigned char> proof_placeholder{0x01, 0x02, 0x03};
    const std::vector<std::vector<unsigned char>> data_chunks{{0x04, 0x05}, {0x06}};
    const uint8_t sidechain_id = 9;
    const CScript script = BuildValiditySidechainCommitScript(sidechain_id, public_inputs, proof_placeholder, data_chunks);

    ValiditySidechainScriptInfo info;
    BOOST_REQUIRE(DecodeValiditySidechainScript(script, info));
    BOOST_CHECK(info.kind == ValiditySidechainScriptInfo::Kind::COMMIT_VALIDITY_BATCH);
    BOOST_CHECK_EQUAL(info.sidechain_id, sidechain_id);
    BOOST_REQUIRE_EQUAL(info.metadata_pushes.size(), 4U);

    ValiditySidechainBatchPublicInputs decoded_public_inputs;
    std::vector<unsigned char> decoded_proof_bytes;
    std::vector<std::vector<unsigned char>> decoded_data_chunks;
    BOOST_REQUIRE(DecodeValiditySidechainCommitMetadata(info, decoded_public_inputs, decoded_proof_bytes, decoded_data_chunks));
    BOOST_CHECK_EQUAL(decoded_public_inputs.batch_number, public_inputs.batch_number);
    BOOST_CHECK(decoded_public_inputs.prior_state_root == public_inputs.prior_state_root);
    BOOST_CHECK(decoded_public_inputs.new_state_root == public_inputs.new_state_root);
    BOOST_CHECK_EQUAL(decoded_public_inputs.consumed_queue_messages, public_inputs.consumed_queue_messages);
    BOOST_CHECK(decoded_public_inputs.withdrawal_root == public_inputs.withdrawal_root);
    BOOST_CHECK_EQUAL(decoded_public_inputs.data_size, public_inputs.data_size);
    BOOST_CHECK(decoded_proof_bytes == proof_placeholder);
    BOOST_CHECK(decoded_data_chunks == data_chunks);
    BOOST_CHECK(info.payload == ComputeValiditySidechainBatchCommitmentHash(sidechain_id, public_inputs));
}

BOOST_AUTO_TEST_CASE(force_exit_script_roundtrip)
{
    ValiditySidechainForceExitData request;
    request.account_id = uint256S("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    request.exit_asset_id = uint256S("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
    request.max_exit_amount = 7 * COIN;
    request.destination_commitment = uint256S("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
    request.nonce = 5;

    const uint8_t sidechain_id = 11;
    const CScript script = BuildValiditySidechainForceExitScript(sidechain_id, request);

    ValiditySidechainScriptInfo info;
    BOOST_REQUIRE(DecodeValiditySidechainScript(script, info));
    BOOST_CHECK(info.kind == ValiditySidechainScriptInfo::Kind::REQUEST_FORCE_EXIT);
    BOOST_CHECK_EQUAL(info.sidechain_id, sidechain_id);
    BOOST_REQUIRE_EQUAL(info.metadata_pushes.size(), 1U);

    ValiditySidechainForceExitData decoded_request;
    BOOST_REQUIRE(DecodeValiditySidechainForceExitData(info.primary_metadata, decoded_request));
    BOOST_CHECK(decoded_request.account_id == request.account_id);
    BOOST_CHECK(decoded_request.exit_asset_id == request.exit_asset_id);
    BOOST_CHECK_EQUAL(decoded_request.max_exit_amount, request.max_exit_amount);
    BOOST_CHECK(decoded_request.destination_commitment == request.destination_commitment);
    BOOST_CHECK_EQUAL(decoded_request.nonce, request.nonce);
    BOOST_CHECK(info.payload == ComputeValiditySidechainForceExitHash(sidechain_id, request));
}

BOOST_AUTO_TEST_CASE(execute_and_reclaim_markers_roundtrip)
{
    const uint8_t sidechain_id = 12;
    const uint32_t batch_number = 34;
    ValiditySidechainDepositData deposit;
    deposit.deposit_id = uint256S("1212121212121212121212121212121212121212121212121212121212121212");
    deposit.amount = 6 * COIN;
    deposit.destination_commitment = uint256S("1414141414141414141414141414141414141414141414141414141414141414");
    deposit.refund_script_commitment = uint256S("1515151515151515151515151515151515151515151515151515151515151515");
    deposit.nonce = 7;
    const std::vector<ValiditySidechainWithdrawalLeaf> withdrawals{
        {
            uint256S("1616161616161616161616161616161616161616161616161616161616161616"),
            2 * COIN,
            uint256S("1717171717171717171717171717171717171717171717171717171717171717"),
        },
        {
            uint256S("1818181818181818181818181818181818181818181818181818181818181818"),
            3 * COIN,
            uint256S("1919191919191919191919191919191919191919191919191919191919191919"),
        },
    };
    const uint256 withdrawal_root = ComputeValiditySidechainWithdrawalRoot(withdrawals);
    std::vector<ValiditySidechainWithdrawalProof> withdrawal_proofs;
    for (uint32_t i = 0; i < withdrawals.size(); ++i) {
        ValiditySidechainWithdrawalProof proof;
        BOOST_REQUIRE(BuildValiditySidechainWithdrawalProof(withdrawals, i, proof));
        withdrawal_proofs.push_back(std::move(proof));
    }
    const std::vector<ValiditySidechainEscapeExitLeaf> exits{
        {
            uint256S("1313131313131313131313131313131313131313131313131313131313131313"),
            1 * COIN,
            uint256S("1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a"),
        },
        {
            uint256S("1414141414141414141414141414141414141414141414141414141414141414"),
            4 * COIN,
            uint256S("1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b"),
        },
    };
    const uint256 state_root_reference = ComputeValiditySidechainEscapeExitRoot(exits);
    std::vector<ValiditySidechainEscapeExitProof> exit_proofs;
    for (uint32_t i = 0; i < exits.size(); ++i) {
        ValiditySidechainEscapeExitProof proof;
        BOOST_REQUIRE(BuildValiditySidechainEscapeExitProof(exits, i, proof));
        exit_proofs.push_back(std::move(proof));
    }

    {
        ValiditySidechainScriptInfo info;
        BOOST_REQUIRE(DecodeValiditySidechainScript(
            BuildValiditySidechainExecuteScript(sidechain_id, batch_number, withdrawal_root, withdrawal_proofs),
            info));
        BOOST_CHECK(info.kind == ValiditySidechainScriptInfo::Kind::EXECUTE_VERIFIED_WITHDRAWALS);
        BOOST_CHECK(info.payload == ComputeValiditySidechainAcceptedBatchId(sidechain_id, batch_number, withdrawal_root));
        BOOST_REQUIRE_EQUAL(info.metadata_pushes.size(), withdrawal_proofs.size());

        std::vector<ValiditySidechainWithdrawalProof> decoded_withdrawal_proofs;
        BOOST_REQUIRE(DecodeValiditySidechainExecuteMetadata(info, decoded_withdrawal_proofs));
        BOOST_REQUIRE_EQUAL(decoded_withdrawal_proofs.size(), withdrawal_proofs.size());
        BOOST_CHECK(decoded_withdrawal_proofs[0].withdrawal.withdrawal_id == withdrawals[0].withdrawal_id);
        BOOST_CHECK_EQUAL(decoded_withdrawal_proofs[1].withdrawal.amount, withdrawals[1].amount);
        BOOST_CHECK(decoded_withdrawal_proofs[1].withdrawal.destination_commitment == withdrawals[1].destination_commitment);
        BOOST_CHECK_EQUAL(decoded_withdrawal_proofs[0].leaf_index, 0U);
        BOOST_CHECK_EQUAL(decoded_withdrawal_proofs[0].leaf_count, static_cast<uint32_t>(withdrawals.size()));
        BOOST_CHECK(VerifyValiditySidechainWithdrawalProof(decoded_withdrawal_proofs[0], withdrawal_root));
        BOOST_CHECK(VerifyValiditySidechainWithdrawalProof(decoded_withdrawal_proofs[1], withdrawal_root));
    }

    {
        ValiditySidechainScriptInfo info;
        BOOST_REQUIRE(DecodeValiditySidechainScript(
            BuildValiditySidechainReclaimDepositScript(sidechain_id, deposit),
            info));
        BOOST_CHECK(info.kind == ValiditySidechainScriptInfo::Kind::RECLAIM_STALE_DEPOSIT);
        BOOST_CHECK(info.payload == deposit.deposit_id);
        BOOST_REQUIRE_EQUAL(info.metadata_pushes.size(), 1U);

        ValiditySidechainDepositData decoded_deposit;
        BOOST_REQUIRE(DecodeValiditySidechainDepositData(info.primary_metadata, decoded_deposit));
        BOOST_CHECK(decoded_deposit.deposit_id == deposit.deposit_id);
        BOOST_CHECK_EQUAL(decoded_deposit.amount, deposit.amount);
        BOOST_CHECK(decoded_deposit.refund_script_commitment == deposit.refund_script_commitment);
    }

    {
        ValiditySidechainScriptInfo info;
        BOOST_REQUIRE(DecodeValiditySidechainScript(
            BuildValiditySidechainEscapeExitScript(sidechain_id, state_root_reference, exit_proofs),
            info));
        BOOST_CHECK(info.kind == ValiditySidechainScriptInfo::Kind::EXECUTE_ESCAPE_EXIT);
        BOOST_CHECK(info.payload == state_root_reference);
        BOOST_REQUIRE_EQUAL(info.metadata_pushes.size(), exit_proofs.size());

        std::vector<ValiditySidechainEscapeExitProof> decoded_exit_proofs;
        BOOST_REQUIRE(DecodeValiditySidechainEscapeExitMetadata(info, decoded_exit_proofs));
        BOOST_REQUIRE_EQUAL(decoded_exit_proofs.size(), exit_proofs.size());
        BOOST_CHECK(decoded_exit_proofs[0].exit.exit_id == exits[0].exit_id);
        BOOST_CHECK_EQUAL(decoded_exit_proofs[1].exit.amount, exits[1].amount);
        BOOST_CHECK(decoded_exit_proofs[1].exit.destination_commitment == exits[1].destination_commitment);
        BOOST_CHECK_EQUAL(decoded_exit_proofs[0].leaf_index, 0U);
        BOOST_CHECK_EQUAL(decoded_exit_proofs[0].leaf_count, static_cast<uint32_t>(exits.size()));
        BOOST_CHECK(VerifyValiditySidechainEscapeExitProof(decoded_exit_proofs[0], state_root_reference));
        BOOST_CHECK(VerifyValiditySidechainEscapeExitProof(decoded_exit_proofs[1], state_root_reference));
    }
}

BOOST_AUTO_TEST_CASE(validity_parser_rejects_legacy_register_tag)
{
    const std::vector<unsigned char> payload(32, 0x42);
    CScript script;
    script << OP_RETURN << OP_DRIVECHAIN << std::vector<unsigned char>{1} << payload << std::vector<unsigned char>{0x05};

    ValiditySidechainScriptInfo info;
    BOOST_CHECK(!DecodeValiditySidechainScript(script, info));
}

BOOST_AUTO_TEST_SUITE_END()
