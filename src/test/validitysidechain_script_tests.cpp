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

BOOST_AUTO_TEST_CASE(register_script_uses_validity_transport)
{
    const CScript script = BuildValiditySidechainRegisterScript(/* scid= */ 3, MakeRegisterConfig());
    BOOST_CHECK(IsValiditySidechainTransport(script));
}

BOOST_AUTO_TEST_CASE(register_transaction_reports_sidechain_data)
{
    CMutableTransaction tx;
    tx.vout.emplace_back(/* nValueIn= */ 1, BuildValiditySidechainRegisterScript(/* scid= */ 4, MakeRegisterConfig()));
    BOOST_CHECK(CTransaction(tx).HasSidechainData());
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
    public_inputs.queue_prefix_commitment = uint256S("9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a");
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
    BOOST_CHECK(decoded_public_inputs.queue_prefix_commitment == public_inputs.queue_prefix_commitment);
    BOOST_CHECK(decoded_public_inputs.withdrawal_root == public_inputs.withdrawal_root);
    BOOST_CHECK_EQUAL(decoded_public_inputs.data_size, public_inputs.data_size);
    BOOST_CHECK(decoded_proof_bytes == proof_placeholder);
    BOOST_CHECK(decoded_data_chunks == data_chunks);
    BOOST_CHECK(info.payload == ComputeValiditySidechainBatchCommitmentHash(sidechain_id, public_inputs));
}

BOOST_AUTO_TEST_CASE(commit_script_rejects_out_of_order_data_chunks)
{
    ValiditySidechainBatchPublicInputs public_inputs;
    public_inputs.batch_number = 13;
    public_inputs.prior_state_root = uint256S("0101010101010101010101010101010101010101010101010101010101010101");
    public_inputs.new_state_root = uint256S("0202020202020202020202020202020202020202020202020202020202020202");
    public_inputs.l1_message_root_before = uint256S("0303030303030303030303030303030303030303030303030303030303030303");
    public_inputs.l1_message_root_after = uint256S("0404040404040404040404040404040404040404040404040404040404040404");
    public_inputs.queue_prefix_commitment = uint256S("0454545454545454545454545454545454545454545454545454545454545454");
    public_inputs.withdrawal_root = uint256S("0505050505050505050505050505050505050505050505050505050505050505");
    public_inputs.data_root = uint256S("0606060606060606060606060606060606060606060606060606060606060606");
    public_inputs.data_size = 3;

    const CScript script = BuildValiditySidechainCommitScript(
        /* scid= */ 9,
        public_inputs,
        /* proof_bytes= */ {0x01},
        /* data_chunks= */ {{0xaa}, {0xbb, 0xcc}});

    ValiditySidechainScriptInfo info;
    BOOST_REQUIRE(DecodeValiditySidechainScript(script, info));
    BOOST_REQUIRE_EQUAL(info.metadata_pushes.size(), 4U);
    std::swap(info.metadata_pushes[2], info.metadata_pushes[3]);

    ValiditySidechainBatchPublicInputs decoded_public_inputs;
    std::vector<unsigned char> decoded_proof_bytes;
    std::vector<std::vector<unsigned char>> decoded_data_chunks;
    BOOST_CHECK(!DecodeValiditySidechainCommitMetadata(info, decoded_public_inputs, decoded_proof_bytes, decoded_data_chunks));
}

BOOST_AUTO_TEST_CASE(commit_script_rejects_inconsistent_data_chunk_count)
{
    ValiditySidechainBatchPublicInputs public_inputs;
    public_inputs.batch_number = 14;
    public_inputs.prior_state_root = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    public_inputs.new_state_root = uint256S("1212121212121212121212121212121212121212121212121212121212121212");
    public_inputs.l1_message_root_before = uint256S("1313131313131313131313131313131313131313131313131313131313131313");
    public_inputs.l1_message_root_after = uint256S("1414141414141414141414141414141414141414141414141414141414141414");
    public_inputs.queue_prefix_commitment = uint256S("1454545454545454545454545454545454545454545454545454545454545454");
    public_inputs.withdrawal_root = uint256S("1515151515151515151515151515151515151515151515151515151515151515");
    public_inputs.data_root = uint256S("1616161616161616161616161616161616161616161616161616161616161616");
    public_inputs.data_size = 2;

    const CScript script = BuildValiditySidechainCommitScript(
        /* scid= */ 10,
        public_inputs,
        /* proof_bytes= */ {0x02},
        /* data_chunks= */ {{0x10}, {0x20}});

    ValiditySidechainScriptInfo info;
    BOOST_REQUIRE(DecodeValiditySidechainScript(script, info));
    BOOST_REQUIRE_EQUAL(info.metadata_pushes.size(), 4U);
    BOOST_REQUIRE(info.metadata_pushes[2].size() >= 8U);
    info.metadata_pushes[2][4] = 0x03;
    info.metadata_pushes[2][5] = 0x00;
    info.metadata_pushes[2][6] = 0x00;
    info.metadata_pushes[2][7] = 0x00;

    ValiditySidechainBatchPublicInputs decoded_public_inputs;
    std::vector<unsigned char> decoded_proof_bytes;
    std::vector<std::vector<unsigned char>> decoded_data_chunks;
    BOOST_CHECK(!DecodeValiditySidechainCommitMetadata(info, decoded_public_inputs, decoded_proof_bytes, decoded_data_chunks));
}

BOOST_AUTO_TEST_CASE(commit_script_rejects_data_chunk_count_above_consensus_limit)
{
    ValiditySidechainBatchPublicInputs public_inputs;
    public_inputs.batch_number = 15;
    public_inputs.prior_state_root = uint256S("1717171717171717171717171717171717171717171717171717171717171717");
    public_inputs.new_state_root = uint256S("1818181818181818181818181818181818181818181818181818181818181818");
    public_inputs.l1_message_root_before = uint256S("1919191919191919191919191919191919191919191919191919191919191919");
    public_inputs.l1_message_root_after = uint256S("1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a");
    public_inputs.queue_prefix_commitment = uint256S("1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b");
    public_inputs.withdrawal_root = uint256S("1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c");
    public_inputs.data_root = uint256S("1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d");
    public_inputs.data_size = MAX_VALIDITY_SIDECHAIN_BATCH_DATA_CHUNKS + 1;

    ValiditySidechainScriptInfo info;
    BOOST_REQUIRE(DecodeValiditySidechainScript(
        BuildValiditySidechainCommitScript(
            /* scid= */ 11,
            public_inputs,
            /* proof_bytes= */ {0x03},
            /* data_chunks= */ {{0x01}}),
        info));
    info.metadata_pushes.resize(static_cast<size_t>(MAX_VALIDITY_SIDECHAIN_BATCH_DATA_CHUNKS) + 3U);

    ValiditySidechainBatchPublicInputs decoded_public_inputs;
    std::vector<unsigned char> decoded_proof_bytes;
    std::vector<std::vector<unsigned char>> decoded_data_chunks;
    BOOST_CHECK(!DecodeValiditySidechainCommitMetadata(info, decoded_public_inputs, decoded_proof_bytes, decoded_data_chunks));
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

BOOST_AUTO_TEST_CASE(escape_exit_state_proof_roundtrip)
{
    ValiditySidechainEscapeExitStateProof proof;
    proof.exit_id = uint256S("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    proof.exit_asset_id = uint256S("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    proof.amount = 3 * COIN;
    proof.destination_commitment = uint256S("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    proof.account_proof.account.account_id = uint256S("0101010101010101010101010101010101010101010101010101010101010101");
    proof.account_proof.account.spend_key_commitment = uint256S("0202020202020202020202020202020202020202020202020202020202020202");
    proof.account_proof.account.balance_root = uint256S("0303030303030303030303030303030303030303030303030303030303030303");
    proof.account_proof.account.account_nonce = 17;
    proof.account_proof.account.last_forced_exit_nonce = 9;
    proof.account_proof.leaf_index = 1;
    proof.account_proof.leaf_count = 2;
    proof.account_proof.sibling_hashes = {
        uint256S("0404040404040404040404040404040404040404040404040404040404040404"),
    };
    proof.balance_proof.balance.asset_id = uint256S("0505050505050505050505050505050505050505050505050505050505050505");
    proof.balance_proof.balance.balance = 12 * COIN;
    proof.balance_proof.leaf_index = 0;
    proof.balance_proof.leaf_count = 1;
    proof.required_account_nonce = 18;
    proof.required_last_forced_exit_nonce = 10;

    const std::vector<unsigned char> encoded = EncodeValiditySidechainEscapeExitStateProof(proof);

    ValiditySidechainEscapeExitStateProof decoded;
    BOOST_REQUIRE(DecodeValiditySidechainEscapeExitStateProof(encoded, decoded));
    BOOST_CHECK(decoded.exit_id == proof.exit_id);
    BOOST_CHECK(decoded.exit_asset_id == proof.exit_asset_id);
    BOOST_CHECK_EQUAL(decoded.amount, proof.amount);
    BOOST_CHECK(decoded.destination_commitment == proof.destination_commitment);
    BOOST_CHECK(decoded.account_proof.account.account_id == proof.account_proof.account.account_id);
    BOOST_CHECK(decoded.account_proof.account.spend_key_commitment == proof.account_proof.account.spend_key_commitment);
    BOOST_CHECK(decoded.account_proof.account.balance_root == proof.account_proof.account.balance_root);
    BOOST_CHECK_EQUAL(decoded.account_proof.account.account_nonce, proof.account_proof.account.account_nonce);
    BOOST_CHECK_EQUAL(decoded.account_proof.account.last_forced_exit_nonce, proof.account_proof.account.last_forced_exit_nonce);
    BOOST_CHECK_EQUAL(decoded.account_proof.leaf_index, proof.account_proof.leaf_index);
    BOOST_CHECK_EQUAL(decoded.account_proof.leaf_count, proof.account_proof.leaf_count);
    BOOST_REQUIRE_EQUAL(decoded.account_proof.sibling_hashes.size(), proof.account_proof.sibling_hashes.size());
    BOOST_CHECK(decoded.account_proof.sibling_hashes[0] == proof.account_proof.sibling_hashes[0]);
    BOOST_CHECK(decoded.balance_proof.balance.asset_id == proof.balance_proof.balance.asset_id);
    BOOST_CHECK_EQUAL(decoded.balance_proof.balance.balance, proof.balance_proof.balance.balance);
    BOOST_CHECK_EQUAL(decoded.balance_proof.leaf_index, proof.balance_proof.leaf_index);
    BOOST_CHECK_EQUAL(decoded.balance_proof.leaf_count, proof.balance_proof.leaf_count);
    BOOST_CHECK_EQUAL(decoded.required_account_nonce, proof.required_account_nonce);
    BOOST_CHECK_EQUAL(decoded.required_last_forced_exit_nonce, proof.required_last_forced_exit_nonce);
}

BOOST_AUTO_TEST_CASE(escape_exit_state_script_roundtrip)
{
    const uint8_t sidechain_id = 19;
    const uint256 state_root_reference = uint256S("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
    ValiditySidechainEscapeExitStateProof first_proof;
    first_proof.exit_id = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    first_proof.exit_asset_id = uint256S("1212121212121212121212121212121212121212121212121212121212121212");
    first_proof.amount = 1 * COIN;
    first_proof.destination_commitment = uint256S("1313131313131313131313131313131313131313131313131313131313131313");
    first_proof.account_proof.account.account_id = uint256S("1414141414141414141414141414141414141414141414141414141414141414");
    first_proof.account_proof.account.spend_key_commitment = uint256S("1515151515151515151515151515151515151515151515151515151515151515");
    first_proof.account_proof.account.balance_root = uint256S("1616161616161616161616161616161616161616161616161616161616161616");
    first_proof.account_proof.account.account_nonce = 2;
    first_proof.account_proof.account.last_forced_exit_nonce = 1;
    first_proof.account_proof.leaf_index = 0;
    first_proof.account_proof.leaf_count = 1;
    first_proof.balance_proof.balance.asset_id = uint256S("1717171717171717171717171717171717171717171717171717171717171717");
    first_proof.balance_proof.balance.balance = 5 * COIN;
    first_proof.balance_proof.leaf_index = 0;
    first_proof.balance_proof.leaf_count = 1;
    first_proof.required_account_nonce = 3;
    first_proof.required_last_forced_exit_nonce = 2;

    ValiditySidechainEscapeExitStateProof second_proof;
    second_proof.exit_id = uint256S("1818181818181818181818181818181818181818181818181818181818181818");
    second_proof.exit_asset_id = uint256S("1919191919191919191919191919191919191919191919191919191919191919");
    second_proof.amount = 2 * COIN;
    second_proof.destination_commitment = uint256S("1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a");
    second_proof.account_proof.account.account_id = uint256S("1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b");
    second_proof.account_proof.account.spend_key_commitment = uint256S("1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c");
    second_proof.account_proof.account.balance_root = uint256S("1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d");
    second_proof.account_proof.account.account_nonce = 6;
    second_proof.account_proof.account.last_forced_exit_nonce = 4;
    second_proof.account_proof.leaf_index = 1;
    second_proof.account_proof.leaf_count = 2;
    second_proof.account_proof.sibling_hashes = {
        uint256S("1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e"),
    };
    second_proof.balance_proof.balance.asset_id = uint256S("1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f");
    second_proof.balance_proof.balance.balance = 8 * COIN;
    second_proof.balance_proof.leaf_index = 0;
    second_proof.balance_proof.leaf_count = 1;
    second_proof.required_account_nonce = 7;
    second_proof.required_last_forced_exit_nonce = 5;

    const std::vector<ValiditySidechainEscapeExitStateProof> exit_state_proofs{
        first_proof,
        second_proof,
    };

    ValiditySidechainScriptInfo info;
    BOOST_REQUIRE(DecodeValiditySidechainScript(
        BuildValiditySidechainEscapeExitStateScript(sidechain_id, state_root_reference, exit_state_proofs),
        info));
    BOOST_CHECK(info.kind == ValiditySidechainScriptInfo::Kind::EXECUTE_ESCAPE_EXIT);
    BOOST_CHECK(info.payload == state_root_reference);
    BOOST_REQUIRE_EQUAL(info.metadata_pushes.size(), exit_state_proofs.size());

    std::vector<ValiditySidechainEscapeExitStateProof> decoded;
    BOOST_REQUIRE(DecodeValiditySidechainEscapeExitStateMetadata(info, decoded));
    BOOST_REQUIRE_EQUAL(decoded.size(), exit_state_proofs.size());
    BOOST_CHECK(decoded[0].exit_id == exit_state_proofs[0].exit_id);
    BOOST_CHECK(decoded[0].account_proof.account.account_id == exit_state_proofs[0].account_proof.account.account_id);
    BOOST_CHECK(decoded[0].balance_proof.balance.asset_id == exit_state_proofs[0].balance_proof.balance.asset_id);
    BOOST_CHECK_EQUAL(decoded[1].amount, exit_state_proofs[1].amount);
    BOOST_CHECK(decoded[1].destination_commitment == exit_state_proofs[1].destination_commitment);
    BOOST_CHECK_EQUAL(decoded[1].required_account_nonce, exit_state_proofs[1].required_account_nonce);
    BOOST_CHECK_EQUAL(decoded[1].required_last_forced_exit_nonce, exit_state_proofs[1].required_last_forced_exit_nonce);
    BOOST_REQUIRE_EQUAL(decoded[1].account_proof.sibling_hashes.size(), 1U);
    BOOST_CHECK(decoded[1].account_proof.sibling_hashes[0] == exit_state_proofs[1].account_proof.sibling_hashes[0]);
}

BOOST_AUTO_TEST_CASE(balance_and_account_state_proof_helpers_roundtrip)
{
    const std::vector<ValiditySidechainBalanceLeaf> balances{
        {uint256S("3030303030303030303030303030303030303030303030303030303030303030"), 2 * COIN},
        {uint256S("3131313131313131313131313131313131313131313131313131313131313131"), 5 * COIN},
        {uint256S("3232323232323232323232323232323232323232323232323232323232323232"), 7 * COIN},
    };
    const uint256 balance_root = ComputeValiditySidechainBalanceRoot(balances);

    ValiditySidechainBalanceProof balance_proof;
    BOOST_REQUIRE(BuildValiditySidechainBalanceProof(balances, /* leaf_index= */ 1, balance_proof));
    BOOST_CHECK_EQUAL(balance_proof.leaf_index, 1U);
    BOOST_CHECK_EQUAL(balance_proof.leaf_count, static_cast<uint32_t>(balances.size()));
    BOOST_CHECK(balance_proof.balance.asset_id == balances[1].asset_id);
    BOOST_CHECK_EQUAL(balance_proof.balance.balance, balances[1].balance);
    BOOST_CHECK(VerifyValiditySidechainBalanceProof(balance_proof, balance_root));

    ValiditySidechainBalanceProof tampered_balance_proof = balance_proof;
    tampered_balance_proof.balance.balance += 1;
    BOOST_CHECK(!VerifyValiditySidechainBalanceProof(tampered_balance_proof, balance_root));

    const std::vector<ValiditySidechainAccountStateLeaf> accounts{
        {
            uint256S("3333333333333333333333333333333333333333333333333333333333333333"),
            uint256S("3434343434343434343434343434343434343434343434343434343434343434"),
            balance_root,
            7,
            3,
        },
        {
            uint256S("3535353535353535353535353535353535353535353535353535353535353535"),
            uint256S("3636363636363636363636363636363636363636363636363636363636363636"),
            uint256S("3737373737373737373737373737373737373737373737373737373737373737"),
            9,
            4,
        },
    };
    const uint256 account_root = ComputeValiditySidechainAccountStateRoot(accounts);

    ValiditySidechainAccountStateProof account_proof;
    BOOST_REQUIRE(BuildValiditySidechainAccountStateProof(accounts, /* leaf_index= */ 0, account_proof));
    BOOST_CHECK_EQUAL(account_proof.leaf_index, 0U);
    BOOST_CHECK_EQUAL(account_proof.leaf_count, static_cast<uint32_t>(accounts.size()));
    BOOST_CHECK(account_proof.account.account_id == accounts[0].account_id);
    BOOST_CHECK(account_proof.account.balance_root == accounts[0].balance_root);
    BOOST_CHECK(VerifyValiditySidechainAccountStateProof(account_proof, account_root));

    ValiditySidechainAccountStateProof tampered_account_proof = account_proof;
    tampered_account_proof.account.account_nonce += 1;
    BOOST_CHECK(!VerifyValiditySidechainAccountStateProof(tampered_account_proof, account_root));
}

BOOST_AUTO_TEST_CASE(escape_exit_state_claim_key_and_id_binding)
{
    ValiditySidechainEscapeExitStateProof proof;
    proof.exit_asset_id = uint256S("3838383838383838383838383838383838383838383838383838383838383838");
    proof.amount = 4 * COIN;
    proof.destination_commitment = uint256S("3939393939393939393939393939393939393939393939393939393939393939");
    proof.account_proof.account.account_id = uint256S("3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a");
    proof.account_proof.account.spend_key_commitment = uint256S("3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b");
    proof.account_proof.account.balance_root = uint256S("3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c");
    proof.account_proof.account.account_nonce = 11;
    proof.account_proof.account.last_forced_exit_nonce = 6;
    proof.account_proof.leaf_index = 0;
    proof.account_proof.leaf_count = 1;
    proof.balance_proof.balance.asset_id = proof.exit_asset_id;
    proof.balance_proof.balance.balance = 9 * COIN;
    proof.balance_proof.leaf_index = 0;
    proof.balance_proof.leaf_count = 1;
    proof.required_account_nonce = proof.account_proof.account.account_nonce;
    proof.required_last_forced_exit_nonce = proof.account_proof.account.last_forced_exit_nonce;

    const uint8_t sidechain_id = 44;
    const uint256 claim_key = ComputeValiditySidechainEscapeExitStateClaimKey(sidechain_id, proof);
    const uint256 exit_id = ComputeValiditySidechainEscapeExitStateId(sidechain_id, proof);

    ValiditySidechainEscapeExitStateProof amount_variant = proof;
    amount_variant.amount += COIN;
    BOOST_CHECK(ComputeValiditySidechainEscapeExitStateClaimKey(sidechain_id, amount_variant) == claim_key);
    BOOST_CHECK(ComputeValiditySidechainEscapeExitStateId(sidechain_id, amount_variant) != exit_id);

    ValiditySidechainEscapeExitStateProof destination_variant = proof;
    destination_variant.destination_commitment = uint256S("3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d");
    BOOST_CHECK(ComputeValiditySidechainEscapeExitStateClaimKey(sidechain_id, destination_variant) == claim_key);
    BOOST_CHECK(ComputeValiditySidechainEscapeExitStateId(sidechain_id, destination_variant) != exit_id);

    ValiditySidechainEscapeExitStateProof nonce_variant = proof;
    nonce_variant.required_account_nonce += 1;
    BOOST_CHECK(ComputeValiditySidechainEscapeExitStateClaimKey(sidechain_id, nonce_variant) != claim_key);
    BOOST_CHECK(ComputeValiditySidechainEscapeExitStateId(sidechain_id, nonce_variant) != exit_id);

    BOOST_CHECK(ComputeValiditySidechainEscapeExitStateClaimKey(sidechain_id + 1, proof) != claim_key);
    BOOST_CHECK(ComputeValiditySidechainEscapeExitStateId(sidechain_id + 1, proof) != exit_id);
}

BOOST_AUTO_TEST_CASE(escape_exit_state_proof_rejects_bad_length_prefix)
{
    ValiditySidechainEscapeExitStateProof proof;
    proof.exit_id = uint256S("2020202020202020202020202020202020202020202020202020202020202020");
    proof.exit_asset_id = uint256S("2121212121212121212121212121212121212121212121212121212121212121");
    proof.amount = 1 * COIN;
    proof.destination_commitment = uint256S("2222222222222222222222222222222222222222222222222222222222222222");
    proof.account_proof.account.account_id = uint256S("2323232323232323232323232323232323232323232323232323232323232323");
    proof.account_proof.account.spend_key_commitment = uint256S("2424242424242424242424242424242424242424242424242424242424242424");
    proof.account_proof.account.balance_root = uint256S("2525252525252525252525252525252525252525252525252525252525252525");
    proof.account_proof.account.account_nonce = 1;
    proof.account_proof.account.last_forced_exit_nonce = 0;
    proof.account_proof.leaf_index = 0;
    proof.account_proof.leaf_count = 1;
    proof.balance_proof.balance.asset_id = uint256S("2626262626262626262626262626262626262626262626262626262626262626");
    proof.balance_proof.balance.balance = 1 * COIN;
    proof.balance_proof.leaf_index = 0;
    proof.balance_proof.leaf_count = 1;

    std::vector<unsigned char> encoded = EncodeValiditySidechainEscapeExitStateProof(proof);
    BOOST_REQUIRE(encoded.size() >= 124U);
    encoded[120] ^= 0x01;

    ValiditySidechainEscapeExitStateProof decoded;
    BOOST_CHECK(!DecodeValiditySidechainEscapeExitStateProof(encoded, decoded));
}

BOOST_AUTO_TEST_CASE(withdrawal_proof_decode_rejects_oversized_merkle_depth)
{
    ValiditySidechainWithdrawalProof proof;
    proof.withdrawal.withdrawal_id = uint256S("2727272727272727272727272727272727272727272727272727272727272727");
    proof.withdrawal.amount = COIN;
    proof.withdrawal.destination_commitment = uint256S("2828282828282828282828282828282828282828282828282828282828282828");
    proof.leaf_index = 0;
    proof.leaf_count = 1;
    proof.sibling_hashes.assign(33, uint256S("2929292929292929292929292929292929292929292929292929292929292929"));

    const std::vector<unsigned char> encoded = EncodeValiditySidechainWithdrawalProof(proof);

    ValiditySidechainWithdrawalProof decoded;
    BOOST_CHECK(!DecodeValiditySidechainWithdrawalProof(encoded, decoded));
}

BOOST_AUTO_TEST_CASE(escape_exit_state_proof_rejects_oversized_merkle_depth)
{
    ValiditySidechainEscapeExitStateProof proof;
    proof.exit_id = uint256S("2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a");
    proof.exit_asset_id = uint256S("2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
    proof.amount = COIN;
    proof.destination_commitment = uint256S("2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c");
    proof.account_proof.account.account_id = uint256S("2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d");
    proof.account_proof.account.spend_key_commitment = uint256S("2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e");
    proof.account_proof.account.balance_root = uint256S("2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f");
    proof.account_proof.account.account_nonce = 1;
    proof.account_proof.account.last_forced_exit_nonce = 0;
    proof.account_proof.leaf_index = 0;
    proof.account_proof.leaf_count = 1;
    proof.account_proof.sibling_hashes.assign(33, uint256S("3030303030303030303030303030303030303030303030303030303030303030"));
    proof.balance_proof.balance.asset_id = uint256S("3131313131313131313131313131313131313131313131313131313131313131");
    proof.balance_proof.balance.balance = COIN;
    proof.balance_proof.leaf_index = 0;
    proof.balance_proof.leaf_count = 1;

    const std::vector<unsigned char> encoded = EncodeValiditySidechainEscapeExitStateProof(proof);

    ValiditySidechainEscapeExitStateProof decoded;
    BOOST_CHECK(!DecodeValiditySidechainEscapeExitStateProof(encoded, decoded));
}

BOOST_AUTO_TEST_CASE(withdrawal_leaf_validator_rejects_duplicate_ids)
{
    const std::vector<ValiditySidechainWithdrawalLeaf> withdrawals{
        {
            uint256S("2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f"),
            COIN,
            uint256S("3030303030303030303030303030303030303030303030303030303030303030"),
        },
        {
            uint256S("2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f"),
            2 * COIN,
            uint256S("3131313131313131313131313131313131313131313131313131313131313131"),
        },
    };

    std::string error;
    BOOST_CHECK(!ValidateValiditySidechainWithdrawalLeafIds(withdrawals, &error));
    BOOST_CHECK_EQUAL(error, "duplicate withdrawal_id in withdrawal witness set");
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
    script << OP_RETURN << OP_SIDECHAIN << std::vector<unsigned char>{1} << payload << std::vector<unsigned char>{0x05};

    ValiditySidechainScriptInfo info;
    BOOST_CHECK(!DecodeValiditySidechainScript(script, info));
}

BOOST_AUTO_TEST_CASE(execute_metadata_rejects_fanout_above_consensus_limit)
{
    ValiditySidechainScriptInfo info;
    info.kind = ValiditySidechainScriptInfo::Kind::EXECUTE_VERIFIED_WITHDRAWALS;
    info.metadata_pushes.resize(MAX_VALIDITY_SIDECHAIN_EXECUTION_FANOUT + 1);

    std::vector<ValiditySidechainWithdrawalProof> decoded;
    BOOST_CHECK(!DecodeValiditySidechainExecuteMetadata(info, decoded));
}

BOOST_AUTO_TEST_CASE(escape_exit_metadata_rejects_fanout_above_consensus_limit)
{
    ValiditySidechainScriptInfo info;
    info.kind = ValiditySidechainScriptInfo::Kind::EXECUTE_ESCAPE_EXIT;
    info.metadata_pushes.resize(MAX_VALIDITY_SIDECHAIN_EXECUTION_FANOUT + 1);

    std::vector<ValiditySidechainEscapeExitProof> decoded;
    BOOST_CHECK(!DecodeValiditySidechainEscapeExitMetadata(info, decoded));
}

BOOST_AUTO_TEST_SUITE_END()
