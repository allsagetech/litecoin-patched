// Copyright (c) 2026 AllSageTech, LLC
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/params.h>
#include <drivechain/script.h>
#include <drivechain/state.h>
#include <hash.h>
#include <key.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(drivechain_script_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(execute_script_roundtrip)
{
    const uint8_t sidechain_id = 7;
    const uint256 bundle_hash = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    const uint32_t n_withdrawals = 3;

    const CScript script = BuildDrivechainExecuteScript(sidechain_id, bundle_hash, n_withdrawals);
    DrivechainScriptInfo info;
    BOOST_REQUIRE(DecodeDrivechainScript(script, info));
    BOOST_CHECK(info.kind == DrivechainScriptInfo::Kind::EXECUTE);
    BOOST_CHECK_EQUAL(info.sidechain_id, sidechain_id);
    BOOST_CHECK(info.payload == bundle_hash);
    BOOST_CHECK_EQUAL(info.n_withdrawals, n_withdrawals);
}

BOOST_AUTO_TEST_CASE(execute_script_rejects_unknown_tag)
{
    std::vector<unsigned char> payload(32, 0x42);
    CScript script;
    script << OP_RETURN << OP_DRIVECHAIN << std::vector<unsigned char>{1} << payload << std::vector<unsigned char>{0x99};

    DrivechainScriptInfo info;
    BOOST_CHECK(!DecodeDrivechainScript(script, info));
}

BOOST_AUTO_TEST_CASE(bmm_request_roundtrip)
{
    const uint8_t sidechain_id = 4;
    const uint256 side_block_hash = uint256S("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    const uint256 prev_main_hash = uint256S("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

    const CScript script = BuildDrivechainBmmRequestScript(sidechain_id, side_block_hash, prev_main_hash);
    DrivechainBmmRequestInfo info;
    BOOST_REQUIRE(DecodeDrivechainBmmRequestScript(script, info));
    BOOST_CHECK_EQUAL(info.sidechain_id, sidechain_id);
    BOOST_CHECK(info.side_block_hash == side_block_hash);
    BOOST_CHECK(info.prev_main_block_hash == prev_main_hash);
}

BOOST_AUTO_TEST_CASE(bmm_accept_roundtrip)
{
    const uint8_t sidechain_id = 12;
    const uint256 side_block_hash = uint256S("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");

    const CScript script = BuildDrivechainBmmAcceptScript(sidechain_id, side_block_hash);
    DrivechainBmmAcceptInfo info;
    BOOST_REQUIRE(DecodeDrivechainBmmAcceptScript(script, info));
    BOOST_CHECK_EQUAL(info.sidechain_id, sidechain_id);
    BOOST_CHECK(info.side_block_hash == side_block_hash);
}

BOOST_AUTO_TEST_CASE(bundle_schedule_boundaries)
{
    Consensus::Params params;
    params.nDrivechainVoteWindow = 20;
    params.nDrivechainFinalizationDelay = 20;
    params.vDeployments[Consensus::DEPLOYMENT_DRIVECHAIN].nStartHeight = 100;

    DrivechainBundleSchedule schedule;

    BOOST_REQUIRE(ComputeDrivechainBundleSchedule(params, 103, schedule));
    BOOST_CHECK_EQUAL(schedule.vote_start_height, 120);
    BOOST_CHECK_EQUAL(schedule.vote_end_height, 139);
    BOOST_CHECK_EQUAL(schedule.approval_height, 140);
    BOOST_CHECK_EQUAL(schedule.executable_height, 160);

    BOOST_REQUIRE(ComputeDrivechainBundleSchedule(params, 120, schedule));
    BOOST_CHECK_EQUAL(schedule.vote_start_height, 140);
    BOOST_CHECK_EQUAL(schedule.vote_end_height, 159);
    BOOST_CHECK_EQUAL(schedule.approval_height, 160);
    BOOST_CHECK_EQUAL(schedule.executable_height, 180);
}

BOOST_AUTO_TEST_CASE(bundle_schedule_invalid_inputs)
{
    Consensus::Params params;
    params.nDrivechainVoteWindow = 0;
    params.nDrivechainFinalizationDelay = 20;
    params.vDeployments[Consensus::DEPLOYMENT_DRIVECHAIN].nStartHeight = 100;

    DrivechainBundleSchedule schedule;
    BOOST_CHECK(!ComputeDrivechainBundleSchedule(params, 100, schedule));

    params.nDrivechainVoteWindow = 20;
    params.nDrivechainFinalizationDelay = 0;
    BOOST_CHECK(!ComputeDrivechainBundleSchedule(params, 100, schedule));

    params.nDrivechainFinalizationDelay = 20;
    BOOST_CHECK(!ComputeDrivechainBundleSchedule(params, -1, schedule));
}

BOOST_AUTO_TEST_CASE(bundle_commit_owner_auth_roundtrip)
{
    const uint8_t sidechain_id = 9;
    const uint256 bundle_hash = uint256S("9999999999999999999999999999999999999999999999999999999999999999");

    CKey owner_key;
    const std::vector<unsigned char> secret(32, 0x11);
    owner_key.Set(secret.begin(), secret.end(), true);
    BOOST_REQUIRE(owner_key.IsValid());

    const CPubKey owner_pubkey = owner_key.GetPubKey();
    const std::vector<unsigned char> owner_pubkey_bytes(owner_pubkey.begin(), owner_pubkey.end());
    const uint256 owner_key_hash = Hash(owner_pubkey_bytes);
    const DrivechainSidechainPolicy policy{
        /*auth_threshold=*/1,
        /*owner_key_hashes=*/{owner_key_hash},
        /*max_escrow_amount=*/100 * COIN,
        /*max_bundle_withdrawal=*/25 * COIN,
    };

    const uint256 auth_msg = ComputeDrivechainBundleAuthMessage(sidechain_id, bundle_hash);
    std::vector<unsigned char> auth_sig;
    BOOST_REQUIRE(owner_key.SignCompact(auth_msg, auth_sig));

    const std::vector<unsigned char> sidechain_v{sidechain_id};
    const std::vector<unsigned char> payload(bundle_hash.begin(), bundle_hash.end());
    const std::vector<unsigned char> tag{0x01};

    CScript script;
    script << OP_RETURN << OP_DRIVECHAIN << sidechain_v << payload << tag << auth_sig;

    DrivechainScriptInfo info;
    BOOST_REQUIRE(DecodeDrivechainScript(script, info));
    BOOST_CHECK(info.kind == DrivechainScriptInfo::Kind::BUNDLE_COMMIT);
    BOOST_CHECK_EQUAL(info.sidechain_id, sidechain_id);
    BOOST_CHECK(info.payload == bundle_hash);
    BOOST_CHECK(info.auth_sig == auth_sig);
    BOOST_REQUIRE_EQUAL(info.auth_sigs.size(), 1U);
    BOOST_CHECK(VerifyDrivechainBundleAuthSigs(policy, sidechain_id, bundle_hash, info.auth_sigs));
    BOOST_CHECK(!VerifyDrivechainBundleAuthSigs(policy, sidechain_id + 1, bundle_hash, info.auth_sigs));
}

BOOST_AUTO_TEST_CASE(register_owner_auth_roundtrip)
{
    const uint8_t sidechain_id = 13;

    CKey owner_key;
    const std::vector<unsigned char> secret(32, 0x22);
    owner_key.Set(secret.begin(), secret.end(), true);
    BOOST_REQUIRE(owner_key.IsValid());

    const CPubKey owner_pubkey = owner_key.GetPubKey();
    const std::vector<unsigned char> owner_pubkey_bytes(owner_pubkey.begin(), owner_pubkey.end());
    const uint256 owner_key_hash = Hash(owner_pubkey_bytes);
    const DrivechainSidechainPolicy policy{
        /*auth_threshold=*/1,
        /*owner_key_hashes=*/{owner_key_hash},
        /*max_escrow_amount=*/250 * COIN,
        /*max_bundle_withdrawal=*/40 * COIN,
    };
    const uint256 policy_hash = ComputeDrivechainSidechainPolicyHash(policy);

    const uint256 auth_msg = ComputeDrivechainRegisterAuthMessage(sidechain_id, policy_hash);
    std::vector<unsigned char> auth_sig;
    BOOST_REQUIRE(owner_key.SignCompact(auth_msg, auth_sig));

    const std::vector<unsigned char> sidechain_v{sidechain_id};
    const std::vector<unsigned char> payload(policy_hash.begin(), policy_hash.end());
    const std::vector<unsigned char> tag{0x05};
    const std::vector<unsigned char> encoded_policy = EncodeDrivechainSidechainPolicy(policy);

    CScript script;
    script << OP_RETURN << OP_DRIVECHAIN << sidechain_v << payload << tag << encoded_policy << auth_sig;

    DrivechainScriptInfo info;
    BOOST_REQUIRE(DecodeDrivechainScript(script, info));
    BOOST_CHECK(info.kind == DrivechainScriptInfo::Kind::REGISTER);
    BOOST_CHECK_EQUAL(info.sidechain_id, sidechain_id);
    BOOST_CHECK(info.payload == policy_hash);
    BOOST_CHECK(info.auth_sig == auth_sig);
    BOOST_REQUIRE_EQUAL(info.auth_sigs.size(), 1U);
    BOOST_CHECK_EQUAL(info.sidechain_policy.auth_threshold, policy.auth_threshold);
    BOOST_CHECK(info.sidechain_policy.owner_key_hashes == policy.owner_key_hashes);
    BOOST_CHECK_EQUAL(info.sidechain_policy.max_escrow_amount, policy.max_escrow_amount);
    BOOST_CHECK_EQUAL(info.sidechain_policy.max_bundle_withdrawal, policy.max_bundle_withdrawal);
    BOOST_CHECK(VerifyDrivechainRegisterAuthSigs(sidechain_id, info.sidechain_policy, info.auth_sigs));
    BOOST_CHECK(!VerifyDrivechainRegisterAuthSigs(sidechain_id + 1, info.sidechain_policy, info.auth_sigs));
}

BOOST_AUTO_TEST_CASE(sidechain_policy_roundtrip_rejects_unsorted_keys)
{
    DrivechainSidechainPolicy policy;
    policy.auth_threshold = 2;
    policy.max_escrow_amount = 100 * COIN;
    policy.max_bundle_withdrawal = 25 * COIN;
    policy.owner_key_hashes = {
        uint256S("1111111111111111111111111111111111111111111111111111111111111111"),
        uint256S("2222222222222222222222222222222222222222222222222222222222222222"),
    };

    const std::vector<unsigned char> encoded = EncodeDrivechainSidechainPolicy(policy);
    DrivechainSidechainPolicy decoded_policy;
    BOOST_REQUIRE(DecodeDrivechainSidechainPolicy(encoded, decoded_policy));
    BOOST_CHECK(decoded_policy.owner_key_hashes == policy.owner_key_hashes);

    std::swap(policy.owner_key_hashes[0], policy.owner_key_hashes[1]);
    BOOST_CHECK(!DecodeDrivechainSidechainPolicy(EncodeDrivechainSidechainPolicy(policy), decoded_policy));
}

BOOST_AUTO_TEST_CASE(threshold_bundle_auth_requires_distinct_keys)
{
    const uint8_t sidechain_id = 4;
    const uint256 bundle_hash = uint256S("abababababababababababababababababababababababababababababababab");

    CKey owner_key_a;
    const std::vector<unsigned char> secret_a(32, 0x31);
    owner_key_a.Set(secret_a.begin(), secret_a.end(), true);
    BOOST_REQUIRE(owner_key_a.IsValid());

    CKey owner_key_b;
    const std::vector<unsigned char> secret_b(32, 0x41);
    owner_key_b.Set(secret_b.begin(), secret_b.end(), true);
    BOOST_REQUIRE(owner_key_b.IsValid());

    const CPubKey owner_pubkey_a = owner_key_a.GetPubKey();
    const CPubKey owner_pubkey_b = owner_key_b.GetPubKey();
    const uint256 owner_key_hash_a = Hash(std::vector<unsigned char>(owner_pubkey_a.begin(), owner_pubkey_a.end()));
    const uint256 owner_key_hash_b = Hash(std::vector<unsigned char>(owner_pubkey_b.begin(), owner_pubkey_b.end()));

    DrivechainSidechainPolicy policy;
    policy.auth_threshold = 2;
    policy.owner_key_hashes = {std::min(owner_key_hash_a, owner_key_hash_b), std::max(owner_key_hash_a, owner_key_hash_b)};
    policy.max_escrow_amount = 100 * COIN;
    policy.max_bundle_withdrawal = 30 * COIN;

    const uint256 auth_msg = ComputeDrivechainBundleAuthMessage(sidechain_id, bundle_hash);
    std::vector<unsigned char> auth_sig_a;
    std::vector<unsigned char> auth_sig_b;
    BOOST_REQUIRE(owner_key_a.SignCompact(auth_msg, auth_sig_a));
    BOOST_REQUIRE(owner_key_b.SignCompact(auth_msg, auth_sig_b));

    BOOST_CHECK(!VerifyDrivechainBundleAuthSigs(policy, sidechain_id, bundle_hash, {auth_sig_a, auth_sig_a}));
    BOOST_CHECK(VerifyDrivechainBundleAuthSigs(policy, sidechain_id, bundle_hash, {auth_sig_a, auth_sig_b}));
}

BOOST_AUTO_TEST_SUITE_END()
