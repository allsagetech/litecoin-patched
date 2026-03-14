// Copyright (c) 2026 AllSageTech, LLC
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/setup_common.h>
#include <validitysidechain/groth16.h>

extern "C" {
#include <blst.h>
}

#include <boost/test/unit_test.hpp>

#include <array>
#include <vector>

namespace {

std::array<unsigned char, 48> CompressedG1Generator()
{
    std::array<unsigned char, 48> out{};
    blst_p1_affine_compress(out.data(), blst_p1_affine_generator());
    return out;
}

std::array<unsigned char, 96> CompressedG2Generator()
{
    std::array<unsigned char, 96> out{};
    blst_p2_affine_compress(out.data(), blst_p2_affine_generator());
    return out;
}

ValiditySidechainGroth16Proof MakeProof()
{
    ValiditySidechainGroth16Proof proof;
    proof.a_g1 = CompressedG1Generator();
    proof.b_g2 = CompressedG2Generator();
    proof.c_g1 = CompressedG1Generator();
    return proof;
}

ValiditySidechainGroth16VerificationKey MakeVerificationKey(uint32_t public_input_count)
{
    ValiditySidechainGroth16VerificationKey verifying_key;
    verifying_key.public_input_count = public_input_count;
    verifying_key.alpha_g1 = CompressedG1Generator();
    verifying_key.beta_g2 = CompressedG2Generator();
    verifying_key.gamma_g2 = CompressedG2Generator();
    verifying_key.delta_g2 = CompressedG2Generator();
    verifying_key.gamma_abc_g1.resize(public_input_count + 1, CompressedG1Generator());
    return verifying_key;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(validitysidechain_groth16_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(groth16_proof_roundtrip_parses)
{
    const ValiditySidechainGroth16Proof proof = MakeProof();
    const std::vector<unsigned char> encoded = EncodeValiditySidechainGroth16Proof(proof);

    ValiditySidechainGroth16Proof parsed;
    std::string error;
    BOOST_REQUIRE(ParseValiditySidechainGroth16Proof(encoded, parsed, &error));
    BOOST_CHECK(error.empty());
    BOOST_CHECK(parsed.a_g1 == proof.a_g1);
    BOOST_CHECK(parsed.b_g2 == proof.b_g2);
    BOOST_CHECK(parsed.c_g1 == proof.c_g1);
}

BOOST_AUTO_TEST_CASE(groth16_proof_rejects_invalid_magic)
{
    std::vector<unsigned char> encoded = EncodeValiditySidechainGroth16Proof(MakeProof());
    encoded[0] ^= 0x01;

    ValiditySidechainGroth16Proof parsed;
    std::string error;
    BOOST_CHECK(!ParseValiditySidechainGroth16Proof(encoded, parsed, &error));
    BOOST_CHECK_EQUAL(error, "Groth16 proof bytes have invalid magic");
}

BOOST_AUTO_TEST_CASE(groth16_verifying_key_roundtrip_parses)
{
    const ValiditySidechainGroth16VerificationKey verifying_key = MakeVerificationKey(/* public_input_count= */ 11);
    const std::vector<unsigned char> encoded = EncodeValiditySidechainGroth16VerificationKey(verifying_key);

    ValiditySidechainGroth16VerificationKey parsed;
    std::string error;
    BOOST_REQUIRE(ParseValiditySidechainGroth16VerificationKey(encoded, 11, parsed, &error));
    BOOST_CHECK(error.empty());
    BOOST_CHECK_EQUAL(parsed.public_input_count, 11U);
    BOOST_CHECK_EQUAL(parsed.gamma_abc_g1.size(), 12U);
    BOOST_CHECK(parsed.alpha_g1 == verifying_key.alpha_g1);
    BOOST_CHECK(parsed.beta_g2 == verifying_key.beta_g2);
}

BOOST_AUTO_TEST_CASE(groth16_verifying_key_rejects_wrong_public_input_count)
{
    const std::vector<unsigned char> encoded =
        EncodeValiditySidechainGroth16VerificationKey(MakeVerificationKey(/* public_input_count= */ 10));

    ValiditySidechainGroth16VerificationKey parsed;
    std::string error;
    BOOST_CHECK(!ParseValiditySidechainGroth16VerificationKey(encoded, 11, parsed, &error));
    BOOST_CHECK_EQUAL(error, "Groth16 verifying key public-input count does not match supported profile");
}

BOOST_AUTO_TEST_CASE(groth16_verifying_key_rejects_truncated_bytes)
{
    std::vector<unsigned char> encoded =
        EncodeValiditySidechainGroth16VerificationKey(MakeVerificationKey(/* public_input_count= */ 11));
    encoded.pop_back();

    ValiditySidechainGroth16VerificationKey parsed;
    std::string error;
    BOOST_CHECK(!ParseValiditySidechainGroth16VerificationKey(encoded, 11, parsed, &error));
    BOOST_CHECK_EQUAL(error, "Groth16 verifying key bytes have unexpected length");
}

BOOST_AUTO_TEST_SUITE_END()
