// Copyright (c) 2026 AllSageTech, LLC
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <validitysidechain/groth16.h>

#include <univalue.h>

extern "C" {
#include <blst.h>
}

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>
#include <fstream>
#include <sstream>
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

std::array<unsigned char, 48> CompressedG1Multiple(uint64_t scalar_value)
{
    uint64_t scalar_words[4]{scalar_value, 0, 0, 0};
    blst_scalar scalar;
    blst_scalar_from_uint64(&scalar, scalar_words);

    blst_p1 generator;
    blst_p1_from_affine(&generator, blst_p1_affine_generator());
    blst_p1 point;
    blst_p1_mult(&point, &generator, scalar.b, 255);

    blst_p1_affine point_affine;
    blst_p1_to_affine(&point_affine, &point);

    std::array<unsigned char, 48> out{};
    blst_p1_affine_compress(out.data(), &point_affine);
    return out;
}

std::array<unsigned char, 96> CompressedG2Multiple(uint64_t scalar_value)
{
    uint64_t scalar_words[4]{scalar_value, 0, 0, 0};
    blst_scalar scalar;
    blst_scalar_from_uint64(&scalar, scalar_words);

    blst_p2 generator;
    blst_p2_from_affine(&generator, blst_p2_affine_generator());
    blst_p2 point;
    blst_p2_mult(&point, &generator, scalar.b, 255);

    blst_p2_affine point_affine;
    blst_p2_to_affine(&point_affine, &point);

    std::array<unsigned char, 96> out{};
    blst_p2_affine_compress(out.data(), &point_affine);
    return out;
}

std::array<unsigned char, 32> ScalarLE(uint64_t value)
{
    std::array<unsigned char, 32> out{};
    out[0] = static_cast<unsigned char>(value & 0xff);
    out[1] = static_cast<unsigned char>((value >> 8) & 0xff);
    out[2] = static_cast<unsigned char>((value >> 16) & 0xff);
    out[3] = static_cast<unsigned char>((value >> 24) & 0xff);
    out[4] = static_cast<unsigned char>((value >> 32) & 0xff);
    out[5] = static_cast<unsigned char>((value >> 40) & 0xff);
    out[6] = static_cast<unsigned char>((value >> 48) & 0xff);
    out[7] = static_cast<unsigned char>((value >> 56) & 0xff);
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

ValiditySidechainGroth16VerificationKey MakeSyntheticValidVerificationKey()
{
    ValiditySidechainGroth16VerificationKey verifying_key;
    verifying_key.public_input_count = 2;
    verifying_key.alpha_g1 = CompressedG1Multiple(1);
    verifying_key.beta_g2 = CompressedG2Multiple(1);
    verifying_key.gamma_g2 = CompressedG2Multiple(1);
    verifying_key.delta_g2 = CompressedG2Multiple(1);
    verifying_key.gamma_abc_g1 = {
        CompressedG1Multiple(5),
        CompressedG1Multiple(7),
        CompressedG1Multiple(11),
    };
    return verifying_key;
}

ValiditySidechainGroth16Proof MakeSyntheticValidProof()
{
    ValiditySidechainGroth16Proof proof;
    proof.a_g1 = CompressedG1Multiple(8);
    proof.b_g2 = CompressedG2Multiple(10);
    proof.c_g1 = CompressedG1Multiple(9);
    return proof;
}

ValiditySidechainGroth16VerificationKey MakeSyntheticZeroInputVerificationKey()
{
    ValiditySidechainGroth16VerificationKey verifying_key;
    verifying_key.public_input_count = 2;
    verifying_key.alpha_g1 = CompressedG1Multiple(1);
    verifying_key.beta_g2 = CompressedG2Multiple(1);
    verifying_key.gamma_g2 = CompressedG2Multiple(1);
    verifying_key.delta_g2 = CompressedG2Multiple(1);
    verifying_key.gamma_abc_g1 = {
        CompressedG1Multiple(70),
        CompressedG1Multiple(0),
        CompressedG1Multiple(0),
    };
    return verifying_key;
}

fs::path FindRepoPath(const fs::path& relative)
{
    std::vector<fs::path> roots;
    roots.push_back(fs::current_path());

    fs::path source_path{__FILE__};
    if (source_path.is_relative()) {
        source_path = fs::current_path() / source_path;
    }
    roots.push_back(source_path.parent_path());

    for (fs::path root : roots) {
        for (;;) {
            const fs::path candidate = root / relative;
            if (fs::exists(candidate)) {
                return candidate;
            }
            if (!root.has_parent_path() || root.parent_path() == root) {
                break;
            }
            root = root.parent_path();
        }
    }

    BOOST_FAIL("failed to locate repo path " + relative.string());
    return {};
}

std::string ReadTextFile(const fs::path& path)
{
    std::ifstream file(path);
    BOOST_REQUIRE_MESSAGE(file.is_open(), "failed to open " + path.string());
    std::ostringstream contents;
    contents << file.rdbuf();
    return contents.str();
}

UniValue ReadJSONFile(const fs::path& path)
{
    UniValue json;
    BOOST_REQUIRE_MESSAGE(json.read(ReadTextFile(path)), "failed to parse JSON " + path.string());
    return json;
}

std::array<unsigned char, 32> ScalarLEFromUint(uint64_t value)
{
    return ScalarLE(value);
}

std::array<unsigned char, 32> ScalarLEFromHex(const std::string& value)
{
    std::string normalized = value;
    if (normalized.empty()) {
        normalized = "0";
    }
    while (normalized.size() < 64) {
        normalized = "0" + normalized;
    }

    const uint256 parsed = uint256S(normalized);
    std::array<unsigned char, 32> out{};
    std::copy(parsed.begin(), parsed.end(), out.begin());
    return out;
}

uint64_t ParseUintString(const UniValue& value)
{
    const std::string raw = value.get_str();
    uint64_t parsed{0};
    BOOST_REQUIRE_MESSAGE(ParseUInt64(raw, &parsed), "failed to parse uint64 from " + raw);
    return parsed;
}

std::vector<std::array<unsigned char, 32>> BuildRealProfilePublicInputs(const UniValue& public_inputs)
{
    std::vector<std::array<unsigned char, 32>> encoded;
    encoded.reserve(11);
    encoded.push_back(ScalarLEFromUint(ParseUintString(find_value(public_inputs, "sidechain_id"))));
    encoded.push_back(ScalarLEFromUint(ParseUintString(find_value(public_inputs, "batch_number"))));
    encoded.push_back(ScalarLEFromHex(find_value(public_inputs, "prior_state_root").get_str()));
    encoded.push_back(ScalarLEFromHex(find_value(public_inputs, "new_state_root").get_str()));
    encoded.push_back(ScalarLEFromHex(find_value(public_inputs, "l1_message_root_before").get_str()));
    encoded.push_back(ScalarLEFromHex(find_value(public_inputs, "l1_message_root_after").get_str()));
    encoded.push_back(ScalarLEFromUint(ParseUintString(find_value(public_inputs, "consumed_queue_messages"))));
    encoded.push_back(ScalarLEFromHex(find_value(public_inputs, "queue_prefix_commitment").get_str()));
    encoded.push_back(ScalarLEFromHex(find_value(public_inputs, "withdrawal_root").get_str()));
    encoded.push_back(ScalarLEFromHex(find_value(public_inputs, "data_root").get_str()));
    encoded.push_back(ScalarLEFromUint(ParseUintString(find_value(public_inputs, "data_size"))));
    return encoded;
}

ValiditySidechainGroth16Proof ParseProofFromVector(const UniValue& vector_json)
{
    ValiditySidechainGroth16Proof proof;
    std::string error;
    const std::vector<unsigned char> proof_bytes = ParseHex(find_value(vector_json, "proof_bytes_hex").get_str());
    BOOST_REQUIRE(ParseValiditySidechainGroth16Proof(proof_bytes, proof, &error));
    BOOST_CHECK(error.empty());
    return proof;
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

BOOST_AUTO_TEST_CASE(groth16_pairing_verifier_accepts_synthetic_valid_equation)
{
    const ValiditySidechainGroth16VerificationKey verifying_key = MakeSyntheticValidVerificationKey();
    const ValiditySidechainGroth16Proof proof = MakeSyntheticValidProof();
    const std::vector<std::array<unsigned char, 32>> public_inputs{
        ScalarLE(3),
        ScalarLE(4),
    };

    std::string error;
    BOOST_CHECK(VerifyValiditySidechainGroth16Proof(verifying_key, proof, public_inputs, &error));
    BOOST_CHECK(error.empty());
}

BOOST_AUTO_TEST_CASE(groth16_pairing_verifier_rejects_public_input_mismatch)
{
    const ValiditySidechainGroth16VerificationKey verifying_key = MakeSyntheticValidVerificationKey();
    const ValiditySidechainGroth16Proof proof = MakeSyntheticValidProof();
    const std::vector<std::array<unsigned char, 32>> public_inputs{
        ScalarLE(3),
        ScalarLE(5),
    };

    std::string error;
    BOOST_CHECK(!VerifyValiditySidechainGroth16Proof(verifying_key, proof, public_inputs, &error));
    BOOST_CHECK_EQUAL(error, "Groth16 pairing doesn't match");
}

BOOST_AUTO_TEST_CASE(groth16_pairing_verifier_rejects_scalar_outside_field)
{
    const ValiditySidechainGroth16VerificationKey verifying_key = MakeSyntheticValidVerificationKey();
    const ValiditySidechainGroth16Proof proof = MakeSyntheticValidProof();
    std::array<unsigned char, 32> oversized{};
    oversized.fill(0xff);
    const std::vector<std::array<unsigned char, 32>> public_inputs{
        ScalarLE(3),
        oversized,
    };

    std::string error;
    BOOST_CHECK(!VerifyValiditySidechainGroth16Proof(verifying_key, proof, public_inputs, &error));
    BOOST_CHECK_EQUAL(error, "Groth16 public input does not fit BLS12-381 scalar field");
}

BOOST_AUTO_TEST_CASE(groth16_pairing_verifier_accepts_zero_public_inputs)
{
    const ValiditySidechainGroth16VerificationKey verifying_key = MakeSyntheticZeroInputVerificationKey();
    const ValiditySidechainGroth16Proof proof = MakeSyntheticValidProof();
    const std::vector<std::array<unsigned char, 32>> public_inputs{
        ScalarLE(0),
        ScalarLE(0),
    };

    std::string error;
    BOOST_CHECK(VerifyValiditySidechainGroth16Proof(verifying_key, proof, public_inputs, &error));
    BOOST_CHECK(error.empty());
}

BOOST_AUTO_TEST_CASE(groth16_real_profile_bundle_accepts_committed_valid_vector)
{
    const fs::path artifact_dir =
        FindRepoPath(fs::path{"artifacts"} / "validitysidechain" / "groth16_bls12_381_poseidon_v1");

    ValiditySidechainGroth16VerificationKey verifying_key;
    std::string error;
    BOOST_REQUIRE(LoadValiditySidechainGroth16VerificationKey(
        artifact_dir / "batch_vk.bin",
        /* expected_public_input_count= */ 11,
        verifying_key,
        &error));
    BOOST_CHECK(error.empty());
    BOOST_CHECK_EQUAL(verifying_key.public_input_count, 11U);

    const UniValue valid_vector = ReadJSONFile(artifact_dir / "valid" / "valid_proof.json");
    const auto public_inputs = BuildRealProfilePublicInputs(find_value(valid_vector, "public_inputs"));
    const ValiditySidechainGroth16Proof proof = ParseProofFromVector(valid_vector);

    BOOST_CHECK(VerifyValiditySidechainGroth16Proof(verifying_key, proof, public_inputs, &error));
    BOOST_CHECK(error.empty());
}

BOOST_AUTO_TEST_CASE(groth16_real_profile_bundle_rejects_committed_invalid_vectors)
{
    const fs::path artifact_dir =
        FindRepoPath(fs::path{"artifacts"} / "validitysidechain" / "groth16_bls12_381_poseidon_v1");

    ValiditySidechainGroth16VerificationKey verifying_key;
    std::string error;
    BOOST_REQUIRE(LoadValiditySidechainGroth16VerificationKey(
        artifact_dir / "batch_vk.bin",
        /* expected_public_input_count= */ 11,
        verifying_key,
        &error));
    BOOST_CHECK(error.empty());

    for (const char* path : {
             "invalid/public_input_mismatch.json",
             "invalid/queue_prefix_commitment_mismatch.json",
             "invalid/withdrawal_root_mismatch.json",
         }) {
        const UniValue vector_json = ReadJSONFile(artifact_dir / path);
        const auto public_inputs = BuildRealProfilePublicInputs(find_value(vector_json, "public_inputs"));
        const ValiditySidechainGroth16Proof proof = ParseProofFromVector(vector_json);

        BOOST_CHECK(!VerifyValiditySidechainGroth16Proof(verifying_key, proof, public_inputs, &error));
        BOOST_CHECK_EQUAL(error, "Groth16 pairing doesn't match");
    }

    const UniValue corrupt_vector = ReadJSONFile(artifact_dir / "invalid" / "corrupt_proof.json");
    const std::vector<unsigned char> corrupt_bytes = ParseHex(find_value(corrupt_vector, "proof_bytes_hex").get_str());
    ValiditySidechainGroth16Proof corrupt_proof;
    const bool parsed = ParseValiditySidechainGroth16Proof(corrupt_bytes, corrupt_proof, &error);
    if (parsed) {
        const auto public_inputs = BuildRealProfilePublicInputs(find_value(corrupt_vector, "public_inputs"));
        BOOST_CHECK(!VerifyValiditySidechainGroth16Proof(verifying_key, corrupt_proof, public_inputs, &error));
        BOOST_CHECK(!error.empty());
    } else {
        BOOST_CHECK(!error.empty());
    }
}

BOOST_AUTO_TEST_SUITE_END()
