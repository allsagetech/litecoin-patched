// Copyright (c) 2026 AllSageTech, LLC
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <validitysidechain/groth16.h>

extern "C" {
#include <blst.h>
}

#include <fs.h>

#include <algorithm>
#include <ios>
#include <iterator>

namespace {

static constexpr unsigned char GROTH16_PROOF_MAGIC[] = {'V', 'S', 'G', 'P', 0x01};
static constexpr unsigned char GROTH16_VK_MAGIC[] = {'V', 'S', 'G', 'V', 'K', 0x01};
static constexpr size_t GROTH16_G1_COMPRESSED_BYTES = 48;
static constexpr size_t GROTH16_G2_COMPRESSED_BYTES = 96;
static constexpr size_t GROTH16_SCALAR_BYTES = 32;
static constexpr size_t GROTH16_PROOF_ENCODED_BYTES =
    sizeof(GROTH16_PROOF_MAGIC) + GROTH16_G1_COMPRESSED_BYTES + GROTH16_G2_COMPRESSED_BYTES + GROTH16_G1_COMPRESSED_BYTES;
static constexpr size_t GROTH16_VK_HEADER_BYTES =
    sizeof(GROTH16_VK_MAGIC) + sizeof(uint32_t) + (GROTH16_G1_COMPRESSED_BYTES + (GROTH16_G2_COMPRESSED_BYTES * 3)) + sizeof(uint32_t);

static bool FailValidation(std::string* error, const char* message)
{
    if (error != nullptr) {
        *error = message;
    }
    return false;
}

static void AppendUint32LE(std::vector<unsigned char>& out, uint32_t value)
{
    out.push_back(static_cast<unsigned char>(value & 0xff));
    out.push_back(static_cast<unsigned char>((value >> 8) & 0xff));
    out.push_back(static_cast<unsigned char>((value >> 16) & 0xff));
    out.push_back(static_cast<unsigned char>((value >> 24) & 0xff));
}

static bool ReadUint32LE(
    const std::vector<unsigned char>& bytes,
    size_t offset,
    uint32_t& out_value)
{
    if (offset > bytes.size() || bytes.size() - offset < sizeof(uint32_t)) {
        return false;
    }
    out_value =
        static_cast<uint32_t>(bytes[offset]) |
        (static_cast<uint32_t>(bytes[offset + 1]) << 8) |
        (static_cast<uint32_t>(bytes[offset + 2]) << 16) |
        (static_cast<uint32_t>(bytes[offset + 3]) << 24);
    return true;
}

static bool ValidateCompressedG1(
    const std::array<unsigned char, GROTH16_G1_COMPRESSED_BYTES>& point_bytes,
    std::string* error)
{
    blst_p1_affine point;
    const BLST_ERROR result = blst_p1_uncompress(&point, point_bytes.data());
    if (result != BLST_SUCCESS || !blst_p1_affine_in_g1(&point) || blst_p1_affine_is_inf(&point)) {
        return FailValidation(error, "Groth16 proof artifact contains invalid G1 encoding");
    }
    return true;
}

static bool UncompressG1(
    const std::array<unsigned char, GROTH16_G1_COMPRESSED_BYTES>& point_bytes,
    blst_p1_affine& out_point,
    std::string* error)
{
    const BLST_ERROR result = blst_p1_uncompress(&out_point, point_bytes.data());
    if (result != BLST_SUCCESS || !blst_p1_affine_in_g1(&out_point) || blst_p1_affine_is_inf(&out_point)) {
        return FailValidation(error, "Groth16 proof artifact contains invalid G1 encoding");
    }
    return true;
}

static bool ValidateCompressedG2(
    const std::array<unsigned char, GROTH16_G2_COMPRESSED_BYTES>& point_bytes,
    std::string* error)
{
    blst_p2_affine point;
    const BLST_ERROR result = blst_p2_uncompress(&point, point_bytes.data());
    if (result != BLST_SUCCESS || !blst_p2_affine_in_g2(&point) || blst_p2_affine_is_inf(&point)) {
        return FailValidation(error, "Groth16 proof artifact contains invalid G2 encoding");
    }
    return true;
}

static bool UncompressG2(
    const std::array<unsigned char, GROTH16_G2_COMPRESSED_BYTES>& point_bytes,
    blst_p2_affine& out_point,
    std::string* error)
{
    const BLST_ERROR result = blst_p2_uncompress(&out_point, point_bytes.data());
    if (result != BLST_SUCCESS || !blst_p2_affine_in_g2(&out_point) || blst_p2_affine_is_inf(&out_point)) {
        return FailValidation(error, "Groth16 proof artifact contains invalid G2 encoding");
    }
    return true;
}

static bool ParseScalarLE(
    const std::array<unsigned char, GROTH16_SCALAR_BYTES>& scalar_bytes,
    blst_scalar& out_scalar,
    std::string* error)
{
    // Load the raw scalar bytes without modular reduction; fr_check enforces
    // the canonical BLS12-381 scalar-field range, including zero.
    blst_scalar_from_lendian(&out_scalar, scalar_bytes.data());
    if (!blst_scalar_fr_check(&out_scalar)) {
        return FailValidation(error, "Groth16 public input does not fit BLS12-381 scalar field");
    }
    return true;
}

static bool IsZeroScalarLE(const std::array<unsigned char, GROTH16_SCALAR_BYTES>& scalar_bytes)
{
    return std::all_of(
        scalar_bytes.begin(),
        scalar_bytes.end(),
        [](unsigned char byte) { return byte == 0; });
}

static void ComputeSafeMillerLoop(
    blst_fp12& out_result,
    const blst_p2_affine& q,
    const blst_p1_affine& p)
{
    if (blst_p2_affine_is_inf(&q) || blst_p1_affine_is_inf(&p)) {
        out_result = *blst_fp12_one();
        return;
    }
    blst_miller_loop(&out_result, &q, &p);
}

static bool ComputeGammaABCCombination(
    const ValiditySidechainGroth16VerificationKey& verifying_key,
    const std::vector<std::array<unsigned char, GROTH16_SCALAR_BYTES>>& public_inputs_le,
    blst_p1_affine& out_point,
    std::string* error)
{
    if (public_inputs_le.size() != verifying_key.public_input_count) {
        return FailValidation(error, "Groth16 public-input count does not match verifying key");
    }
    if (verifying_key.gamma_abc_g1.size() != public_inputs_le.size() + 1) {
        return FailValidation(error, "Groth16 verifying key gamma_abc layout is inconsistent");
    }

    blst_p1_affine gamma_abc_0_affine;
    if (!UncompressG1(verifying_key.gamma_abc_g1.front(), gamma_abc_0_affine, error)) {
        return false;
    }

    blst_p1 accumulator;
    bool have_accumulator = !blst_p1_affine_is_inf(&gamma_abc_0_affine);
    if (have_accumulator) {
        blst_p1_from_affine(&accumulator, &gamma_abc_0_affine);
    }

    for (size_t i = 0; i < public_inputs_le.size(); ++i) {
        blst_scalar scalar;
        if (!ParseScalarLE(public_inputs_le[i], scalar, error)) {
            return false;
        }
        if (IsZeroScalarLE(public_inputs_le[i])) {
            continue;
        }

        blst_p1_affine gamma_abc_affine;
        if (!UncompressG1(verifying_key.gamma_abc_g1[i + 1], gamma_abc_affine, error)) {
            return false;
        }
        if (blst_p1_affine_is_inf(&gamma_abc_affine)) {
            continue;
        }

        blst_p1 gamma_abc;
        blst_p1_from_affine(&gamma_abc, &gamma_abc_affine);

        blst_p1 scaled_term;
        blst_p1_mult(&scaled_term, &gamma_abc, scalar.b, 255);
        if (!have_accumulator) {
            accumulator = scaled_term;
            have_accumulator = true;
            continue;
        }
        blst_p1_add_or_double(&accumulator, &accumulator, &scaled_term);
    }

    if (!have_accumulator) {
        out_point = blst_p1_affine{};
    } else {
        blst_p1_to_affine(&out_point, &accumulator);
    }
    if (!blst_p1_affine_in_g1(&out_point)) {
        return FailValidation(error, "Groth16 public-input linear combination left G1");
    }
    return true;
}

} // namespace

std::vector<unsigned char> EncodeValiditySidechainGroth16Proof(
    const ValiditySidechainGroth16Proof& proof)
{
    std::vector<unsigned char> out;
    out.insert(out.end(), std::begin(GROTH16_PROOF_MAGIC), std::end(GROTH16_PROOF_MAGIC));
    out.insert(out.end(), proof.a_g1.begin(), proof.a_g1.end());
    out.insert(out.end(), proof.b_g2.begin(), proof.b_g2.end());
    out.insert(out.end(), proof.c_g1.begin(), proof.c_g1.end());
    return out;
}

std::vector<unsigned char> EncodeValiditySidechainGroth16VerificationKey(
    const ValiditySidechainGroth16VerificationKey& verifying_key)
{
    std::vector<unsigned char> out;
    out.insert(out.end(), std::begin(GROTH16_VK_MAGIC), std::end(GROTH16_VK_MAGIC));
    AppendUint32LE(out, verifying_key.public_input_count);
    out.insert(out.end(), verifying_key.alpha_g1.begin(), verifying_key.alpha_g1.end());
    out.insert(out.end(), verifying_key.beta_g2.begin(), verifying_key.beta_g2.end());
    out.insert(out.end(), verifying_key.gamma_g2.begin(), verifying_key.gamma_g2.end());
    out.insert(out.end(), verifying_key.delta_g2.begin(), verifying_key.delta_g2.end());
    AppendUint32LE(out, static_cast<uint32_t>(verifying_key.gamma_abc_g1.size()));
    for (const auto& point : verifying_key.gamma_abc_g1) {
        out.insert(out.end(), point.begin(), point.end());
    }
    return out;
}

bool ParseValiditySidechainGroth16Proof(
    const std::vector<unsigned char>& proof_bytes,
    ValiditySidechainGroth16Proof& out_proof,
    std::string* error)
{
    if (proof_bytes.size() != GROTH16_PROOF_ENCODED_BYTES) {
        return FailValidation(error, "Groth16 proof bytes have unexpected length");
    }
    if (!std::equal(std::begin(GROTH16_PROOF_MAGIC), std::end(GROTH16_PROOF_MAGIC), proof_bytes.begin())) {
        return FailValidation(error, "Groth16 proof bytes have invalid magic");
    }

    ValiditySidechainGroth16Proof parsed;
    size_t offset = sizeof(GROTH16_PROOF_MAGIC);
    std::copy_n(proof_bytes.begin() + offset, GROTH16_G1_COMPRESSED_BYTES, parsed.a_g1.begin());
    offset += GROTH16_G1_COMPRESSED_BYTES;
    std::copy_n(proof_bytes.begin() + offset, GROTH16_G2_COMPRESSED_BYTES, parsed.b_g2.begin());
    offset += GROTH16_G2_COMPRESSED_BYTES;
    std::copy_n(proof_bytes.begin() + offset, GROTH16_G1_COMPRESSED_BYTES, parsed.c_g1.begin());

    if (!ValidateCompressedG1(parsed.a_g1, error) ||
        !ValidateCompressedG2(parsed.b_g2, error) ||
        !ValidateCompressedG1(parsed.c_g1, error)) {
        return false;
    }

    out_proof = parsed;
    return true;
}

bool ParseValiditySidechainGroth16VerificationKey(
    const std::vector<unsigned char>& key_bytes,
    uint32_t expected_public_input_count,
    ValiditySidechainGroth16VerificationKey& out_verifying_key,
    std::string* error)
{
    if (key_bytes.size() < GROTH16_VK_HEADER_BYTES) {
        return FailValidation(error, "Groth16 verifying key bytes are truncated");
    }
    if (!std::equal(std::begin(GROTH16_VK_MAGIC), std::end(GROTH16_VK_MAGIC), key_bytes.begin())) {
        return FailValidation(error, "Groth16 verifying key bytes have invalid magic");
    }

    size_t offset = sizeof(GROTH16_VK_MAGIC);
    ValiditySidechainGroth16VerificationKey parsed;
    if (!ReadUint32LE(key_bytes, offset, parsed.public_input_count)) {
        return FailValidation(error, "Groth16 verifying key missing public-input count");
    }
    offset += sizeof(uint32_t);
    if (parsed.public_input_count != expected_public_input_count) {
        return FailValidation(error, "Groth16 verifying key public-input count does not match supported profile");
    }

    std::copy_n(key_bytes.begin() + offset, GROTH16_G1_COMPRESSED_BYTES, parsed.alpha_g1.begin());
    offset += GROTH16_G1_COMPRESSED_BYTES;
    std::copy_n(key_bytes.begin() + offset, GROTH16_G2_COMPRESSED_BYTES, parsed.beta_g2.begin());
    offset += GROTH16_G2_COMPRESSED_BYTES;
    std::copy_n(key_bytes.begin() + offset, GROTH16_G2_COMPRESSED_BYTES, parsed.gamma_g2.begin());
    offset += GROTH16_G2_COMPRESSED_BYTES;
    std::copy_n(key_bytes.begin() + offset, GROTH16_G2_COMPRESSED_BYTES, parsed.delta_g2.begin());
    offset += GROTH16_G2_COMPRESSED_BYTES;

    uint32_t gamma_abc_count = 0;
    if (!ReadUint32LE(key_bytes, offset, gamma_abc_count)) {
        return FailValidation(error, "Groth16 verifying key missing gamma_abc count");
    }
    offset += sizeof(uint32_t);
    if (gamma_abc_count != expected_public_input_count + 1) {
        return FailValidation(error, "Groth16 verifying key gamma_abc count does not match supported profile");
    }

    const size_t expected_size = GROTH16_VK_HEADER_BYTES + (static_cast<size_t>(gamma_abc_count) * GROTH16_G1_COMPRESSED_BYTES);
    if (key_bytes.size() != expected_size) {
        return FailValidation(error, "Groth16 verifying key bytes have unexpected length");
    }

    if (!ValidateCompressedG1(parsed.alpha_g1, error) ||
        !ValidateCompressedG2(parsed.beta_g2, error) ||
        !ValidateCompressedG2(parsed.gamma_g2, error) ||
        !ValidateCompressedG2(parsed.delta_g2, error)) {
        return false;
    }

    parsed.gamma_abc_g1.resize(gamma_abc_count);
    for (uint32_t i = 0; i < gamma_abc_count; ++i) {
        std::copy_n(key_bytes.begin() + offset, GROTH16_G1_COMPRESSED_BYTES, parsed.gamma_abc_g1[i].begin());
        offset += GROTH16_G1_COMPRESSED_BYTES;
        if (!ValidateCompressedG1(parsed.gamma_abc_g1[i], error)) {
            return false;
        }
    }

    out_verifying_key = parsed;
    return true;
}

bool LoadValiditySidechainGroth16VerificationKey(
    const fs::path& path,
    uint32_t expected_public_input_count,
    ValiditySidechainGroth16VerificationKey& out_verifying_key,
    std::string* error)
{
    fsbridge::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return FailValidation(error, "unable to read Groth16 verifying key");
    }

    const std::vector<unsigned char> key_bytes{
        std::istreambuf_iterator<char>(file),
        std::istreambuf_iterator<char>()};
    return ParseValiditySidechainGroth16VerificationKey(
        key_bytes,
        expected_public_input_count,
        out_verifying_key,
        error);
}

bool ValidateValiditySidechainGroth16ScalarFieldElement(
    const std::array<unsigned char, 32>& scalar_bytes_le,
    std::string* error)
{
    blst_scalar scalar;
    return ParseScalarLE(scalar_bytes_le, scalar, error);
}

bool VerifyValiditySidechainGroth16Proof(
    const ValiditySidechainGroth16VerificationKey& verifying_key,
    const ValiditySidechainGroth16Proof& proof,
    const std::vector<std::array<unsigned char, 32>>& public_inputs_le,
    std::string* error)
{
    blst_p1_affine proof_a;
    blst_p2_affine proof_b;
    blst_p1_affine proof_c;
    blst_p1_affine alpha_g1;
    blst_p2_affine beta_g2;
    blst_p2_affine gamma_g2;
    blst_p2_affine delta_g2;
    blst_p1_affine gamma_abc_sum;

    if (!UncompressG1(proof.a_g1, proof_a, error) ||
        !UncompressG2(proof.b_g2, proof_b, error) ||
        !UncompressG1(proof.c_g1, proof_c, error) ||
        !UncompressG1(verifying_key.alpha_g1, alpha_g1, error) ||
        !UncompressG2(verifying_key.beta_g2, beta_g2, error) ||
        !UncompressG2(verifying_key.gamma_g2, gamma_g2, error) ||
        !UncompressG2(verifying_key.delta_g2, delta_g2, error) ||
        !ComputeGammaABCCombination(verifying_key, public_inputs_le, gamma_abc_sum, error)) {
        return false;
    }

    blst_fp12 lhs;
    blst_fp12 rhs;
    blst_fp12 term;
    ComputeSafeMillerLoop(lhs, proof_b, proof_a);
    ComputeSafeMillerLoop(rhs, beta_g2, alpha_g1);
    ComputeSafeMillerLoop(term, gamma_g2, gamma_abc_sum);
    blst_fp12_mul(&rhs, &rhs, &term);
    ComputeSafeMillerLoop(term, delta_g2, proof_c);
    blst_fp12_mul(&rhs, &rhs, &term);

    if (!blst_fp12_finalverify(&lhs, &rhs)) {
        return FailValidation(error, "Groth16 pairing doesn't match");
    }

    return true;
}
