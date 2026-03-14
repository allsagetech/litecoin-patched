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
    if (result != BLST_SUCCESS || !blst_p1_affine_in_g1(&point)) {
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
    if (result != BLST_SUCCESS || !blst_p2_affine_in_g2(&point)) {
        return FailValidation(error, "Groth16 proof artifact contains invalid G2 encoding");
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

    const std::vector<unsigned char> key_bytes(
        std::istreambuf_iterator<char>(file),
        std::istreambuf_iterator<char>());
    return ParseValiditySidechainGroth16VerificationKey(
        key_bytes,
        expected_public_input_count,
        out_verifying_key,
        error);
}
