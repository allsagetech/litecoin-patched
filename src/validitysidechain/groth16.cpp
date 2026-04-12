// Copyright (c) 2026 AllSageTech, LLC
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <validitysidechain/groth16.h>

extern "C" {
#include <blst.h>
}

#include <fs.h>
#include <hash.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <ios>
#include <iterator>
#include <vector>

namespace {

static constexpr unsigned char GROTH16_PROOF_MAGIC[] = {'V', 'S', 'G', 'P', 0x01};
static constexpr unsigned char GROTH16_VK_MAGIC[] = {'V', 'S', 'G', 'V', 'K', 0x01};
static constexpr size_t GROTH16_G1_COMPRESSED_BYTES = 48;
static constexpr size_t GROTH16_G1_UNCOMPRESSED_BYTES = 96;
static constexpr size_t GROTH16_G2_COMPRESSED_BYTES = 96;
static constexpr size_t GROTH16_SCALAR_BYTES = 32;
static constexpr size_t GROTH16_PROOF_ENCODED_BYTES =
    sizeof(GROTH16_PROOF_MAGIC) + GROTH16_G1_COMPRESSED_BYTES + GROTH16_G2_COMPRESSED_BYTES + GROTH16_G1_COMPRESSED_BYTES;
static constexpr size_t GROTH16_VK_HEADER_BYTES =
    sizeof(GROTH16_VK_MAGIC) + sizeof(uint32_t) + (GROTH16_G1_COMPRESSED_BYTES + (GROTH16_G2_COMPRESSED_BYTES * 3)) + sizeof(uint32_t);
static constexpr size_t GROTH16_PEDERSEN_VK_ENCODED_BYTES = GROTH16_G2_COMPRESSED_BYTES * 2;
static constexpr size_t GROTH16_EXPAND_MESSAGE_XMD_SECURITY_BYTES = 16;
static constexpr char GROTH16_COMMITMENT_DST[] = "bsb22-commitment";
static constexpr char GROTH16_COMMITMENT_FOLD_DST[] = "G16-BSB22";

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

static bool ValidateCompressedG1AllowInfinity(
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

static bool UncompressG1AllowInfinity(
    const std::array<unsigned char, GROTH16_G1_COMPRESSED_BYTES>& point_bytes,
    blst_p1_affine& out_point,
    std::string* error)
{
    const BLST_ERROR result = blst_p1_uncompress(&out_point, point_bytes.data());
    if (result != BLST_SUCCESS || !blst_p1_affine_in_g1(&out_point)) {
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

static std::array<unsigned char, GROTH16_SCALAR_BYTES> ReverseScalarBytes(
    const std::array<unsigned char, GROTH16_SCALAR_BYTES>& bytes)
{
    std::array<unsigned char, GROTH16_SCALAR_BYTES> reversed{};
    std::reverse_copy(bytes.begin(), bytes.end(), reversed.begin());
    return reversed;
}

static std::array<unsigned char, GROTH16_SCALAR_BYTES> ScalarLEFromScalar(const blst_scalar& scalar)
{
    std::array<unsigned char, GROTH16_SCALAR_BYTES> out{};
    blst_lendian_from_scalar(out.data(), &scalar);
    return out;
}

static std::array<unsigned char, GROTH16_SCALAR_BYTES> ScalarBEFromScalar(const blst_scalar& scalar)
{
    std::array<unsigned char, GROTH16_SCALAR_BYTES> out{};
    blst_bendian_from_scalar(out.data(), &scalar);
    return out;
}

static bool IsZeroScalarLE(const std::array<unsigned char, GROTH16_SCALAR_BYTES>& scalar_bytes)
{
    return std::all_of(
        scalar_bytes.begin(),
        scalar_bytes.end(),
        [](unsigned char byte) { return byte == 0; });
}

static void NegateG2Affine(
    blst_p2_affine& out_point,
    const blst_p2_affine& point)
{
    blst_p2 point_jacobian;
    blst_p2_from_affine(&point_jacobian, &point);
    blst_p2_cneg(&point_jacobian, true);
    blst_p2_to_affine(&out_point, &point_jacobian);
}

static bool ExpandMsgXmdSHA256(
    const std::vector<unsigned char>& msg,
    const std::vector<unsigned char>& dst,
    size_t len_in_bytes,
    std::vector<unsigned char>& out,
    std::string* error)
{
    if (dst.size() > 255) {
        return FailValidation(error, "Groth16 commitment hash domain is too large");
    }

    const size_t hash_size = CSHA256::OUTPUT_SIZE;
    const size_t hash_block_size = 64;
    const size_t ell = (len_in_bytes + hash_size - 1) / hash_size;
    if (ell > 255) {
        return FailValidation(error, "Groth16 commitment hash output is too large");
    }

    const unsigned char dst_size = static_cast<unsigned char>(dst.size());
    std::array<unsigned char, CSHA256::OUTPUT_SIZE> b0{};
    std::array<unsigned char, CSHA256::OUTPUT_SIZE> bi{};
    std::array<unsigned char, CSHA256::OUTPUT_SIZE> strxor{};
    std::array<unsigned char, 3> len_block{
        static_cast<unsigned char>((len_in_bytes >> 8) & 0xff),
        static_cast<unsigned char>(len_in_bytes & 0xff),
        0};
    const unsigned char one = 1;

    std::vector<unsigned char> z_pad(hash_block_size, 0);

    CSHA256()
        .Write(z_pad.data(), z_pad.size())
        .Write(msg.data(), msg.size())
        .Write(len_block.data(), len_block.size())
        .Write(dst.data(), dst.size())
        .Write(&dst_size, 1)
        .Finalize(b0.data());

    CSHA256()
        .Write(b0.data(), b0.size())
        .Write(&one, 1)
        .Write(dst.data(), dst.size())
        .Write(&dst_size, 1)
        .Finalize(bi.data());

    out.assign(len_in_bytes, 0);
    std::copy_n(bi.begin(), std::min(hash_size, len_in_bytes), out.begin());

    for (size_t i = 2; i <= ell; ++i) {
        for (size_t j = 0; j < hash_size; ++j) {
            strxor[j] = b0[j] ^ bi[j];
        }
        const unsigned char block_index = static_cast<unsigned char>(i);
        CSHA256()
            .Write(strxor.data(), strxor.size())
            .Write(&block_index, 1)
            .Write(dst.data(), dst.size())
            .Write(&dst_size, 1)
            .Finalize(bi.data());

        const size_t offset = hash_size * (i - 1);
        const size_t copy_len = std::min(hash_size, len_in_bytes - offset);
        std::copy_n(bi.begin(), copy_len, out.begin() + offset);
    }

    return true;
}

static bool HashToFieldScalar(
    const std::vector<unsigned char>& msg,
    const std::vector<unsigned char>& dst,
    std::array<unsigned char, GROTH16_SCALAR_BYTES>& out_scalar_le,
    std::array<unsigned char, GROTH16_SCALAR_BYTES>& out_scalar_be,
    std::string* error)
{
    const size_t uniform_len = GROTH16_EXPAND_MESSAGE_XMD_SECURITY_BYTES + GROTH16_SCALAR_BYTES;
    std::vector<unsigned char> uniform_bytes;
    if (!ExpandMsgXmdSHA256(msg, dst, uniform_len, uniform_bytes, error)) {
        return false;
    }

    blst_scalar scalar{};
    blst_scalar_from_be_bytes(&scalar, uniform_bytes.data(), uniform_bytes.size());
    out_scalar_le = ScalarLEFromScalar(scalar);
    out_scalar_be = ScalarBEFromScalar(scalar);
    return true;
}

static bool BuildCommitmentDerivedPublicInputs(
    const ValiditySidechainGroth16VerificationKey& verifying_key,
    const ValiditySidechainGroth16Proof& proof,
    std::vector<std::array<unsigned char, GROTH16_SCALAR_BYTES>>& inout_public_inputs_le,
    std::vector<std::array<unsigned char, GROTH16_SCALAR_BYTES>>& out_commitment_hashes_be,
    std::string* error)
{
    out_commitment_hashes_be.clear();
    if (verifying_key.commitment_keys.empty()) {
        if (!proof.commitments_g1.empty() || proof.has_commitment_pok ||
            !verifying_key.public_and_commitment_committed.empty()) {
            return FailValidation(error, "Groth16 proof contains unexpected commitment metadata");
        }
        return true;
    }

    if (verifying_key.public_and_commitment_committed.size() != verifying_key.commitment_keys.size()) {
        return FailValidation(error, "Groth16 verifying key commitment metadata is inconsistent");
    }
    if (proof.commitments_g1.size() != verifying_key.commitment_keys.size()) {
        return FailValidation(error, "Groth16 proof commitment count does not match verifying key");
    }
    if (!proof.has_commitment_pok) {
        return FailValidation(error, "Groth16 proof is missing folded commitment proof");
    }

    std::vector<std::array<unsigned char, GROTH16_SCALAR_BYTES>> public_inputs_be;
    public_inputs_be.reserve(inout_public_inputs_le.size() + verifying_key.commitment_keys.size());
    for (const auto& input_le : inout_public_inputs_le) {
        public_inputs_be.push_back(ReverseScalarBytes(input_le));
    }

    const std::vector<unsigned char> commitment_dst{
        GROTH16_COMMITMENT_DST,
        GROTH16_COMMITMENT_DST + sizeof(GROTH16_COMMITMENT_DST) - 1};

    out_commitment_hashes_be.reserve(verifying_key.commitment_keys.size());
    inout_public_inputs_le.reserve(inout_public_inputs_le.size() + verifying_key.commitment_keys.size());

    for (size_t i = 0; i < verifying_key.commitment_keys.size(); ++i) {
        blst_p1_affine commitment_affine;
        if (!UncompressG1AllowInfinity(proof.commitments_g1[i], commitment_affine, error)) {
            return false;
        }

        std::array<unsigned char, GROTH16_G1_UNCOMPRESSED_BYTES> commitment_bytes{};
        blst_p1_affine_serialize(commitment_bytes.data(), &commitment_affine);

        std::vector<unsigned char> preimage;
        preimage.reserve(
            commitment_bytes.size() +
            (verifying_key.public_and_commitment_committed[i].size() * GROTH16_SCALAR_BYTES));
        preimage.insert(preimage.end(), commitment_bytes.begin(), commitment_bytes.end());

        for (const uint32_t wire_index : verifying_key.public_and_commitment_committed[i]) {
            if (wire_index == 0 || wire_index > public_inputs_be.size()) {
                return FailValidation(error, "Groth16 commitment witness index is out of range");
            }
            const auto& witness_be = public_inputs_be[wire_index - 1];
            preimage.insert(preimage.end(), witness_be.begin(), witness_be.end());
        }

        std::array<unsigned char, GROTH16_SCALAR_BYTES> derived_input_le{};
        std::array<unsigned char, GROTH16_SCALAR_BYTES> derived_input_be{};
        if (!HashToFieldScalar(preimage, commitment_dst, derived_input_le, derived_input_be, error)) {
            return false;
        }

        inout_public_inputs_le.push_back(derived_input_le);
        public_inputs_be.push_back(derived_input_be);
        out_commitment_hashes_be.push_back(derived_input_be);
    }

    return true;
}

static bool AddProofCommitmentsToGammaABCCombination(
    const ValiditySidechainGroth16Proof& proof,
    blst_p1_affine& inout_gamma_abc_sum,
    std::string* error)
{
    if (proof.commitments_g1.empty()) {
        return true;
    }

    blst_p1 accumulator;
    bool have_accumulator = !blst_p1_affine_is_inf(&inout_gamma_abc_sum);
    if (have_accumulator) {
        blst_p1_from_affine(&accumulator, &inout_gamma_abc_sum);
    }

    for (const auto& commitment_bytes : proof.commitments_g1) {
        blst_p1_affine commitment_affine;
        if (!UncompressG1AllowInfinity(commitment_bytes, commitment_affine, error)) {
            return false;
        }
        if (blst_p1_affine_is_inf(&commitment_affine)) {
            continue;
        }

        blst_p1 commitment;
        blst_p1_from_affine(&commitment, &commitment_affine);
        if (!have_accumulator) {
            accumulator = commitment;
            have_accumulator = true;
            continue;
        }
        blst_p1_add_or_double(&accumulator, &accumulator, &commitment);
    }

    if (!have_accumulator) {
        inout_gamma_abc_sum = blst_p1_affine{};
    } else {
        blst_p1_to_affine(&inout_gamma_abc_sum, &accumulator);
    }
    if (!blst_p1_affine_in_g1(&inout_gamma_abc_sum)) {
        return FailValidation(error, "Groth16 commitment combination left G1");
    }
    return true;
}

static bool VerifyProofCommitmentKnowledge(
    const ValiditySidechainGroth16VerificationKey& verifying_key,
    const ValiditySidechainGroth16Proof& proof,
    const std::vector<std::array<unsigned char, GROTH16_SCALAR_BYTES>>& commitment_hashes_be,
    std::string* error)
{
    if (verifying_key.commitment_keys.empty()) {
        return true;
    }
    if (commitment_hashes_be.size() != verifying_key.commitment_keys.size()) {
        return FailValidation(error, "Groth16 commitment hash count does not match verifying key");
    }

    std::vector<unsigned char> folded_challenge_preimage;
    folded_challenge_preimage.reserve(commitment_hashes_be.size() * GROTH16_SCALAR_BYTES);
    for (const auto& hash_be : commitment_hashes_be) {
        folded_challenge_preimage.insert(
            folded_challenge_preimage.end(),
            hash_be.begin(),
            hash_be.end());
    }
    const std::vector<unsigned char> folded_dst{
        GROTH16_COMMITMENT_FOLD_DST,
        GROTH16_COMMITMENT_FOLD_DST + sizeof(GROTH16_COMMITMENT_FOLD_DST) - 1};

    std::array<unsigned char, GROTH16_SCALAR_BYTES> challenge_le{};
    std::array<unsigned char, GROTH16_SCALAR_BYTES> challenge_be{};
    if (!HashToFieldScalar(folded_challenge_preimage, folded_dst, challenge_le, challenge_be, error)) {
        return false;
    }

    blst_scalar challenge_scalar{};
    if (!ParseScalarLE(challenge_le, challenge_scalar, error)) {
        return false;
    }
    blst_fr challenge_fr{};
    blst_fr_from_scalar(&challenge_fr, &challenge_scalar);
    uint64_t one_words[4]{1, 0, 0, 0};
    blst_fr challenge_power_fr{};
    blst_fr_from_uint64(&challenge_power_fr, one_words);

    std::vector<blst_p2_affine> commitment_key_gs;
    commitment_key_gs.reserve(verifying_key.commitment_keys.size());

    const size_t pairing_size = blst_pairing_sizeof();
    if (pairing_size == 0) {
        return FailValidation(error, "Groth16 verifier pairing context is unavailable");
    }

    std::vector<uint64_t> pairing_storage((pairing_size + sizeof(uint64_t) - 1) / sizeof(uint64_t));
    auto* pairing = reinterpret_cast<blst_pairing*>(pairing_storage.data());
    blst_pairing_init(pairing, /* hash_or_encode= */ false, nullptr, 0);

    for (size_t i = 0; i < verifying_key.commitment_keys.size(); ++i) {
        blst_p1_affine commitment_affine;
        if (!UncompressG1AllowInfinity(proof.commitments_g1[i], commitment_affine, error)) {
            return false;
        }

        blst_p2_affine g_sigma_neg_affine;
        if (!UncompressG2(verifying_key.commitment_keys[i].g_sigma_neg_g2, g_sigma_neg_affine, error)) {
            return false;
        }
        blst_p2_affine g_affine;
        if (!UncompressG2(verifying_key.commitment_keys[i].g_g2, g_affine, error)) {
            return false;
        }
        if (!commitment_key_gs.empty() && !blst_p2_affine_is_equal(&g_affine, &commitment_key_gs.front())) {
            return FailValidation(error, "Groth16 commitment keys use inconsistent G2 generators");
        }
        commitment_key_gs.push_back(g_affine);

        if (i == 0) {
            blst_pairing_raw_aggregate(pairing, &g_sigma_neg_affine, &commitment_affine);
            continue;
        }

        blst_fr_mul(&challenge_power_fr, &challenge_power_fr, &challenge_fr);
        blst_scalar challenge_power_scalar{};
        blst_scalar_from_fr(&challenge_power_scalar, &challenge_power_fr);

        blst_p1 commitment_scaled;
        blst_p1_from_affine(&commitment_scaled, &commitment_affine);
        blst_p1_mult(&commitment_scaled, &commitment_scaled, challenge_power_scalar.b, 255);
        blst_p1_affine commitment_scaled_affine;
        blst_p1_to_affine(&commitment_scaled_affine, &commitment_scaled);
        blst_pairing_raw_aggregate(pairing, &g_sigma_neg_affine, &commitment_scaled_affine);
    }

    blst_p1_affine folded_pok_affine;
    if (!UncompressG1AllowInfinity(proof.commitment_pok_g1, folded_pok_affine, error)) {
        return false;
    }
    blst_pairing_raw_aggregate(pairing, &commitment_key_gs.front(), &folded_pok_affine);
    blst_pairing_commit(pairing);

    if (!blst_pairing_finalverify(pairing, nullptr)) {
        return FailValidation(error, "Groth16 commitment proof rejected");
    }
    return true;
}

static bool ComputeGammaABCCombination(
    const ValiditySidechainGroth16VerificationKey& verifying_key,
    const std::vector<std::array<unsigned char, GROTH16_SCALAR_BYTES>>& public_inputs_le,
    blst_p1_affine& out_point,
    std::string* error)
{
    if (verifying_key.public_and_commitment_committed.size() != verifying_key.commitment_keys.size()) {
        return FailValidation(error, "Groth16 verifying key commitment metadata is inconsistent");
    }
    const size_t expected_public_inputs =
        static_cast<size_t>(verifying_key.public_input_count) + verifying_key.commitment_keys.size();
    if (public_inputs_le.size() != expected_public_inputs) {
        return FailValidation(error, "Groth16 public-input count does not match verifying key");
    }
    if (verifying_key.gamma_abc_g1.size() != expected_public_inputs + 1) {
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
    if (!proof.commitments_g1.empty()) {
        AppendUint32LE(out, static_cast<uint32_t>(proof.commitments_g1.size()));
        for (const auto& point : proof.commitments_g1) {
            out.insert(out.end(), point.begin(), point.end());
        }
        out.insert(out.end(), proof.commitment_pok_g1.begin(), proof.commitment_pok_g1.end());
    }
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
    const size_t commitment_count = std::min(
        verifying_key.public_and_commitment_committed.size(),
        verifying_key.commitment_keys.size());
    if (commitment_count != 0) {
        AppendUint32LE(out, static_cast<uint32_t>(commitment_count));
        for (size_t i = 0; i < commitment_count; ++i) {
            AppendUint32LE(out, static_cast<uint32_t>(verifying_key.public_and_commitment_committed[i].size()));
            for (const uint32_t wire_index : verifying_key.public_and_commitment_committed[i]) {
                AppendUint32LE(out, wire_index);
            }
            out.insert(
                out.end(),
                verifying_key.commitment_keys[i].g_g2.begin(),
                verifying_key.commitment_keys[i].g_g2.end());
            out.insert(
                out.end(),
                verifying_key.commitment_keys[i].g_sigma_neg_g2.begin(),
                verifying_key.commitment_keys[i].g_sigma_neg_g2.end());
        }
    }
    return out;
}

bool ParseValiditySidechainGroth16Proof(
    const std::vector<unsigned char>& proof_bytes,
    ValiditySidechainGroth16Proof& out_proof,
    std::string* error)
{
    if (proof_bytes.size() < GROTH16_PROOF_ENCODED_BYTES) {
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
    offset += GROTH16_G1_COMPRESSED_BYTES;

    if (!ValidateCompressedG1(parsed.a_g1, error) ||
        !ValidateCompressedG2(parsed.b_g2, error) ||
        !ValidateCompressedG1(parsed.c_g1, error)) {
        return false;
    }

    if (offset != proof_bytes.size()) {
        uint32_t commitment_count = 0;
        if (!ReadUint32LE(proof_bytes, offset, commitment_count)) {
            return FailValidation(error, "Groth16 proof bytes have unexpected length");
        }
        offset += sizeof(uint32_t);
        if (commitment_count == 0) {
            return FailValidation(error, "Groth16 proof commitment extension is malformed");
        }

        const size_t expected_size =
            GROTH16_PROOF_ENCODED_BYTES +
            sizeof(uint32_t) +
            (static_cast<size_t>(commitment_count) * GROTH16_G1_COMPRESSED_BYTES) +
            GROTH16_G1_COMPRESSED_BYTES;
        if (proof_bytes.size() != expected_size) {
            return FailValidation(error, "Groth16 proof bytes have unexpected length");
        }

        parsed.commitments_g1.resize(commitment_count);
        for (uint32_t i = 0; i < commitment_count; ++i) {
            std::copy_n(
                proof_bytes.begin() + offset,
                GROTH16_G1_COMPRESSED_BYTES,
                parsed.commitments_g1[i].begin());
            offset += GROTH16_G1_COMPRESSED_BYTES;
            if (!ValidateCompressedG1AllowInfinity(parsed.commitments_g1[i], error)) {
                return false;
            }
        }

        std::copy_n(
            proof_bytes.begin() + offset,
            GROTH16_G1_COMPRESSED_BYTES,
            parsed.commitment_pok_g1.begin());
        offset += GROTH16_G1_COMPRESSED_BYTES;
        if (!ValidateCompressedG1AllowInfinity(parsed.commitment_pok_g1, error)) {
            return false;
        }
        parsed.has_commitment_pok = true;
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

    if (offset != key_bytes.size()) {
        uint32_t commitment_count = 0;
        if (!ReadUint32LE(key_bytes, offset, commitment_count)) {
            return FailValidation(error, "Groth16 verifying key bytes have unexpected length");
        }
        offset += sizeof(uint32_t);
        if (commitment_count == 0) {
            return FailValidation(error, "Groth16 verifying key commitment extension is malformed");
        }
        if (gamma_abc_count != expected_public_input_count + commitment_count + 1) {
            return FailValidation(error, "Groth16 verifying key gamma_abc count does not match supported profile");
        }

        parsed.public_and_commitment_committed.resize(commitment_count);
        parsed.commitment_keys.resize(commitment_count);
        for (uint32_t i = 0; i < commitment_count; ++i) {
            uint32_t witness_index_count = 0;
            if (!ReadUint32LE(key_bytes, offset, witness_index_count)) {
                return FailValidation(error, "Groth16 verifying key bytes have unexpected length");
            }
            offset += sizeof(uint32_t);

            parsed.public_and_commitment_committed[i].resize(witness_index_count);
            for (uint32_t j = 0; j < witness_index_count; ++j) {
                if (!ReadUint32LE(key_bytes, offset, parsed.public_and_commitment_committed[i][j])) {
                    return FailValidation(error, "Groth16 verifying key bytes have unexpected length");
                }
                offset += sizeof(uint32_t);
            }

            if (key_bytes.size() - offset < GROTH16_PEDERSEN_VK_ENCODED_BYTES) {
                return FailValidation(error, "Groth16 verifying key bytes have unexpected length");
            }
            std::copy_n(
                key_bytes.begin() + offset,
                GROTH16_G2_COMPRESSED_BYTES,
                parsed.commitment_keys[i].g_g2.begin());
            offset += GROTH16_G2_COMPRESSED_BYTES;
            std::copy_n(
                key_bytes.begin() + offset,
                GROTH16_G2_COMPRESSED_BYTES,
                parsed.commitment_keys[i].g_sigma_neg_g2.begin());
            offset += GROTH16_G2_COMPRESSED_BYTES;

            if (!ValidateCompressedG2(parsed.commitment_keys[i].g_g2, error) ||
                !ValidateCompressedG2(parsed.commitment_keys[i].g_sigma_neg_g2, error)) {
                return false;
            }
        }
    } else if (gamma_abc_count != expected_public_input_count + 1) {
        return FailValidation(error, "Groth16 verifying key gamma_abc count does not match supported profile");
    }

    if (offset != key_bytes.size()) {
        return FailValidation(error, "Groth16 verifying key bytes have unexpected length");
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
    std::vector<std::array<unsigned char, GROTH16_SCALAR_BYTES>> effective_public_inputs = public_inputs_le;
    std::vector<std::array<unsigned char, GROTH16_SCALAR_BYTES>> commitment_hashes_be;
    if (!BuildCommitmentDerivedPublicInputs(
            verifying_key,
            proof,
            effective_public_inputs,
            commitment_hashes_be,
            error)) {
        return false;
    }

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
        !ComputeGammaABCCombination(verifying_key, effective_public_inputs, gamma_abc_sum, error)) {
        return false;
    }
    if (!VerifyProofCommitmentKnowledge(verifying_key, proof, commitment_hashes_be, error) ||
        !AddProofCommitmentsToGammaABCCombination(proof, gamma_abc_sum, error)) {
        return false;
    }

    const size_t pairing_size = blst_pairing_sizeof();
    if (pairing_size == 0) {
        return FailValidation(error, "Groth16 verifier pairing context is unavailable");
    }

    std::vector<uint64_t> pairing_storage((pairing_size + sizeof(uint64_t) - 1) / sizeof(uint64_t));
    auto* pairing = reinterpret_cast<blst_pairing*>(pairing_storage.data());
    blst_pairing_init(pairing, /* hash_or_encode= */ false, nullptr, 0);

    blst_p2_affine negated_proof_b;
    NegateG2Affine(negated_proof_b, proof_b);

    blst_pairing_raw_aggregate(pairing, &negated_proof_b, &proof_a);
    blst_pairing_raw_aggregate(pairing, &beta_g2, &alpha_g1);
    blst_pairing_raw_aggregate(pairing, &gamma_g2, &gamma_abc_sum);
    blst_pairing_raw_aggregate(pairing, &delta_g2, &proof_c);
    blst_pairing_commit(pairing);

    if (!blst_pairing_finalverify(pairing, nullptr)) {
        return FailValidation(error, "Groth16 pairing doesn't match");
    }

    return true;
}
