// Copyright (c) 2026 AllSageTech, LLC
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VALIDITYSIDECHAIN_GROTH16_H
#define BITCOIN_VALIDITYSIDECHAIN_GROTH16_H

#include <fs.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

struct ValiditySidechainGroth16Proof
{
    std::array<unsigned char, 48> a_g1{};
    std::array<unsigned char, 96> b_g2{};
    std::array<unsigned char, 48> c_g1{};
};

struct ValiditySidechainGroth16VerificationKey
{
    uint32_t public_input_count{0};
    std::array<unsigned char, 48> alpha_g1{};
    std::array<unsigned char, 96> beta_g2{};
    std::array<unsigned char, 96> gamma_g2{};
    std::array<unsigned char, 96> delta_g2{};
    std::vector<std::array<unsigned char, 48>> gamma_abc_g1;
};

std::vector<unsigned char> EncodeValiditySidechainGroth16Proof(
    const ValiditySidechainGroth16Proof& proof);
std::vector<unsigned char> EncodeValiditySidechainGroth16VerificationKey(
    const ValiditySidechainGroth16VerificationKey& verifying_key);
bool ParseValiditySidechainGroth16Proof(
    const std::vector<unsigned char>& proof_bytes,
    ValiditySidechainGroth16Proof& out_proof,
    std::string* error = nullptr);
bool ParseValiditySidechainGroth16VerificationKey(
    const std::vector<unsigned char>& key_bytes,
    uint32_t expected_public_input_count,
    ValiditySidechainGroth16VerificationKey& out_verifying_key,
    std::string* error = nullptr);
bool LoadValiditySidechainGroth16VerificationKey(
    const fs::path& path,
    uint32_t expected_public_input_count,
    ValiditySidechainGroth16VerificationKey& out_verifying_key,
    std::string* error = nullptr);
bool ValidateValiditySidechainGroth16ScalarFieldElement(
    const std::array<unsigned char, 32>& scalar_bytes_le,
    std::string* error = nullptr);
bool VerifyValiditySidechainGroth16Proof(
    const ValiditySidechainGroth16VerificationKey& verifying_key,
    const ValiditySidechainGroth16Proof& proof,
    const std::vector<std::array<unsigned char, 32>>& public_inputs_le,
    std::string* error = nullptr);

#endif // BITCOIN_VALIDITYSIDECHAIN_GROTH16_H
