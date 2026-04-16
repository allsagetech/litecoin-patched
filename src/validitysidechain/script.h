// Copyright (c) 2026 AllSageTech, LLC
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VALIDITYSIDECHAIN_SCRIPT_H
#define BITCOIN_VALIDITYSIDECHAIN_SCRIPT_H

#include <amount.h>
#include <script/script.h>
#include <span.h>
#include <uint256.h>
#include <validitysidechain/state.h>

#include <cstdint>
#include <string>
#include <vector>

struct ValiditySidechainScriptInfo
{
    enum class Kind : uint8_t {
        REGISTER_VALIDITY_SIDECHAIN   = 0x06,
        DEPOSIT_TO_VALIDITY_SIDECHAIN = 0x07,
        COMMIT_VALIDITY_BATCH         = 0x08,
        EXECUTE_VERIFIED_WITHDRAWALS  = 0x09,
        REQUEST_FORCE_EXIT            = 0x0A,
        RECLAIM_STALE_DEPOSIT         = 0x0B,
        EXECUTE_ESCAPE_EXIT           = 0x0C,
        UNKNOWN                       = 0xFF,
    };

    Kind kind{Kind::UNKNOWN};
    uint8_t sidechain_id{0};
    uint256 payload;
    std::vector<unsigned char> primary_metadata;
    std::vector<std::vector<unsigned char>> metadata_pushes;
};

bool DecodeValiditySidechainScript(const CScript& scriptPubKey, ValiditySidechainScriptInfo& out_info);
CScript BuildValiditySidechainScript(
    ValiditySidechainScriptInfo::Kind kind,
    uint8_t scid,
    const uint256& payload,
    const std::vector<std::vector<unsigned char>>& metadata_pushes = {});
CScript BuildValiditySidechainRegisterScript(uint8_t scid, const ValiditySidechainConfig& config);
CScript BuildValiditySidechainDepositScript(uint8_t scid, const ValiditySidechainDepositData& deposit);
CScript BuildValiditySidechainCommitScript(
    uint8_t scid,
    const ValiditySidechainBatchPublicInputs& public_inputs,
    const std::vector<unsigned char>& proof_bytes,
    const std::vector<std::vector<unsigned char>>& data_chunks = {});
CScript BuildValiditySidechainExecuteScript(
    uint8_t scid,
    uint32_t batch_number,
    const uint256& withdrawal_root,
    const std::vector<ValiditySidechainWithdrawalProof>& withdrawal_proofs);
CScript BuildValiditySidechainForceExitScript(uint8_t scid, const ValiditySidechainForceExitData& request);
CScript BuildValiditySidechainReclaimDepositScript(uint8_t scid, const ValiditySidechainDepositData& deposit);
CScript BuildValiditySidechainEscapeExitScript(
    uint8_t scid,
    const uint256& state_root_reference,
    const std::vector<ValiditySidechainEscapeExitProof>& exit_proofs);
CScript BuildValiditySidechainEscapeExitStateScript(
    uint8_t scid,
    const uint256& state_root_reference,
    const std::vector<ValiditySidechainEscapeExitStateProof>& exit_state_proofs);

std::vector<unsigned char> EncodeValiditySidechainConfig(const ValiditySidechainConfig& config);
bool DecodeValiditySidechainConfig(Span<const unsigned char> config_bytes, ValiditySidechainConfig& out_config);
uint256 ComputeValiditySidechainConfigHash(const ValiditySidechainConfig& config);

std::vector<unsigned char> EncodeValiditySidechainDepositData(const ValiditySidechainDepositData& deposit);
bool DecodeValiditySidechainDepositData(Span<const unsigned char> deposit_bytes, ValiditySidechainDepositData& out_deposit);
uint256 ComputeValiditySidechainDepositMessageHash(uint8_t scid, const ValiditySidechainDepositData& deposit);

std::vector<unsigned char> EncodeValiditySidechainBatchPublicInputs(const ValiditySidechainBatchPublicInputs& public_inputs);
bool DecodeValiditySidechainBatchPublicInputs(
    Span<const unsigned char> public_input_bytes,
    ValiditySidechainBatchPublicInputs& out_public_inputs);
bool DecodeValiditySidechainCommitMetadata(
    const ValiditySidechainScriptInfo& info,
    ValiditySidechainBatchPublicInputs& out_public_inputs,
    std::vector<unsigned char>& out_proof_bytes,
    std::vector<std::vector<unsigned char>>& out_data_chunks);
uint256 ComputeValiditySidechainBatchCommitmentHash(uint8_t scid, const ValiditySidechainBatchPublicInputs& public_inputs);

std::vector<unsigned char> EncodeValiditySidechainWithdrawalLeaf(const ValiditySidechainWithdrawalLeaf& withdrawal);
bool DecodeValiditySidechainWithdrawalLeaf(
    Span<const unsigned char> withdrawal_bytes,
    ValiditySidechainWithdrawalLeaf& out_withdrawal);
std::vector<unsigned char> EncodeValiditySidechainWithdrawalProof(const ValiditySidechainWithdrawalProof& proof);
bool DecodeValiditySidechainWithdrawalProof(
    Span<const unsigned char> proof_bytes,
    ValiditySidechainWithdrawalProof& out_proof);
bool DecodeValiditySidechainExecuteMetadata(
    const ValiditySidechainScriptInfo& info,
    std::vector<ValiditySidechainWithdrawalProof>& out_withdrawal_proofs);
bool BuildValiditySidechainWithdrawalProof(
    const std::vector<ValiditySidechainWithdrawalLeaf>& withdrawals,
    uint32_t leaf_index,
    ValiditySidechainWithdrawalProof& out_proof);
bool VerifyValiditySidechainWithdrawalProof(
    const ValiditySidechainWithdrawalProof& proof,
    const uint256& expected_root);
bool ValidateValiditySidechainWithdrawalLeafIds(
    const std::vector<ValiditySidechainWithdrawalLeaf>& withdrawals,
    std::string* error = nullptr);
uint256 ComputeValiditySidechainWithdrawalRoot(const std::vector<ValiditySidechainWithdrawalLeaf>& withdrawals);

std::vector<unsigned char> EncodeValiditySidechainBalanceLeaf(const ValiditySidechainBalanceLeaf& balance);
bool DecodeValiditySidechainBalanceLeaf(
    Span<const unsigned char> balance_bytes,
    ValiditySidechainBalanceLeaf& out_balance);
std::vector<unsigned char> EncodeValiditySidechainBalanceProof(const ValiditySidechainBalanceProof& proof);
bool DecodeValiditySidechainBalanceProof(
    Span<const unsigned char> proof_bytes,
    ValiditySidechainBalanceProof& out_proof);
bool BuildValiditySidechainBalanceProof(
    const std::vector<ValiditySidechainBalanceLeaf>& balances,
    uint32_t leaf_index,
    ValiditySidechainBalanceProof& out_proof);
bool VerifyValiditySidechainBalanceProof(
    const ValiditySidechainBalanceProof& proof,
    const uint256& expected_root);
uint256 ComputeValiditySidechainBalanceRoot(const std::vector<ValiditySidechainBalanceLeaf>& balances);
std::vector<unsigned char> EncodeValiditySidechainAccountStateLeaf(const ValiditySidechainAccountStateLeaf& account);
bool DecodeValiditySidechainAccountStateLeaf(
    Span<const unsigned char> account_bytes,
    ValiditySidechainAccountStateLeaf& out_account);
std::vector<unsigned char> EncodeValiditySidechainAccountStateProof(const ValiditySidechainAccountStateProof& proof);
bool DecodeValiditySidechainAccountStateProof(
    Span<const unsigned char> proof_bytes,
    ValiditySidechainAccountStateProof& out_proof);
bool BuildValiditySidechainAccountStateProof(
    const std::vector<ValiditySidechainAccountStateLeaf>& accounts,
    uint32_t leaf_index,
    ValiditySidechainAccountStateProof& out_proof);
bool VerifyValiditySidechainAccountStateProof(
    const ValiditySidechainAccountStateProof& proof,
    const uint256& expected_root);
uint256 ComputeValiditySidechainAccountStateRoot(const std::vector<ValiditySidechainAccountStateLeaf>& accounts);

std::vector<unsigned char> EncodeValiditySidechainEscapeExitLeaf(const ValiditySidechainEscapeExitLeaf& exit);
bool DecodeValiditySidechainEscapeExitLeaf(
    Span<const unsigned char> exit_bytes,
    ValiditySidechainEscapeExitLeaf& out_exit);
std::vector<unsigned char> EncodeValiditySidechainEscapeExitProof(const ValiditySidechainEscapeExitProof& proof);
bool DecodeValiditySidechainEscapeExitProof(
    Span<const unsigned char> proof_bytes,
    ValiditySidechainEscapeExitProof& out_proof);
std::vector<unsigned char> EncodeValiditySidechainEscapeExitStateProof(const ValiditySidechainEscapeExitStateProof& proof);
bool DecodeValiditySidechainEscapeExitStateProof(
    Span<const unsigned char> proof_bytes,
    ValiditySidechainEscapeExitStateProof& out_proof);
bool DecodeValiditySidechainEscapeExitMetadata(
    const ValiditySidechainScriptInfo& info,
    std::vector<ValiditySidechainEscapeExitProof>& out_exit_proofs);
bool DecodeValiditySidechainEscapeExitStateMetadata(
    const ValiditySidechainScriptInfo& info,
    std::vector<ValiditySidechainEscapeExitStateProof>& out_exit_state_proofs);
uint256 ComputeValiditySidechainEscapeExitStateClaimKey(
    uint8_t scid,
    const ValiditySidechainEscapeExitStateProof& proof);
uint256 ComputeValiditySidechainEscapeExitStateId(
    uint8_t scid,
    const ValiditySidechainEscapeExitStateProof& proof);
bool BuildValiditySidechainEscapeExitProof(
    const std::vector<ValiditySidechainEscapeExitLeaf>& exits,
    uint32_t leaf_index,
    ValiditySidechainEscapeExitProof& out_proof);
bool VerifyValiditySidechainEscapeExitProof(
    const ValiditySidechainEscapeExitProof& proof,
    const uint256& expected_root);
uint256 ComputeValiditySidechainEscapeExitRoot(const std::vector<ValiditySidechainEscapeExitLeaf>& exits);

std::vector<unsigned char> EncodeValiditySidechainForceExitData(const ValiditySidechainForceExitData& request);
bool DecodeValiditySidechainForceExitData(Span<const unsigned char> request_bytes, ValiditySidechainForceExitData& out_request);
uint256 ComputeValiditySidechainForceExitHash(uint8_t scid, const ValiditySidechainForceExitData& request);

uint256 ComputeValiditySidechainAcceptedBatchId(uint8_t scid, uint32_t batch_number, const uint256& withdrawal_root);

#endif // BITCOIN_VALIDITYSIDECHAIN_SCRIPT_H
