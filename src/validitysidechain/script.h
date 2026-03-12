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

struct ValiditySidechainDepositData
{
    uint256 deposit_id;
    CAmount amount{0};
    uint256 destination_commitment;
    uint256 refund_script_commitment;
    uint64_t nonce{0};
};

struct ValiditySidechainBatchPublicInputs
{
    uint32_t batch_number{0};
    uint256 prior_state_root;
    uint256 new_state_root;
    uint256 l1_message_root_before;
    uint256 l1_message_root_after;
    uint256 withdrawal_root;
    uint256 data_root;
    uint32_t data_size{0};
};

struct ValiditySidechainForceExitData
{
    uint256 account_id;
    uint256 exit_asset_id;
    CAmount max_exit_amount{0};
    uint256 destination_commitment;
    uint64_t nonce{0};
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
    const std::vector<std::vector<unsigned char>>& extra_metadata_pushes = {});
CScript BuildValiditySidechainExecuteScript(uint8_t scid, uint32_t batch_number, const uint256& withdrawal_root);
CScript BuildValiditySidechainForceExitScript(uint8_t scid, const ValiditySidechainForceExitData& request);
CScript BuildValiditySidechainReclaimDepositScript(uint8_t scid, const uint256& deposit_id);
CScript BuildValiditySidechainEscapeExitScript(uint8_t scid, const uint256& state_root_reference);

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
uint256 ComputeValiditySidechainBatchCommitmentHash(uint8_t scid, const ValiditySidechainBatchPublicInputs& public_inputs);

std::vector<unsigned char> EncodeValiditySidechainForceExitData(const ValiditySidechainForceExitData& request);
bool DecodeValiditySidechainForceExitData(Span<const unsigned char> request_bytes, ValiditySidechainForceExitData& out_request);
uint256 ComputeValiditySidechainForceExitHash(uint8_t scid, const ValiditySidechainForceExitData& request);

uint256 ComputeValiditySidechainAcceptedBatchId(uint8_t scid, uint32_t batch_number, const uint256& withdrawal_root);

#endif // BITCOIN_VALIDITYSIDECHAIN_SCRIPT_H
