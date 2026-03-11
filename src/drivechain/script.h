// Copyright (c) 2025-2026 AllSageTech, LLC
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DRIVECHAIN_SCRIPT_H
#define DRIVECHAIN_SCRIPT_H

#include <drivechain/policy.h>

#include <cstdint>
#include <span.h>
#include <script/script.h>
#include <uint256.h>
#include <vector>

struct DrivechainScriptInfo
{
    enum class Kind : uint8_t {
        DEPOSIT       = 0,
        BUNDLE_COMMIT = 1,
        VOTE_YES      = 2,
        EXECUTE       = 3,
        VOTE_NO       = 4,
        REGISTER      = 5,
        UNKNOWN       = 255,
    };

    Kind kind{Kind::UNKNOWN};
    uint8_t sidechain_id{0};
    uint256 payload;
    uint32_t n_withdrawals{0};
    std::vector<unsigned char> auth_sig; // First compact auth signature, kept for legacy callers/tests.
    std::vector<std::vector<unsigned char>> auth_sigs;
    DrivechainSidechainPolicy sidechain_policy;
};

struct DrivechainBmmRequestInfo
{
    uint8_t sidechain_id{0};
    uint256 side_block_hash;
    uint256 prev_main_block_hash;
};

struct DrivechainBmmAcceptInfo
{
    uint8_t sidechain_id{0};
    uint256 side_block_hash;
};

bool DecodeDrivechainScript(const CScript& scriptPubKey, DrivechainScriptInfo& out_info);
bool DecodeDrivechainBmmRequestScript(const CScript& scriptPubKey, DrivechainBmmRequestInfo& out_info);
bool DecodeDrivechainBmmAcceptScript(const CScript& scriptPubKey, DrivechainBmmAcceptInfo& out_info);
std::vector<unsigned char> EncodeDrivechainSidechainPolicy(const DrivechainSidechainPolicy& policy);
bool DecodeDrivechainSidechainPolicy(Span<const unsigned char> policy_bytes, DrivechainSidechainPolicy& out_policy);
uint256 ComputeDrivechainSidechainPolicyHash(const DrivechainSidechainPolicy& policy);

// OP_RETURN OP_DRIVECHAIN <scid> <bundle_hash> <tag=0x03> <n_withdrawals LE32>
CScript BuildDrivechainExecuteScript(uint8_t scid, const uint256& bundle_hash, uint32_t n_withdrawals);
CScript BuildDrivechainBmmRequestScript(uint8_t scid, const uint256& side_block_hash, const uint256& prev_main_block_hash);
CScript BuildDrivechainBmmAcceptScript(uint8_t scid, const uint256& side_block_hash);

uint256 ComputeDrivechainBundleAuthMessage(uint8_t scid, const uint256& bundle_hash);
bool VerifyDrivechainBundleAuthSigs(
    const DrivechainSidechainPolicy& policy,
    uint8_t scid,
    const uint256& bundle_hash,
    const std::vector<std::vector<unsigned char>>& compact_sigs);
uint256 ComputeDrivechainRegisterAuthMessage(uint8_t scid, const uint256& owner_policy_hash);
bool VerifyDrivechainRegisterAuthSigs(
    uint8_t scid,
    const DrivechainSidechainPolicy& policy,
    const std::vector<std::vector<unsigned char>>& compact_sigs);

#endif
