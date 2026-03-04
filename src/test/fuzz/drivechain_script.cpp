// Copyright (c) 2026 AllSageTech, LLC
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <drivechain/script.h>
#include <script/script.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <uint256.h>

#include <cassert>
#include <optional>
#include <vector>

void test_one_input(const std::vector<uint8_t>& buffer)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    const std::optional<CScript> script_opt = ConsumeDeserializable<CScript>(fuzzed_data_provider);
    if (script_opt) {
        DrivechainScriptInfo drivechain_info;
        (void)DecodeDrivechainScript(*script_opt, drivechain_info);

        DrivechainBmmRequestInfo request_info;
        (void)DecodeDrivechainBmmRequestScript(*script_opt, request_info);

        DrivechainBmmAcceptInfo accept_info;
        (void)DecodeDrivechainBmmAcceptScript(*script_opt, accept_info);
    }

    const uint8_t sidechain_id = fuzzed_data_provider.ConsumeIntegral<uint8_t>();
    const uint256 bundle_hash = ConsumeUInt256(fuzzed_data_provider);
    const uint32_t n_withdrawals = fuzzed_data_provider.ConsumeIntegralInRange<uint32_t>(1, 128);

    const CScript execute_script = BuildDrivechainExecuteScript(sidechain_id, bundle_hash, n_withdrawals);
    DrivechainScriptInfo execute_info;
    const bool execute_decoded = DecodeDrivechainScript(execute_script, execute_info);
    assert(execute_decoded);
    assert(execute_info.kind == DrivechainScriptInfo::Kind::EXECUTE);
    assert(execute_info.sidechain_id == sidechain_id);
    assert(execute_info.payload == bundle_hash);
    assert(execute_info.n_withdrawals == n_withdrawals);

    const uint256 side_block_hash = ConsumeUInt256(fuzzed_data_provider);
    const uint256 prev_main_hash = ConsumeUInt256(fuzzed_data_provider);

    const CScript request_script = BuildDrivechainBmmRequestScript(sidechain_id, side_block_hash, prev_main_hash);
    DrivechainBmmRequestInfo request_info;
    const bool request_decoded = DecodeDrivechainBmmRequestScript(request_script, request_info);
    assert(request_decoded);
    assert(request_info.sidechain_id == sidechain_id);
    assert(request_info.side_block_hash == side_block_hash);
    assert(request_info.prev_main_block_hash == prev_main_hash);

    const CScript accept_script = BuildDrivechainBmmAcceptScript(sidechain_id, side_block_hash);
    DrivechainBmmAcceptInfo accept_info;
    const bool accept_decoded = DecodeDrivechainBmmAcceptScript(accept_script, accept_info);
    assert(accept_decoded);
    assert(accept_info.sidechain_id == sidechain_id);
    assert(accept_info.side_block_hash == side_block_hash);
}
