// Copyright (c) 2026 AllSageTech, LLC
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VALIDITYSIDECHAIN_BLST_BACKEND_H
#define BITCOIN_VALIDITYSIDECHAIN_BLST_BACKEND_H

#include <cstdint>
#include <string>

struct ValiditySidechainNativeBlstBackendStatus
{
    bool available{false};
    bool self_test_passed{false};
    uint64_t pairing_context_bytes{0};
    std::string status;
};

bool GetValiditySidechainNativeBlstBackendStatus(
    ValiditySidechainNativeBlstBackendStatus& out_status);

#endif // BITCOIN_VALIDITYSIDECHAIN_BLST_BACKEND_H
