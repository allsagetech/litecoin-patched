// Copyright (c) 2026 AllSageTech, LLC
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <validitysidechain/blst_backend.h>

extern "C" {
#include <blst.h>
}

#include <algorithm>
#include <array>

namespace {

static ValiditySidechainNativeBlstBackendStatus ComputeNativeBlstBackendStatus()
{
    ValiditySidechainNativeBlstBackendStatus status;
    status.available = true;
    status.pairing_context_bytes = static_cast<uint64_t>(blst_pairing_sizeof());

    if (status.pairing_context_bytes == 0) {
        status.status = "native blst backend reported zero pairing context size";
        return status;
    }

    const blst_p1_affine* g1 = blst_p1_affine_generator();
    const blst_p2_affine* g2 = blst_p2_affine_generator();
    if (g1 == nullptr || g2 == nullptr) {
        status.status = "native blst backend did not expose curve generators";
        return status;
    }
    if (!blst_p1_affine_on_curve(g1) || !blst_p1_affine_in_g1(g1)) {
        status.status = "native blst backend failed G1 generator validation";
        return status;
    }
    if (!blst_p2_affine_on_curve(g2) || !blst_p2_affine_in_g2(g2)) {
        status.status = "native blst backend failed G2 generator validation";
        return status;
    }

    std::array<unsigned char, 48> g1_compressed{};
    std::array<unsigned char, 96> g2_compressed{};
    blst_p1_affine_compress(g1_compressed.data(), g1);
    blst_p2_affine_compress(g2_compressed.data(), g2);
    if (std::all_of(g1_compressed.begin(), g1_compressed.end(), [](unsigned char byte) { return byte == 0; }) ||
        std::all_of(g2_compressed.begin(), g2_compressed.end(), [](unsigned char byte) { return byte == 0; })) {
        status.status = "native blst backend produced empty compressed generators";
        return status;
    }

    blst_fp12 gt;
    blst_miller_loop(&gt, g2, g1);
    blst_final_exp(&gt, &gt);
    if (blst_fp12_is_one(&gt)) {
        status.status = "native blst backend pairing self-test returned identity";
        return status;
    }

    status.self_test_passed = true;
    status.status = "native blst backend available";
    return status;
}

} // namespace

bool GetValiditySidechainNativeBlstBackendStatus(
    ValiditySidechainNativeBlstBackendStatus& out_status)
{
    static const ValiditySidechainNativeBlstBackendStatus cached_status = ComputeNativeBlstBackendStatus();
    out_status = cached_status;
    return out_status.available;
}
