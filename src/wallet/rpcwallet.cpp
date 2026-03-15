// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <amount.h>
#include <set>
#include <chainparams.h>
#include <core_io.h>
#include <interfaces/chain.h>
#include <key_io.h>
#include <node/context.h>
#include <optional.h>
#include <outputtype.h>
#include <policy/feerate.h>
#include <policy/fees.h>
#include <policy/policy.h>
#include <policy/rbf.h>
#include <pubkey.h>
#include <random.h>
#include <rpc/rawtransaction_util.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <util/bip32.h>
#include <util/fees.h>
#include <util/message.h> // For MessageSign()
#include <util/moneystr.h>
#include <util/ref.h>
#include <util/string.h>
#include <util/system.h>
#include <util/translation.h>
#include <util/url.h>
#include <util/vector.h>
#include <wallet/coincontrol.h>
#include <wallet/context.h>
#include <wallet/feebumper.h>
#include <wallet/load.h>
#include <wallet/rpcwallet.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/txlist.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>
#include <wallet/walletutil.h>
#include <drivechain/script.h>
#include <hash.h>
#include <validitysidechain/registry.h>
#include <validitysidechain/script.h>
#include <validitysidechain/verifier.h>
#include <wallet/fees.h>

#include <stdint.h>

#include <algorithm>
#include <univalue.h>


using interfaces::FoundBlock;

static const std::string WALLET_ENDPOINT_BASE = "/wallet/";
static const std::string HELP_REQUIRING_PASSPHRASE{"\nRequires wallet passphrase to be set with walletpassphrase call if wallet is encrypted.\n"};

static inline bool GetAvoidReuseFlag(const CWallet* const pwallet, const UniValue& param) {
    bool can_avoid_reuse = pwallet->IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE);
    bool avoid_reuse = param.isNull() ? can_avoid_reuse : param.get_bool();

    if (avoid_reuse && !can_avoid_reuse) {
        throw JSONRPCError(RPC_WALLET_ERROR, "wallet does not have the \"avoid reuse\" feature enabled");
    }

    return avoid_reuse;
}


/** Used by RPC commands that have an include_watchonly parameter.
 *  We default to true for watchonly wallets if include_watchonly isn't
 *  explicitly set.
 */
static bool ParseIncludeWatchonly(const UniValue& include_watchonly, const CWallet& pwallet)
{
    if (include_watchonly.isNull()) {
        // if include_watchonly isn't explicitly set, then check if we have a watchonly wallet
        return pwallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
    }

    // otherwise return whatever include_watchonly was set to
    return include_watchonly.get_bool();
}


/** Checks if a CKey is in the given CWallet compressed or otherwise*/
bool HaveKey(const SigningProvider& wallet, const CKey& key)
{
    CKey key2;
    key2.Set(key.begin(), key.end(), !key.IsCompressed());
    return wallet.HaveKey(key.GetPubKey().GetID()) || wallet.HaveKey(key2.GetPubKey().GetID());
}

bool GetWalletNameFromJSONRPCRequest(const JSONRPCRequest& request, std::string& wallet_name)
{
    if (URL_DECODE && request.URI.substr(0, WALLET_ENDPOINT_BASE.size()) == WALLET_ENDPOINT_BASE) {
        // wallet endpoint was used
        wallet_name = URL_DECODE(request.URI.substr(WALLET_ENDPOINT_BASE.size()));
        return true;
    }
    return false;
}

std::shared_ptr<CWallet> GetWalletForJSONRPCRequest(const JSONRPCRequest& request)
{
    CHECK_NONFATAL(!request.fHelp);
    std::string wallet_name;
    if (GetWalletNameFromJSONRPCRequest(request, wallet_name)) {
        std::shared_ptr<CWallet> pwallet = GetWallet(wallet_name);
        if (!pwallet) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Requested wallet does not exist or is not loaded");
        return pwallet;
    }

    std::vector<std::shared_ptr<CWallet>> wallets = GetWallets();
    if (wallets.size() == 1) {
        return wallets[0];
    }

    if (wallets.empty()) {
        throw JSONRPCError(
            RPC_WALLET_NOT_FOUND, "No wallet is loaded. Load a wallet using loadwallet or create a new one with createwallet. (Note: A default wallet is no longer automatically created)");
    }
    throw JSONRPCError(RPC_WALLET_NOT_SPECIFIED,
        "Wallet file not specified (must request wallet RPC through /wallet/<filename> uri-path).");
}

void EnsureWalletIsUnlocked(const CWallet* pwallet)
{
    if (pwallet->IsLocked()) {
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");
    }
}

WalletContext& EnsureWalletContext(const util::Ref& context)
{
    if (!context.Has<WalletContext>()) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Wallet context not found");
    }
    return context.Get<WalletContext>();
}

// also_create should only be set to true only when the RPC is expected to add things to a blank wallet and make it no longer blank
LegacyScriptPubKeyMan& EnsureLegacyScriptPubKeyMan(CWallet& wallet, bool also_create)
{
    LegacyScriptPubKeyMan* spk_man = wallet.GetLegacyScriptPubKeyMan();
    if (!spk_man && also_create) {
        spk_man = wallet.GetOrCreateLegacyScriptPubKeyMan();
    }
    if (!spk_man) {
        throw JSONRPCError(RPC_WALLET_ERROR, "This type of wallet does not support this command");
    }
    return *spk_man;
}

static void WalletTxToJSON(interfaces::Chain& chain, const CWalletTx& wtx, UniValue& entry)
{
    int confirms = wtx.GetDepthInMainChain();
    entry.pushKV("confirmations", confirms);
    if (wtx.IsCoinBase())
        entry.pushKV("generated", true);
    if (confirms > 0)
    {
        entry.pushKV("blockhash", wtx.m_confirm.hashBlock.GetHex());
        entry.pushKV("blockheight", wtx.m_confirm.block_height);
        entry.pushKV("blockindex", wtx.m_confirm.nIndex);
        int64_t block_time;
        CHECK_NONFATAL(chain.findBlock(wtx.m_confirm.hashBlock, FoundBlock().time(block_time)));
        entry.pushKV("blocktime", block_time);
    } else {
        entry.pushKV("trusted", wtx.IsTrusted());
    }
    uint256 hash = wtx.GetHash();
    entry.pushKV("txid", hash.GetHex());
    UniValue conflicts(UniValue::VARR);
    for (const uint256& conflict : wtx.GetConflicts())
        conflicts.push_back(conflict.GetHex());
    entry.pushKV("walletconflicts", conflicts);
    entry.pushKV("time", wtx.GetTxTime());
    entry.pushKV("timereceived", (int64_t)wtx.nTimeReceived);
    
    if (wtx.mweb_wtx_info) {
        UniValue partial_mweb(UniValue::VOBJ);

        if (wtx.mweb_wtx_info->received_coin) {
            UniValue received_entry(UniValue::VOBJ);
            const mw::Coin& received = *wtx.mweb_wtx_info->received_coin;
            received_entry.pushKV("output_id", received.output_id.ToHex());
            received_entry.pushKV("amount", received.amount);
            partial_mweb.pushKV("received", received_entry);
        }

        if (wtx.mweb_wtx_info->spent_input) {
            UniValue spent_entry(UniValue::VOBJ);
            spent_entry.pushKV("output_id", wtx.mweb_wtx_info->spent_input->ToHex());
            partial_mweb.pushKV("spent", spent_entry);
        }

        entry.pushKV("partial_mweb", partial_mweb);
    }

    // Add opt-in RBF status
    std::string rbfStatus = "no";
    if (confirms <= 0) {
        RBFTransactionState rbfState = chain.isRBFOptIn(*wtx.tx);
        if (rbfState == RBFTransactionState::UNKNOWN)
            rbfStatus = "unknown";
        else if (rbfState == RBFTransactionState::REPLACEABLE_BIP125)
            rbfStatus = "yes";
    }
    entry.pushKV("bip125-replaceable", rbfStatus);

    for (const std::pair<const std::string, std::string>& item : wtx.mapValue)
        entry.pushKV(item.first, item.second);
}

static std::string LabelFromValue(const UniValue& value)
{
    std::string label = value.get_str();
    if (label == "*")
        throw JSONRPCError(RPC_WALLET_INVALID_LABEL_NAME, "Invalid label name");
    return label;
}

/**
 * Update coin control with fee estimation based on the given parameters
 *
 * @param[in]     wallet            Wallet reference
 * @param[in,out] cc                Coin control to be updated
 * @param[in]     conf_target       UniValue integer; confirmation target in blocks, values between 1 and 1008 are valid per policy/fees.h;
 * @param[in]     estimate_mode     UniValue string; fee estimation mode, valid values are "unset", "economical" or "conservative";
 * @param[in]     fee_rate          UniValue real; fee rate in sat/vB;
 *                                      if present, both conf_target and estimate_mode must either be null, or "unset"
 * @param[in]     override_min_fee  bool; whether to set fOverrideFeeRate to true to disable minimum fee rate checks and instead
 *                                      verify only that fee_rate is greater than 0
 * @throws a JSONRPCError if conf_target, estimate_mode, or fee_rate contain invalid values or are in conflict
 */
static void SetFeeEstimateMode(const CWallet& wallet, CCoinControl& cc, const UniValue& conf_target, const UniValue& estimate_mode, const UniValue& fee_rate, bool override_min_fee)
{
    if (!fee_rate.isNull()) {
        if (!conf_target.isNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot specify both conf_target and fee_rate. Please provide either a confirmation target in blocks for automatic fee estimation, or an explicit fee rate.");
        }
        if (!estimate_mode.isNull() && estimate_mode.get_str() != "unset") {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot specify both estimate_mode and fee_rate");
        }
        cc.m_feerate = CFeeRate(AmountFromValue(fee_rate), COIN, 0);
        if (override_min_fee) cc.fOverrideFeeRate = true;
        // Default RBF to true for explicit fee_rate, if unset.
        if (cc.m_signal_bip125_rbf == nullopt) cc.m_signal_bip125_rbf = true;
        return;
    }
    if (!estimate_mode.isNull() && !FeeModeFromString(estimate_mode.get_str(), cc.m_fee_mode)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, InvalidEstimateModeErrorMessage());
    }
    if (!conf_target.isNull()) {
        cc.m_confirm_target = ParseConfirmTarget(conf_target, wallet.chain().estimateMaxBlocks());
    }
}

static RPCHelpMan getnewaddress()
{
    return RPCHelpMan{"getnewaddress",
                "\nReturns a new Litecoin address for receiving payments.\n"
                "If 'label' is specified, it is added to the address book \n"
                "so payments received with the address will be associated with 'label'.\n",
                {
                    {"label", RPCArg::Type::STR, /* default */ "\"\"", "The label name for the address to be linked to. It can also be set to the empty string \"\" to represent the default label. The label does not need to exist, it will be created if there is no label by the given name."},
                    {"address_type", RPCArg::Type::STR, /* default */ "set by -addresstype", "The address type to use. Options are \"legacy\", \"p2sh-segwit\", and \"bech32\", and \"mweb\"."},
                },
                RPCResult{
                    RPCResult::Type::STR, "address", "The new litecoin address"
                },
                RPCExamples{
                    HelpExampleCli("getnewaddress", "")
            + HelpExampleRpc("getnewaddress", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    LOCK(pwallet->cs_wallet);

    if (!pwallet->CanGetAddresses()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: This wallet has no available keys");
    }

    // Parse the label first so we don't generate a key if there's an error
    std::string label;
    if (!request.params[0].isNull())
        label = LabelFromValue(request.params[0]);

    OutputType output_type = pwallet->m_default_address_type;
    if (!request.params[1].isNull()) {
        if (!ParseOutputType(request.params[1].get_str(), output_type)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Unknown address type '%s'", request.params[1].get_str()));
        }
    }

    if (output_type == OutputType::MWEB) {
        EnsureWalletIsUnlocked(pwallet);

        // MW: TODO - Handle non-HD
    }

    CTxDestination dest;
    std::string error;
    if (!pwallet->GetNewDestination(output_type, label, dest, error)) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, error);
    }

    return EncodeDestination(dest);
},
    };
}

static RPCHelpMan getrawchangeaddress()
{
    return RPCHelpMan{"getrawchangeaddress",
                "\nReturns a new Litecoin address, for receiving change.\n"
                "This is for use with raw transactions, NOT normal use.\n",
                {
                    {"address_type", RPCArg::Type::STR, /* default */ "set by -changetype", "The address type to use. Options are \"legacy\", \"p2sh-segwit\", and \"bech32\"."},
                },
                RPCResult{
                    RPCResult::Type::STR, "address", "The address"
                },
                RPCExamples{
                    HelpExampleCli("getrawchangeaddress", "")
            + HelpExampleRpc("getrawchangeaddress", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    LOCK(pwallet->cs_wallet);

    if (!pwallet->CanGetAddresses(true)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: This wallet has no available keys");
    }

    OutputType output_type = pwallet->m_default_change_type.get_value_or(pwallet->m_default_address_type);
    if (!request.params[0].isNull()) {
        if (!ParseOutputType(request.params[0].get_str(), output_type)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Unknown address type '%s'", request.params[0].get_str()));
        }
    }

    if (output_type == OutputType::MWEB) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "MWEB address type not yet supported for raw transactions");
    }

    CTxDestination dest;
    std::string error;
    if (!pwallet->GetNewChangeDestination(output_type, dest, error)) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, error);
    }
    return EncodeDestination(dest);
},
    };
}

static RPCHelpMan setlabel()
{
    return RPCHelpMan{"setlabel",
                "\nSets the label associated with the given address.\n",
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The litecoin address to be associated with a label."},
                    {"label", RPCArg::Type::STR, RPCArg::Optional::NO, "The label to assign to the address."},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("setlabel", "\"" + EXAMPLE_ADDRESS[0] + "\" \"tabby\"")
            + HelpExampleRpc("setlabel", "\"" + EXAMPLE_ADDRESS[0] + "\", \"tabby\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    LOCK(pwallet->cs_wallet);

    CTxDestination dest = DecodeDestination(request.params[0].get_str());
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Litecoin address");
    }

    std::string label = LabelFromValue(request.params[1]);

    if (pwallet->IsMine(dest)) {
        pwallet->SetAddressBook(dest, label, "receive");
    } else {
        pwallet->SetAddressBook(dest, label, "send");
    }

    return NullUniValue;
},
    };
}

void ParseRecipients(const UniValue& address_amounts, const UniValue& subtract_fee_outputs, std::vector<CRecipient> &recipients) {
    std::set<CTxDestination> destinations;
    int i = 0;
    for (const std::string& address: address_amounts.getKeys()) {
        CTxDestination dest = DecodeDestination(address);
        if (!IsValidDestination(dest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Litecoin address: ") + address);
        }

        if (destinations.count(dest)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameter, duplicated address: ") + address);
        }
        destinations.insert(dest);

        DestinationAddr recipient_addr(dest);
        CAmount amount = AmountFromValue(address_amounts[i++]);

        bool subtract_fee = false;
        for (unsigned int idx = 0; idx < subtract_fee_outputs.size(); idx++) {
            const UniValue& addr = subtract_fee_outputs[idx];
            if (addr.get_str() == address) {
                subtract_fee = true;
            }
        }

        CRecipient recipient = {recipient_addr, amount, subtract_fee};
        recipients.push_back(recipient);
    }
}

static void ParseOutputsArray(const UniValue& outputs_in, std::vector<CRecipient>& recipients)
{
    RPCTypeCheckArgument(outputs_in, UniValue::VARR);

    std::set<CTxDestination> dests_seen;
    std::set<CScript> scripts_seen;

    for (size_t i = 0; i < outputs_in.size(); ++i) {
        const UniValue& out = outputs_in[i];
        RPCTypeCheckArgument(out, UniValue::VOBJ);

        // Require amount
        if (!out.exists("amount")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Output %u missing 'amount'", (unsigned)i));
        }
        const CAmount amount = AmountFromValue(out["amount"]);

        // Optional subtract_fee (default false)
        bool subtract_fee = false;
        if (out.exists("subtract_fee") && !out["subtract_fee"].isNull()) {
            subtract_fee = out["subtract_fee"].get_bool();
        }

        const bool has_addr = out.exists("address") && !out["address"].isNull();
        const bool has_script = out.exists("script") && !out["script"].isNull();
        if (has_addr == has_script) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                strprintf("Output %u must contain exactly one of 'address' or 'script'", (unsigned)i));
        }

        if (has_addr) {
            const std::string addr_str = out["address"].get_str();
            const CTxDestination dest = DecodeDestination(addr_str);
            if (!IsValidDestination(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Litecoin address: " + addr_str);
            }
            if (dests_seen.count(dest)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Duplicate address in outputs: " + addr_str);
            }
            dests_seen.insert(dest);

            DestinationAddr recipient_addr(dest);
            recipients.push_back({recipient_addr, amount, subtract_fee});
        } else {
            const std::string script_hex = out["script"].get_str();
            if (!IsHex(script_hex)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Output %u 'script' is not hex", (unsigned)i));
            }
            const CScript script = CScript(ParseHex(script_hex).begin(), ParseHex(script_hex).end());
            if (scripts_seen.count(script)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Duplicate script in outputs at index %u", (unsigned)i));
            }
            scripts_seen.insert(script);

            recipients.push_back({script, amount, subtract_fee});
        }
    }

    if (recipients.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "outputs array must not be empty");
    }
}

static void ParseDepositAmounts(const UniValue& amounts_in, const UniValue& subtract_fee_in, const CScript& deposit_script, std::vector<CRecipient>& recipients)
{
    RPCTypeCheckArgument(amounts_in, UniValue::VARR);
    if (amounts_in.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "amounts must be a non-empty array");
    }

    // Decide which outputs subtract fee
    bool subtract_all = false;
    std::set<size_t> subtract_indices;

    if (!subtract_fee_in.isNull()) {
        if (subtract_fee_in.isBool()) {
            subtract_all = subtract_fee_in.get_bool();
        } else if (subtract_fee_in.isArray()) {
            for (size_t i = 0; i < subtract_fee_in.size(); ++i) {
                const UniValue& v = subtract_fee_in[i];
                if (!v.isNum()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "subtract_fee array must contain numeric indices");
                }
                const int idx = v.get_int();
                if (idx < 0) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "subtract_fee indices must be >= 0");
                }
                subtract_indices.insert((size_t)idx);
            }
        } else {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "subtract_fee must be a boolean or an array of indices");
        }
    }

    recipients.clear();
    recipients.reserve(amounts_in.size());

    for (size_t i = 0; i < amounts_in.size(); ++i) {
        const CAmount amount = AmountFromValue(amounts_in[i]);
        if (amount <= 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "deposit amounts must be > 0");
        }

        const bool subtract_here = subtract_all || subtract_indices.count(i) > 0;
        recipients.push_back(CRecipient{deposit_script, amount, subtract_here});
    }

    // Validate indices in subtract_fee array (must be in-range)
    for (size_t idx : subtract_indices) {
        if (idx >= recipients.size()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "subtract_fee index out of range for amounts array");
        }
    }
}

static void ParseWithdrawalsArray( const UniValue& arr, std::vector<CRecipient>& out_recipients, CAmount& out_sum)
{
    RPCTypeCheckArgument(arr, UniValue::VARR);
    if (arr.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "withdrawals array must not be empty");
    }

    out_recipients.clear();
    out_recipients.reserve(arr.size());

    CAmount sum{0};

    for (size_t i = 0; i < arr.size(); ++i) {
        const UniValue& o = arr[i];
        RPCTypeCheckArgument(o, UniValue::VOBJ);

        if (!o.exists("amount")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("withdrawals[%u] missing amount", (unsigned)i));
        }
        const CAmount amt = AmountFromValue(o["amount"]);
        if (amt <= 0 || !MoneyRange(amt)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("withdrawals[%u] invalid amount", (unsigned)i));
        }

        const bool has_addr = o.exists("address") && !o["address"].isNull();
        const bool has_script = o.exists("script") && !o["script"].isNull();
        if (has_addr == has_script) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                strprintf("withdrawals[%u] must contain exactly one of address or script", (unsigned)i));
        }

        CScript spk;
        if (has_addr) {
            const std::string addr = o["address"].get_str();
            const CTxDestination dest = DecodeDestination(addr);
            if (!IsValidDestination(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address: " + addr);
            }
            spk = GetScriptForDestination(dest);
        } else {
            const std::string hex = o["script"].get_str();
            if (!IsHex(hex)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("withdrawals[%u] script is not hex", (unsigned)i));
            }
            const std::vector<unsigned char> bytes = ParseHex(hex);
            spk = CScript(bytes.begin(), bytes.end());
        }

        if (spk.size() > 255) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                strprintf("withdrawals[%u] scriptPubKey too long (max 255 bytes)", (unsigned)i));
        }

        // Never subtract fee from withdrawals.
        out_recipients.push_back({spk, amt, /*fSubtractFeeFromAmount=*/false});

        sum += amt;
        if (!MoneyRange(sum)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "withdrawal sum out of range");
        }
    }

    out_sum = sum;
}

static uint256 ComputeRpcScriptCommitment(const CScript& script);

static const ValiditySidechainAcceptedBatch* FindAcceptedValidityBatch(
    const ValiditySidechain& sidechain,
    uint32_t batch_number)
{
    const auto it = sidechain.accepted_batches.find(batch_number);
    return it == sidechain.accepted_batches.end() ? nullptr : &it->second;
}

static CScript ParseRpcPayoutScript(
    const UniValue& obj,
    const std::string& context)
{
    RPCTypeCheckArgument(obj, UniValue::VOBJ);

    const bool has_addr = obj.exists("address") && !obj["address"].isNull();
    const bool has_script = obj.exists("script") && !obj["script"].isNull();
    if (has_addr == has_script) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("%s must contain exactly one of address or script", context));
    }

    CScript script;
    if (has_addr) {
        const std::string addr = obj["address"].get_str();
        const CTxDestination dest = DecodeDestination(addr);
        if (!IsValidDestination(dest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address: " + addr);
        }
        script = GetScriptForDestination(dest);
    } else {
        const std::string hex = obj["script"].get_str();
        if (!IsHex(hex)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s script is not hex", context));
        }
        const std::vector<unsigned char> bytes = ParseHex(hex);
        script = CScript(bytes.begin(), bytes.end());
    }

    if (script.size() > 255) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("%s scriptPubKey too long (max 255 bytes)", context));
    }

    return script;
}

static void ParseValidityWithdrawalLeaves(
    const UniValue& arr,
    std::vector<ValiditySidechainWithdrawalLeaf>& out_withdrawals,
    std::vector<CRecipient>& out_recipients)
{
    RPCTypeCheckArgument(arr, UniValue::VARR);
    if (arr.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "withdrawals array must not be empty");
    }

    out_withdrawals.clear();
    out_withdrawals.reserve(arr.size());
    out_recipients.clear();
    out_recipients.reserve(arr.size());

    for (size_t i = 0; i < arr.size(); ++i) {
        const UniValue& obj = arr[i];
        RPCTypeCheckArgument(obj, UniValue::VOBJ);

        ValiditySidechainWithdrawalLeaf withdrawal;
        withdrawal.withdrawal_id = ParseHashO(obj, "withdrawal_id");
        withdrawal.amount = AmountFromValue(find_value(obj, "amount"));
        if (withdrawal.amount <= 0 || !MoneyRange(withdrawal.amount)) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                strprintf("withdrawals[%u] invalid amount", static_cast<unsigned>(i)));
        }

        const CScript script = ParseRpcPayoutScript(
            obj,
            strprintf("withdrawals[%u]", static_cast<unsigned>(i)));
        withdrawal.destination_commitment = ComputeRpcScriptCommitment(script);

        out_recipients.push_back({script, withdrawal.amount, /*subtract_fee=*/false});
        out_withdrawals.push_back(std::move(withdrawal));
    }
}

static void ParseValidityEscapeExitLeaves(
    const UniValue& arr,
    std::vector<ValiditySidechainEscapeExitLeaf>& out_exits,
    std::vector<CRecipient>& out_recipients)
{
    RPCTypeCheckArgument(arr, UniValue::VARR);
    if (arr.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "exits array must not be empty");
    }

    out_exits.clear();
    out_exits.reserve(arr.size());
    out_recipients.clear();
    out_recipients.reserve(arr.size());

    for (size_t i = 0; i < arr.size(); ++i) {
        const UniValue& obj = arr[i];
        RPCTypeCheckArgument(obj, UniValue::VOBJ);

        ValiditySidechainEscapeExitLeaf exit;
        exit.exit_id = ParseHashO(obj, "exit_id");
        exit.amount = AmountFromValue(find_value(obj, "amount"));
        if (exit.amount <= 0 || !MoneyRange(exit.amount)) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                strprintf("exits[%u] invalid amount", static_cast<unsigned>(i)));
        }

        const CScript script = ParseRpcPayoutScript(
            obj,
            strprintf("exits[%u]", static_cast<unsigned>(i)));
        exit.destination_commitment = ComputeRpcScriptCommitment(script);

        out_recipients.push_back({script, exit.amount, /*subtract_fee=*/false});
        out_exits.push_back(std::move(exit));
    }
}

UniValue SendMoney(CWallet* const pwallet, const CCoinControl &coin_control, std::vector<CRecipient> &recipients, mapValue_t map_value, bool verbose)
{
    EnsureWalletIsUnlocked(pwallet);

    // This function is only used by sendtoaddress and sendmany.
    // This should always try to sign, if we don't have private keys, don't try to do anything here.
    if (pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Private keys are disabled for this wallet");
    }

    // Shuffle recipient list
    std::shuffle(recipients.begin(), recipients.end(), FastRandomContext());

    // Send
    CAmount nFeeRequired = 0;
    int nChangePosRet = -1;
    bilingual_str error;
    CTransactionRef tx;
    FeeCalculation fee_calc_out;
    const bool fCreated = pwallet->CreateTransaction(recipients, tx, nFeeRequired, nChangePosRet, error, coin_control, fee_calc_out, true);
    if (!fCreated) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, error.original);
    }
    pwallet->CommitTransaction(tx, std::move(map_value), {} /* orderForm */);
    if (verbose) {
        UniValue entry(UniValue::VOBJ);
        entry.pushKV("txid", tx->GetHash().GetHex());
        entry.pushKV("fee_reason", StringForFeeReason(fee_calc_out.reason));
        return entry;
    }
    return tx->GetHash().GetHex();
}

static UniValue SendMoneyNoShuffle(
    CWallet* const pwallet,
    const CCoinControl& coin_control,
    std::vector<CRecipient>& recipients,
    mapValue_t map_value,
    bool verbose,
    bool preflight_mempool_accept = true)
{
    EnsureWalletIsUnlocked(pwallet);
    if (pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Private keys are disabled for this wallet");
    }

    // IMPORTANT: no shuffle here

    CAmount nFeeRequired = 0;
    // Keep change output after caller-provided outputs.
    // This preserves recipient ordering for consensus-sensitive outputs (e.g. Drivechain EXECUTE).
    int nChangePosRet = (int)recipients.size();
    bilingual_str error;
    CTransactionRef tx;
    FeeCalculation fee_calc_out;

    const bool fCreated = pwallet->CreateTransaction(
        recipients, tx, nFeeRequired, nChangePosRet, error, coin_control, fee_calc_out, /*sign=*/true);

    if (!fCreated) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, error.original);
    }

    // Preflight mempool acceptance so callers get immediate RPC errors for
    // policy/consensus rejections instead of a txid that failed broadcast.
    if (preflight_mempool_accept && pwallet->GetBroadcastTransactions()) {
        std::string err_string;
        if (!pwallet->chain().broadcastTransaction(tx, pwallet->m_default_max_tx_fee, /*relay=*/false, err_string)) {
            throw JSONRPCError(RPC_TRANSACTION_REJECTED, err_string);
        }
    }

    pwallet->CommitTransaction(tx, std::move(map_value), {});

    if (verbose) {
        UniValue entry(UniValue::VOBJ);
        entry.pushKV("txid", tx->GetHash().GetHex());
        entry.pushKV("fee_reason", StringForFeeReason(fee_calc_out.reason));
        return entry;
    }
    return tx->GetHash().GetHex();
}

static std::string SendToDrivechainOutputs(
    CWallet& wallet,
    std::vector<CRecipient>& recipients,
    CCoinControl& coin_control,
    bool preflight_mempool_accept = true)
{
    CTransactionRef tx;
    CAmount fee_ret = 0;
    int change_pos = -1;
    bilingual_str error;
    FeeCalculation fee_calc;

    if (!wallet.CreateTransaction(recipients, tx, fee_ret, change_pos, error, coin_control, fee_calc, /*sign=*/true)) {
        throw JSONRPCError(RPC_WALLET_ERROR, error.original);
    }

    if (preflight_mempool_accept && wallet.GetBroadcastTransactions()) {
        std::string err_string;
        if (!wallet.chain().broadcastTransaction(tx, wallet.m_default_max_tx_fee, /*relay=*/false, err_string)) {
            throw JSONRPCError(RPC_TRANSACTION_REJECTED, err_string);
        }
    }

    wallet.CommitTransaction(tx, /*mapValue=*/{}, /*orderForm=*/{});
    return tx->GetHash().GetHex();
}

static std::string SendToDrivechainScript(
    CWallet& wallet,
    const CScript& script,
    CAmount amount,
    CCoinControl& coin_control,
    bool subtract_fee_from_amount,
    bool preflight_mempool_accept = true)
{
    std::vector<CRecipient> recipients;
    recipients.push_back(CRecipient{script, amount, subtract_fee_from_amount});
    return SendToDrivechainOutputs(wallet, recipients, coin_control, preflight_mempool_accept);
}

static bool IsDrivechainRegisterSidechainExistsError(const UniValue& err)
{
    if (!err.isObject()) return false;

    const UniValue& code = find_value(err, "code");
    const UniValue& message = find_value(err, "message");
    if (!code.isNum() || !message.isStr()) return false;

    return code.get_int() == RPC_TRANSACTION_REJECTED &&
           message.get_str().find("drivechain-register-sidechain-exists") != std::string::npos;
}

struct DrivechainOwnerKeyEntry
{
    CKey key;
    uint256 key_hash;
};

static void PushDrivechainPolicyResult(UniValue& out, const DrivechainSidechainPolicy& policy)
{
    const uint256 policy_hash = ComputeDrivechainSidechainPolicyHash(policy);
    out.pushKV("policy_hash", policy_hash.GetHex());
    out.pushKV("policy_hash_payload", HexStr(std::vector<unsigned char>(policy_hash.begin(), policy_hash.end())));
    out.pushKV("auth_threshold", static_cast<int>(policy.auth_threshold));

    UniValue owner_key_hashes(UniValue::VARR);
    UniValue owner_key_hashes_payload(UniValue::VARR);
    for (const uint256& key_hash : policy.owner_key_hashes) {
        owner_key_hashes.push_back(key_hash.GetHex());
        owner_key_hashes_payload.push_back(HexStr(std::vector<unsigned char>(key_hash.begin(), key_hash.end())));
    }
    out.pushKV("owner_key_hashes", owner_key_hashes);
    out.pushKV("owner_key_hashes_payload", owner_key_hashes_payload);
    out.pushKV("max_escrow_amount", policy.max_escrow_amount);
    out.pushKV("max_bundle_withdrawal", policy.max_bundle_withdrawal);

    if (policy.owner_key_hashes.size() == 1) {
        const uint256& owner_key_hash = policy.owner_key_hashes.front();
        out.pushKV("owner_key_hash", owner_key_hash.GetHex());
        out.pushKV("owner_key_hash_payload", HexStr(std::vector<unsigned char>(owner_key_hash.begin(), owner_key_hash.end())));
    }
}

static CScript BuildDrivechainRegisterScript(
    uint8_t scid,
    const DrivechainSidechainPolicy& policy,
    const std::vector<std::vector<unsigned char>>& auth_sigs)
{
    const std::vector<unsigned char> scid_v{scid};
    const uint256 policy_hash = ComputeDrivechainSidechainPolicyHash(policy);
    const std::vector<unsigned char> payload(policy_hash.begin(), policy_hash.end());
    const std::vector<unsigned char> tag{0x05};
    const std::vector<unsigned char> encoded_policy = EncodeDrivechainSidechainPolicy(policy);

    CScript script;
    script << OP_RETURN << OP_DRIVECHAIN << scid_v << payload << tag << encoded_policy;
    for (const auto& auth_sig : auth_sigs) {
        if (!auth_sig.empty()) {
            script << auth_sig;
        }
    }
    return script;
}

static CScript BuildDrivechainBundleScript(
    uint8_t scid,
    const uint256& bundle_hash,
    const std::vector<std::vector<unsigned char>>& auth_sigs)
{
    const std::vector<unsigned char> scid_v{scid};
    const std::vector<unsigned char> payload(bundle_hash.begin(), bundle_hash.end());
    const std::vector<unsigned char> tag{0x01};

    CScript script;
    script << OP_RETURN << OP_DRIVECHAIN << scid_v << payload << tag;
    for (const auto& auth_sig : auth_sigs) {
        if (!auth_sig.empty()) {
            script << auth_sig;
        }
    }
    return script;
}

static void GetDrivechainOwnerKeyEntryFromWalletAddress(
    const CWallet& wallet,
    const std::string& owner_address,
    DrivechainOwnerKeyEntry& out_entry)
{
    const CTxDestination dest = DecodeDestination(owner_address);
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "owner_address must be a valid wallet address");
    }

    const DestinationAddr dest_addr(dest);
    ScriptPubKeyMan* const spk_man = wallet.GetScriptPubKeyMan(dest_addr);
    if (spk_man == nullptr) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "owner_address must belong to this wallet");
    }

    std::unique_ptr<SigningProvider> solving_provider = wallet.GetSolvingProvider(dest_addr);
    if (!solving_provider) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "owner_address must refer to a single-key address");
    }

    const CKeyID key_id = GetKeyForDestination(*solving_provider, dest);
    if (key_id.IsNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "owner_address must refer to a single-key address");
    }

    CPubKey owner_pubkey;
    if (!spk_man->GetKeyForDestination(dest, out_entry.key, owner_pubkey)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "owner_address private key is not available in this wallet");
    }

    if (!owner_pubkey.IsValid() || !owner_pubkey.IsCompressed()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "owner_address must resolve to a valid compressed public key");
    }

    const std::vector<unsigned char> owner_pubkey_bytes(owner_pubkey.begin(), owner_pubkey.end());
    out_entry.key_hash = Hash(owner_pubkey_bytes);
}

static std::vector<DrivechainOwnerKeyEntry> GetDrivechainOwnerKeyEntriesFromWalletParam(
    const CWallet& wallet,
    const UniValue& owner_param)
{
    std::vector<std::string> owner_addresses;
    if (owner_param.isStr()) {
        const std::string owner_arg = owner_param.get_str();
        UniValue parsed_owner_array;
        if (!owner_arg.empty() && owner_arg.front() == '[' &&
            parsed_owner_array.read(owner_arg) && parsed_owner_array.isArray()) {
            for (size_t i = 0; i < parsed_owner_array.size(); ++i) {
                if (!parsed_owner_array[i].isStr()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "owner_addresses array must contain only wallet address strings");
                }
                owner_addresses.push_back(parsed_owner_array[i].get_str());
            }
        } else {
            owner_addresses.push_back(owner_arg);
        }
    } else if (owner_param.isArray()) {
        for (size_t i = 0; i < owner_param.size(); ++i) {
            if (!owner_param[i].isStr()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "owner_addresses array must contain only wallet address strings");
            }
            owner_addresses.push_back(owner_param[i].get_str());
        }
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "owner_addresses must be a wallet address or an array of wallet addresses");
    }

    if (owner_addresses.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "owner_addresses must not be empty");
    }
    if (owner_addresses.size() > MAX_DRIVECHAIN_OWNER_KEYS) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("owner_addresses must contain at most %u entries", MAX_DRIVECHAIN_OWNER_KEYS));
    }

    std::vector<DrivechainOwnerKeyEntry> owner_keys;
    owner_keys.reserve(owner_addresses.size());
    for (const std::string& owner_address : owner_addresses) {
        DrivechainOwnerKeyEntry entry;
        GetDrivechainOwnerKeyEntryFromWalletAddress(wallet, owner_address, entry);
        owner_keys.push_back(std::move(entry));
    }

    std::sort(owner_keys.begin(), owner_keys.end(), [](const DrivechainOwnerKeyEntry& a, const DrivechainOwnerKeyEntry& b) {
        return a.key_hash < b.key_hash;
    });

    for (size_t i = 1; i < owner_keys.size(); ++i) {
        if (owner_keys[i - 1].key_hash == owner_keys[i].key_hash) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "owner_addresses must resolve to distinct public keys");
        }
    }

    return owner_keys;
}

static std::vector<std::vector<unsigned char>> SignDrivechainAuthMessage(
    const std::vector<DrivechainOwnerKeyEntry>& owner_keys,
    const uint256& auth_msg,
    const char* failure_message)
{
    std::vector<std::vector<unsigned char>> auth_sigs;
    auth_sigs.reserve(owner_keys.size());
    for (const DrivechainOwnerKeyEntry& owner_key : owner_keys) {
        std::vector<unsigned char> auth_sig;
        if (!owner_key.key.SignCompact(auth_msg, auth_sig)) {
            throw JSONRPCError(RPC_WALLET_ERROR, failure_message);
        }
        auth_sigs.push_back(std::move(auth_sig));
    }
    return auth_sigs;
}

static DrivechainSidechainPolicy BuildDrivechainSidechainPolicy(
    const std::vector<DrivechainOwnerKeyEntry>& owner_keys,
    int auth_threshold,
    CAmount max_escrow_amount,
    CAmount max_bundle_withdrawal)
{
    if (auth_threshold <= 0 || auth_threshold > owner_keys.size() || auth_threshold > MAX_DRIVECHAIN_OWNER_KEYS) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "auth_threshold must be between 1 and the number of owner keys");
    }
    if (max_escrow_amount <= 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "max_escrow_amount must be greater than 0");
    }
    if (max_bundle_withdrawal <= 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "max_bundle_withdrawal must be greater than 0");
    }
    if (max_bundle_withdrawal > max_escrow_amount) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "max_bundle_withdrawal must not exceed max_escrow_amount");
    }

    DrivechainSidechainPolicy policy;
    policy.auth_threshold = static_cast<uint8_t>(auth_threshold);
    policy.max_escrow_amount = max_escrow_amount;
    policy.max_bundle_withdrawal = max_bundle_withdrawal;
    policy.owner_key_hashes.reserve(owner_keys.size());
    for (const DrivechainOwnerKeyEntry& owner_key : owner_keys) {
        policy.owner_key_hashes.push_back(owner_key.key_hash);
    }
    return policy;
}

static std::pair<std::string, uint8_t> SendDrivechainRegisterWithAutoId(
    CWallet& wallet,
    const std::vector<DrivechainOwnerKeyEntry>& owner_keys,
    const DrivechainSidechainPolicy& policy,
    CAmount amount,
    bool subtract_fee_from_amount)
{
    for (int scid_i = 0; scid_i <= 255; ++scid_i) {
        const uint8_t sidechain_id = static_cast<uint8_t>(scid_i);
        const uint256 auth_msg = ComputeDrivechainRegisterAuthMessage(
            sidechain_id,
            ComputeDrivechainSidechainPolicyHash(policy));
        const std::vector<std::vector<unsigned char>> auth_sigs = SignDrivechainAuthMessage(
            owner_keys,
            auth_msg,
            "failed to create registration authorization signature");
        const CScript register_script = BuildDrivechainRegisterScript(sidechain_id, policy, auth_sigs);
        CCoinControl coin_control;
        try {
            const std::string txid = SendToDrivechainScript(
                wallet,
                register_script,
                amount,
                coin_control,
                subtract_fee_from_amount);
            return {txid, sidechain_id};
        } catch (const UniValue& err) {
            if (IsDrivechainRegisterSidechainExistsError(err)) continue;
            throw;
        }
    }

    throw JSONRPCError(RPC_INVALID_PARAMETER, "No unused sidechain_id available (all 0-255 are in use)");
}

static uint8_t ParseUint8Value(const UniValue& value, const std::string& field_name)
{
    const int value_int = value.get_int();
    if (value_int < 0 || value_int > std::numeric_limits<uint8_t>::max()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, field_name + " must be between 0 and 255");
    }
    return static_cast<uint8_t>(value_int);
}

static uint32_t ParseUint32Value(const UniValue& value, const std::string& field_name)
{
    const int64_t value_int = value.get_int64();
    if (value_int < 0 || value_int > std::numeric_limits<uint32_t>::max()) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("%s must be between 0 and %u", field_name, std::numeric_limits<uint32_t>::max()));
    }
    return static_cast<uint32_t>(value_int);
}

static uint64_t ParseUint64Value(const UniValue& value, const std::string& field_name)
{
    const int64_t value_int = value.get_int64();
    if (value_int < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, field_name + " must be non-negative");
    }
    return static_cast<uint64_t>(value_int);
}

static CScript ParseRpcScriptObject(const UniValue& obj, const std::string& context)
{
    RPCTypeCheckArgument(obj, UniValue::VOBJ);

    const bool has_address = obj.exists("address") && !obj["address"].isNull();
    const bool has_script = obj.exists("script") && !obj["script"].isNull();
    if (has_address == has_script) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            context + " must contain exactly one of address or script");
    }

    if (has_address) {
        const std::string address = obj["address"].get_str();
        const CTxDestination dest = DecodeDestination(address);
        if (!IsValidDestination(dest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Litecoin address: " + address);
        }
        return GetScriptForDestination(dest);
    }

    const std::string script_hex = obj["script"].get_str();
    if (!IsHex(script_hex)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, context + " script is not hex");
    }

    const std::vector<unsigned char> bytes = ParseHex(script_hex);
    return CScript(bytes.begin(), bytes.end());
}

static uint256 ComputeRpcScriptCommitment(const CScript& script)
{
    return Hash(script);
}

static bool GetValiditySidechainFromChain(CWallet& wallet, uint8_t sidechain_id, ValiditySidechain& out_sidechain)
{
    if (!wallet.HaveChain()) {
        return false;
    }

    for (const auto& sidechain : wallet.chain().getValiditySidechains()) {
        if (sidechain.id == sidechain_id) {
            out_sidechain = sidechain;
            return true;
        }
    }

    return false;
}

static bool HasValiditySidechainInChain(CWallet& wallet, uint8_t sidechain_id)
{
    ValiditySidechain sidechain;
    return GetValiditySidechainFromChain(wallet, sidechain_id, sidechain);
}

static bool IsSidechainIdInUse(CWallet& wallet, uint8_t sidechain_id)
{
    if (!wallet.HaveChain()) {
        return false;
    }

    bool owner_auth_required = false;
    DrivechainSidechainPolicy policy;
    if (wallet.chain().getDrivechainSidechain(sidechain_id, owner_auth_required, policy)) {
        return true;
    }

    return HasValiditySidechainInChain(wallet, sidechain_id);
}

static ValiditySidechainConfig ParseValiditySidechainConfigObject(const UniValue& obj)
{
    RPCTypeCheckArgument(obj, UniValue::VOBJ);

    ValiditySidechainConfig config;
    config.version = ParseUint8Value(find_value(obj, "version"), "config.version");
    config.proof_system_id = ParseUint8Value(find_value(obj, "proof_system_id"), "config.proof_system_id");
    config.circuit_family_id = ParseUint8Value(find_value(obj, "circuit_family_id"), "config.circuit_family_id");
    config.verifier_id = ParseUint8Value(find_value(obj, "verifier_id"), "config.verifier_id");
    config.public_input_version = ParseUint8Value(find_value(obj, "public_input_version"), "config.public_input_version");
    config.state_root_format = ParseUint8Value(find_value(obj, "state_root_format"), "config.state_root_format");
    config.deposit_message_format = ParseUint8Value(find_value(obj, "deposit_message_format"), "config.deposit_message_format");
    config.withdrawal_leaf_format = ParseUint8Value(find_value(obj, "withdrawal_leaf_format"), "config.withdrawal_leaf_format");
    config.balance_leaf_format = ParseUint8Value(find_value(obj, "balance_leaf_format"), "config.balance_leaf_format");
    config.data_availability_mode = ParseUint8Value(find_value(obj, "data_availability_mode"), "config.data_availability_mode");
    config.max_batch_data_bytes = ParseUint32Value(find_value(obj, "max_batch_data_bytes"), "config.max_batch_data_bytes");
    config.max_proof_bytes = ParseUint32Value(find_value(obj, "max_proof_bytes"), "config.max_proof_bytes");
    config.force_inclusion_delay = ParseUint32Value(find_value(obj, "force_inclusion_delay"), "config.force_inclusion_delay");
    config.deposit_reclaim_delay = ParseUint32Value(find_value(obj, "deposit_reclaim_delay"), "config.deposit_reclaim_delay");
    config.escape_hatch_delay = ParseUint32Value(find_value(obj, "escape_hatch_delay"), "config.escape_hatch_delay");
    config.initial_state_root = ParseHashO(obj, "initial_state_root");
    config.initial_withdrawal_root = ParseHashO(obj, "initial_withdrawal_root");
    return config;
}

static ValiditySidechainBatchPublicInputs ParseValiditySidechainBatchPublicInputsObject(const UniValue& obj)
{
    RPCTypeCheckArgument(obj, UniValue::VOBJ);

    ValiditySidechainBatchPublicInputs public_inputs;
    public_inputs.batch_number = ParseUint32Value(find_value(obj, "batch_number"), "public_inputs.batch_number");
    public_inputs.prior_state_root = ParseHashO(obj, "prior_state_root");
    public_inputs.new_state_root = ParseHashO(obj, "new_state_root");
    public_inputs.l1_message_root_before = ParseHashO(obj, "l1_message_root_before");
    public_inputs.l1_message_root_after = ParseHashO(obj, "l1_message_root_after");
    public_inputs.consumed_queue_messages = ParseUint32Value(
        find_value(obj, "consumed_queue_messages"),
        "public_inputs.consumed_queue_messages");
    const UniValue& queue_prefix_commitment = find_value(obj, "queue_prefix_commitment");
    public_inputs.queue_prefix_commitment = queue_prefix_commitment.isNull()
        ? uint256()
        : ParseHashO(obj, "queue_prefix_commitment");
    public_inputs.withdrawal_root = ParseHashO(obj, "withdrawal_root");
    public_inputs.data_root = ParseHashO(obj, "data_root");
    public_inputs.data_size = ParseUint32Value(find_value(obj, "data_size"), "public_inputs.data_size");
    return public_inputs;
}

static std::vector<std::vector<unsigned char>> ParseHexArray(const UniValue& arr, const std::string& field_name)
{
    RPCTypeCheckArgument(arr, UniValue::VARR);

    std::vector<std::vector<unsigned char>> out;
    out.reserve(arr.size());
    for (size_t i = 0; i < arr.size(); ++i) {
        out.push_back(ParseHexV(arr[i], strprintf("%s[%u]", field_name, static_cast<unsigned>(i))));
    }
    return out;
}

static RPCHelpMan senddrivechainregister()
{
    return RPCHelpMan{
        "senddrivechainregister",
        "Create, fund, sign and broadcast a Drivechain REGISTER transaction.\n"
        "This is the secure sidechain ownership path: the wallet signs the registration binding with one or more wallet-held owner keys.\n"
        "Owner keys are canonicalized by key hash before the sidechain policy hash is computed.\n"
        "If sidechain_id is omitted, the wallet picks the lowest currently unused id from 0-255.\n",
        std::vector<RPCArg>{
            {"owner_addresses", RPCArg::Type::STR, RPCArg::Optional::NO, "Wallet owner address, or a JSON array of wallet owner addresses, whose compressed public keys become the registered owner policy"},
            {"sidechain_id", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Optional sidechain id (0-255). If omitted, lowest unused id is selected."},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "Amount to attach to register output (default: 1.0)"},
            {"subtractfeefromamount", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Subtract fee from amount (default: false)"},
            {"auth_threshold", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Required distinct owner signatures. Default: number of owner keys provided."},
            {"max_escrow_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "Maximum total escrow balance allowed for this sidechain (default: network MAX_MONEY)."},
            {"max_bundle_withdrawal", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "Maximum withdrawal amount allowed in a single EXECUTE bundle (default: max_escrow_amount)."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
                {RPCResult::Type::NUM, "sidechain_id", "Registered sidechain id"},
                {RPCResult::Type::STR_HEX, "policy_hash", "Sidechain policy hash in RPC uint256 display format"},
                {RPCResult::Type::STR_HEX, "policy_hash_payload", "Sidechain policy hash in raw script payload byte order"},
                {RPCResult::Type::NUM, "auth_threshold", "Required distinct owner signatures"},
                {RPCResult::Type::NUM, "max_escrow_amount", "Maximum total escrow balance in satoshis"},
                {RPCResult::Type::NUM, "max_bundle_withdrawal", "Maximum per-bundle withdrawal in satoshis"},
                {RPCResult::Type::STR_HEX, "owner_key_hash", "Legacy single-owner compatibility field. Present only for 1-of-1 policies."},
                {RPCResult::Type::STR_HEX, "owner_key_hash_payload", "Legacy single-owner compatibility field in raw script payload byte order."},
            }},
        RPCExamples{
            HelpExampleCli("senddrivechainregister",
                "\"rltc1q...\"") +
            HelpExampleCli("senddrivechainregister",
                "\"[\\\"rltc1q...\\\",\\\"rltc1q...\\\"]\" 7 1.0 false 2 100.0 25.0") +
            HelpExampleRpc("senddrivechainregister",
                "[\"rltc1q...\",\"rltc1q...\"], 7, 1.0, false, 2, 100.0, 25.0")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) return NullUniValue;
            CWallet* const pwallet = wallet.get();

            Optional<uint8_t> maybe_sidechain_id;
            if (request.params.size() > 1 && !request.params[1].isNull()) {
                const int scid_i = request.params[1].get_int();
                if (scid_i < 0 || scid_i > 255) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "sidechain_id must be between 0 and 255");
                }
                maybe_sidechain_id = static_cast<uint8_t>(scid_i);
            }

            CAmount amount = COIN;
            if (request.params.size() > 2 && !request.params[2].isNull()) {
                amount = AmountFromValue(request.params[2]);
            }
            const CAmount min_register_amount = Params().GetConsensus().nDrivechainMinRegisterAmount;
            if (amount < min_register_amount) {
                throw JSONRPCError(
                    RPC_INVALID_PARAMETER,
                    strprintf("amount must be at least %s LTC", FormatMoney(min_register_amount)));
            }

            bool subtract_fee_from_amount = false;
            if (request.params.size() > 3 && !request.params[3].isNull()) {
                subtract_fee_from_amount = request.params[3].get_bool();
            }

            LOCK(pwallet->cs_wallet);
            EnsureWalletIsUnlocked(pwallet);

            const std::vector<DrivechainOwnerKeyEntry> owner_keys =
                GetDrivechainOwnerKeyEntriesFromWalletParam(*pwallet, request.params[0]);

            int auth_threshold = owner_keys.size();
            if (request.params.size() > 4 && !request.params[4].isNull()) {
                auth_threshold = request.params[4].get_int();
            }

            CAmount max_escrow_amount = MAX_MONEY;
            if (request.params.size() > 5 && !request.params[5].isNull()) {
                max_escrow_amount = AmountFromValue(request.params[5]);
            }

            CAmount max_bundle_withdrawal = max_escrow_amount;
            if (request.params.size() > 6 && !request.params[6].isNull()) {
                max_bundle_withdrawal = AmountFromValue(request.params[6]);
            }

            const DrivechainSidechainPolicy policy = BuildDrivechainSidechainPolicy(
                owner_keys,
                auth_threshold,
                max_escrow_amount,
                max_bundle_withdrawal);

            std::string txid;
            uint8_t sidechain_id = 0;

            if (maybe_sidechain_id) {
                sidechain_id = *maybe_sidechain_id;
                const uint256 auth_msg = ComputeDrivechainRegisterAuthMessage(
                    sidechain_id,
                    ComputeDrivechainSidechainPolicyHash(policy));
                const std::vector<std::vector<unsigned char>> auth_sigs = SignDrivechainAuthMessage(
                    owner_keys,
                    auth_msg,
                    "failed to create registration authorization signature");
                const CScript register_script = BuildDrivechainRegisterScript(sidechain_id, policy, auth_sigs);
                CCoinControl coin_control;
                txid = SendToDrivechainScript(*pwallet, register_script, amount, coin_control, subtract_fee_from_amount);
            } else {
                std::pair<std::string, uint8_t> auto_result = SendDrivechainRegisterWithAutoId(
                    *pwallet,
                    owner_keys,
                    policy,
                    amount,
                    subtract_fee_from_amount);
                txid = std::move(auto_result.first);
                sidechain_id = auto_result.second;
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("txid", txid);
            result.pushKV("sidechain_id", static_cast<int>(sidechain_id));
            PushDrivechainPolicyResult(result, policy);
            return result;
        },
    };
}

static RPCHelpMan senddrivechaindeposit()
{
    return RPCHelpMan{
        "senddrivechaindeposit",
        "Create, fund, sign and broadcast a Drivechain DEPOSIT transaction.\n"
        "This RPC only creates drivechain deposit outputs (script generated internally).\n"
        "You may specify multiple deposit outputs in one transaction.\n"
        "The sidechain must already be registered and confirmed on-chain before deposits are accepted.\n",
        std::vector<RPCArg>{
            {"sidechain_id", RPCArg::Type::NUM, RPCArg::Optional::NO, "Sidechain id (0-255)"},
            {"payload", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte payload hex (64 hex chars)"},
            {"amounts", RPCArg::Type::ARR, RPCArg::Optional::NO, "Array of deposit amounts (LTC)",
                {
                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "Deposit amount"}
                }
            },
            {"subtract_fee", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Subtract fee from all deposit outputs (default: false)."},
        },
        RPCResult{RPCResult::Type::STR_HEX, "txid", "The transaction id"},
        RPCExamples{
            HelpExampleCli("senddrivechaindeposit",
                "1 0000000000000000000000000000000000000000000000000000000000000000 \"[0.5, 1.25]\"") +
            HelpExampleCli("senddrivechaindeposit",
                "1 0000000000000000000000000000000000000000000000000000000000000000 \"[0.5, 1.25]\" true") +
            HelpExampleCli("senddrivechaindeposit",
                "1 0000000000000000000000000000000000000000000000000000000000000000 \"[0.5, 1.25]\" \"[0]\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) return NullUniValue;
            CWallet* const pwallet = wallet.get();

            const int scid_i = request.params[0].get_int();
            if (scid_i < 0 || scid_i > 255) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "sidechain_id must be between 0 and 255");
            }
            const uint8_t scid = static_cast<uint8_t>(scid_i);

            const std::string payload_hex = request.params[1].get_str();
            if (!IsHex(payload_hex) || payload_hex.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "payload must be 32 bytes (64 hex chars)");
            }
            const std::vector<unsigned char> payload = ParseHex(payload_hex);

            CScript deposit_script;
            deposit_script << OP_RETURN
                        << OP_DRIVECHAIN
                        << std::vector<unsigned char>{scid}
                        << payload
                        << std::vector<unsigned char>{0x00};

            const UniValue subtract_fee =
                request.params.size() > 3 ? request.params[3] : UniValue();

            std::vector<CRecipient> recipients;
            ParseDepositAmounts(request.params[2], subtract_fee, deposit_script, recipients);

            CCoinControl coin_control;

            LOCK(pwallet->cs_wallet);
            const std::string txid = SendToDrivechainOutputs(*pwallet, recipients, coin_control);
            return txid;
        },
    };
}

static RPCHelpMan senddrivechainbundle()
{
    return RPCHelpMan{
        "senddrivechainbundle",
        "DEPRECATED legacy RPC.\n"
        "Create, fund, sign and broadcast a drivechain BUNDLE_COMMIT transaction.\n"
        "This remains available only while the legacy drivechain withdrawal path is still active.\n"
        "This publishes a bundle hash for a sidechain.\n"
        "The sidechain must already exist (created by a prior confirmed REGISTER).\n"
        "Commit outputs are always created with zero value to avoid burning funds.\n",
        {
            {"sidechain_id", RPCArg::Type::NUM, RPCArg::Optional::NO, "Sidechain id (0-255)"},
            {"bundle_hash",  RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte bundle hash"},
            {"owner_addresses", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Wallet owner address, or a JSON array of wallet owner addresses, used to sign the owner authorization. Required when the registered sidechain has owner auth enabled."},
        },
        RPCResult{
            RPCResult::Type::STR_HEX, "txid", "The transaction id"
        },
        RPCExamples{
            HelpExampleCli("senddrivechainbundle",
                           "1 0000000000000000000000000000000000000000000000000000000000000000 \"rltc1q...\"") +
            HelpExampleCli("senddrivechainbundle",
                           "1 0000000000000000000000000000000000000000000000000000000000000000 "
                           "\"[\\\"rltc1q...\\\",\\\"rltc1q...\\\"]\"") +
            HelpExampleRpc("senddrivechainbundle",
                           "1, \"0000...0000\", [\"rltc1q...\", \"rltc1q...\"]")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) return NullUniValue;
            CWallet* const pwallet = wallet.get();

            if (request.params.size() < 2) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Missing parameters");
            }

            int sidechain_id_int = request.params[0].get_int();
            if (sidechain_id_int < 0 || sidechain_id_int > 255) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "sidechain_id must be between 0 and 255");
            }
            uint8_t sidechain_id = static_cast<uint8_t>(sidechain_id_int);

            const uint256 bundle_hash = ParseHashV(request.params[1], "bundle_hash");
            const bool owner_addresses_provided = request.params.size() > 2 && !request.params[2].isNull();
            bool owner_auth_required = false;
            DrivechainSidechainPolicy registered_policy;
            if (pwallet->HaveChain()) {
                if (pwallet->chain().getDrivechainSidechain(sidechain_id, owner_auth_required, registered_policy) &&
                    owner_auth_required) {
                    if (!owner_addresses_provided) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "owner_addresses are required for registered sidechains with owner auth");
                    }
                }
            }

            std::vector<std::vector<unsigned char>> auth_sigs;
            if (owner_addresses_provided) {
                LOCK(pwallet->cs_wallet);
                EnsureWalletIsUnlocked(pwallet);

                const std::vector<DrivechainOwnerKeyEntry> owner_keys =
                    GetDrivechainOwnerKeyEntriesFromWalletParam(*pwallet, request.params[2]);

                if (owner_auth_required) {
                    if (owner_keys.size() < registered_policy.auth_threshold) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "owner_addresses do not satisfy the registered auth_threshold");
                    }
                    for (const DrivechainOwnerKeyEntry& owner_key : owner_keys) {
                        if (std::find(
                                registered_policy.owner_key_hashes.begin(),
                                registered_policy.owner_key_hashes.end(),
                                owner_key.key_hash) == registered_policy.owner_key_hashes.end()) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "owner_addresses contain a key that is not part of the registered owner policy");
                        }
                    }
                }

                const uint256 auth_msg = ComputeDrivechainBundleAuthMessage(sidechain_id, bundle_hash);
                auth_sigs = SignDrivechainAuthMessage(
                    owner_keys,
                    auth_msg,
                    "failed to create owner authorization signature");
            }

            const CScript script = BuildDrivechainBundleScript(sidechain_id, bundle_hash, auth_sigs);

            CCoinControl coin_control;

            LOCK(pwallet->cs_wallet);
            std::string txid = SendToDrivechainScript(*pwallet, script, /*amount=*/0, coin_control, /*subtract_fee_from_amount=*/false);
            return txid;
        },
    };
}

static RPCHelpMan senddrivechainbmmrequest()
{
    return RPCHelpMan{
        "senddrivechainbmmrequest",
        "Create, fund, sign and broadcast a drivechain BMM_REQUEST transaction.\n"
        "This publishes a BIP301 sidechain block request for the current mainchain tip.\n",
        {
            {"sidechain_id", RPCArg::Type::NUM, RPCArg::Optional::NO, "Sidechain id (0-255)"},
            {"side_block_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte sidechain block hash"},
            {"prev_main_block_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Expected previous mainchain block hash"},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "Amount to attach to request output (default: 0)"},
            {"subtractfeefromamount", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Subtract fee from amount (default: false)"},
        },
        RPCResult{
            RPCResult::Type::STR_HEX, "txid", "The transaction id"
        },
        RPCExamples{
            HelpExampleCli("senddrivechainbmmrequest",
                           "1 1111111111111111111111111111111111111111111111111111111111111111 "
                           "2222222222222222222222222222222222222222222222222222222222222222") +
            HelpExampleRpc("senddrivechainbmmrequest",
                           "1, \"1111...1111\", \"2222...2222\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) return NullUniValue;
            CWallet* const pwallet = wallet.get();

            if (request.params.size() < 3) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Missing parameters");
            }

            const int sidechain_id_int = request.params[0].get_int();
            if (sidechain_id_int < 0 || sidechain_id_int > 255) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "sidechain_id must be between 0 and 255");
            }
            const uint8_t sidechain_id = static_cast<uint8_t>(sidechain_id_int);

            const uint256 side_block_hash = ParseHashV(request.params[1], "side_block_hash");
            const uint256 prev_main_block_hash = ParseHashV(request.params[2], "prev_main_block_hash");

            CAmount amount = 0;
            if (request.params.size() > 3 && !request.params[3].isNull()) {
                amount = AmountFromValue(request.params[3]);
            }

            bool subtract_fee_from_amount = false;
            if (request.params.size() > 4 && !request.params[4].isNull()) {
                subtract_fee_from_amount = request.params[4].get_bool();
            }

            const CScript script = BuildDrivechainBmmRequestScript(sidechain_id, side_block_hash, prev_main_block_hash);
            CCoinControl coin_control;

            LOCK(pwallet->cs_wallet);
            std::string txid = SendToDrivechainScript(*pwallet, script, amount, coin_control, subtract_fee_from_amount);
            return txid;
        },
    };
}

static RPCHelpMan senddrivechainexecute()
{
    return RPCHelpMan{
        "senddrivechainexecute",
        "DEPRECATED legacy RPC.\n"
        "Create, fund, sign and broadcast a Drivechain EXECUTE transaction paying exact withdrawals.\n"
        "This remains available only while the legacy drivechain withdrawal path is still active.\n",
        {
            {"sidechain_id", RPCArg::Type::NUM, RPCArg::Optional::NO, "Sidechain id (0-255)"},
            {"bundle_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Committed bundle hash (32 bytes hex)"},
            {"withdrawals", RPCArg::Type::ARR, RPCArg::Optional::NO, "Array of withdrawals",
                {
                    {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                        {
                            {"address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Destination address (exactly one of address/script)"},
                            {"script",  RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Raw scriptPubKey hex (exactly one of address/script)"},
                            {"amount",  RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount in LTC"},
                        }
                    }
                }
            },
            {"allow_unbroadcast", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED,
                "If true, skip preflight mempool rejection and return txid even if broadcast fails immediately (default: false)."},
        },
        RPCResult{RPCResult::Type::STR_HEX, "txid", "The transaction id"},
        RPCExamples{
            HelpExampleCli("senddrivechainexecute",
                "1 0000000000000000000000000000000000000000000000000000000000000000 "
                "'[{\"address\":\"ltc1q...\",\"amount\":1.0},{\"script\":\"0014...\",\"amount\":0.5}]'") +
            HelpExampleCli("senddrivechainexecute",
                "1 0000000000000000000000000000000000000000000000000000000000000000 "
                "'[{\"address\":\"ltc1q...\",\"amount\":1.0}]' true")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) return NullUniValue;
            CWallet* const pwallet = wallet.get();

            const int scid_i = request.params[0].get_int();
            if (scid_i < 0 || scid_i > 255) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "sidechain_id must be between 0 and 255");
            }
            const uint8_t scid = static_cast<uint8_t>(scid_i);

            const uint256 bundle_hash = ParseHashV(request.params[1], "bundle_hash");

            bool allow_unbroadcast = false;
            if (request.params.size() > 3 && !request.params[3].isNull()) {
                allow_unbroadcast = request.params[3].get_bool();
            }

            // Parse withdrawals
            std::vector<CRecipient> withdrawal_recipients;
            CAmount withdraw_sum{0};
            ParseWithdrawalsArray(request.params[2], withdrawal_recipients, withdraw_sum);

            // Build marker script with nWithdrawals
            const uint32_t n_withdrawals = (uint32_t)withdrawal_recipients.size();
            const CScript exec_script = BuildDrivechainExecuteScript(scid, bundle_hash, n_withdrawals);

            // Recipients must be in consensus order:
            // [0] marker (value 0)
            // [1..n] withdrawals
            std::vector<CRecipient> recipients;
            recipients.reserve(1 + withdrawal_recipients.size());

            recipients.push_back({exec_script, /*nAmount=*/0, /*subtract_fee=*/false});
            recipients.insert(recipients.end(), withdrawal_recipients.begin(), withdrawal_recipients.end());

            CCoinControl coin_control;
            mapValue_t map_value;
            LOCK(pwallet->cs_wallet);

            // IMPORTANT: no shuffle
            UniValue res = SendMoneyNoShuffle(
                pwallet,
                coin_control,
                recipients,
                map_value,
                /*verbose=*/false,
                /*preflight_mempool_accept=*/!allow_unbroadcast);
            return res;
        },
    };
}

static RPCHelpMan sendvaliditysidechainregister()
{
    return RPCHelpMan{
        "sendvaliditysidechainregister",
        "Create, fund, sign and broadcast a validity-sidechain REGISTER transaction.\n"
        "The config must match one of the node's supported proof configuration profiles.\n",
        {
            {"sidechain_id", RPCArg::Type::NUM, RPCArg::Optional::NO, "Sidechain id (0-255)"},
            {"config", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Validity-sidechain config",
                {
                    {"version", RPCArg::Type::NUM, RPCArg::Optional::NO, "Protocol version"},
                    {"proof_system_id", RPCArg::Type::NUM, RPCArg::Optional::NO, "Proof system id"},
                    {"circuit_family_id", RPCArg::Type::NUM, RPCArg::Optional::NO, "Circuit family id"},
                    {"verifier_id", RPCArg::Type::NUM, RPCArg::Optional::NO, "Verifier id"},
                    {"public_input_version", RPCArg::Type::NUM, RPCArg::Optional::NO, "Public-input encoding version"},
                    {"state_root_format", RPCArg::Type::NUM, RPCArg::Optional::NO, "State-root format id"},
                    {"deposit_message_format", RPCArg::Type::NUM, RPCArg::Optional::NO, "Deposit-message format id"},
                    {"withdrawal_leaf_format", RPCArg::Type::NUM, RPCArg::Optional::NO, "Withdrawal-leaf format id"},
                    {"balance_leaf_format", RPCArg::Type::NUM, RPCArg::Optional::NO, "Balance-leaf format id"},
                    {"data_availability_mode", RPCArg::Type::NUM, RPCArg::Optional::NO, "Data-availability mode id"},
                    {"max_batch_data_bytes", RPCArg::Type::NUM, RPCArg::Optional::NO, "Maximum batch data bytes"},
                    {"max_proof_bytes", RPCArg::Type::NUM, RPCArg::Optional::NO, "Maximum proof bytes"},
                    {"force_inclusion_delay", RPCArg::Type::NUM, RPCArg::Optional::NO, "Force-inclusion delay in blocks"},
                    {"deposit_reclaim_delay", RPCArg::Type::NUM, RPCArg::Optional::NO, "Deposit reclaim delay in blocks"},
                    {"escape_hatch_delay", RPCArg::Type::NUM, RPCArg::Optional::NO, "Escape hatch delay in blocks"},
                    {"initial_state_root", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Initial state root"},
                    {"initial_withdrawal_root", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Initial withdrawal root"},
                }},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "Amount to attach to the marker output (default: 0)"},
            {"subtractfeefromamount", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Subtract fee from amount (default: false)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
                {RPCResult::Type::NUM, "sidechain_id", "Registered sidechain id"},
                {RPCResult::Type::STR_HEX, "config_hash", "Configuration hash"},
            }},
        RPCExamples{
            HelpExampleCli("sendvaliditysidechainregister",
                "7 '{\"version\":1,\"proof_system_id\":1,\"circuit_family_id\":1,\"verifier_id\":1,"
                "\"public_input_version\":1,\"state_root_format\":1,\"deposit_message_format\":1,"
                "\"withdrawal_leaf_format\":1,\"balance_leaf_format\":1,\"data_availability_mode\":1,"
                "\"max_batch_data_bytes\":65536,\"max_proof_bytes\":16384,\"force_inclusion_delay\":12,"
                "\"deposit_reclaim_delay\":144,\"escape_hatch_delay\":288,"
                "\"initial_state_root\":\"11...11\",\"initial_withdrawal_root\":\"22...22\"}'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) return NullUniValue;
            CWallet* const pwallet = wallet.get();

            const uint8_t sidechain_id = ParseUint8Value(request.params[0], "sidechain_id");
            const ValiditySidechainConfig config = ParseValiditySidechainConfigObject(request.params[1]);

            std::string validation_error;
            if (!ValidateValiditySidechainConfig(config, &validation_error)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, validation_error);
            }

            CAmount amount = 0;
            if (request.params.size() > 2 && !request.params[2].isNull()) {
                amount = AmountFromValue(request.params[2]);
            }

            bool subtract_fee_from_amount = false;
            if (request.params.size() > 3 && !request.params[3].isNull()) {
                subtract_fee_from_amount = request.params[3].get_bool();
            }

            LOCK(pwallet->cs_wallet);
            EnsureWalletIsUnlocked(pwallet);
            if (IsSidechainIdInUse(*pwallet, sidechain_id)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "sidechain_id is already registered");
            }

            CCoinControl coin_control;
            const std::string txid = SendToDrivechainScript(
                *pwallet,
                BuildValiditySidechainRegisterScript(sidechain_id, config),
                amount,
                coin_control,
                subtract_fee_from_amount);

            UniValue result(UniValue::VOBJ);
            result.pushKV("txid", txid);
            result.pushKV("sidechain_id", static_cast<int>(sidechain_id));
            result.pushKV("config_hash", ComputeValiditySidechainConfigHash(config).GetHex());
            return result;
        },
    };
}

static RPCHelpMan sendvaliditydeposit()
{
    return RPCHelpMan{
        "sendvaliditydeposit",
        "Create, fund, sign and broadcast a validity-sidechain DEPOSIT transaction.\n"
        "If deposit_id or nonce are omitted, wallet-side randomness is used.\n",
        {
            {"sidechain_id", RPCArg::Type::NUM, RPCArg::Optional::NO, "Sidechain id (0-255)"},
            {"destination_commitment", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte sidechain destination commitment"},
            {"refund_destination", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Refund destination on Litecoin",
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Litecoin refund address"},
                    {"script", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Raw refund scriptPubKey hex"},
                }},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Deposit amount in " + CURRENCY_UNIT},
            {"nonce", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Optional deposit nonce (default: random uint64)"},
            {"deposit_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Optional 32-byte deposit id (default: random hash)"},
            {"subtractfeefromamount", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Subtract fee from deposit amount (default: false)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
                {RPCResult::Type::STR_HEX, "deposit_id", "The deposit id"},
                {RPCResult::Type::STR_HEX, "deposit_message_hash", "The committed deposit message hash"},
                {RPCResult::Type::NUM, "nonce", "The deposit nonce"},
            }},
        RPCExamples{
            HelpExampleCli("sendvaliditydeposit",
                "7 \"33...33\" '{\"address\":\"rltc1q...\"}' 1.25 7 \"44...44\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) return NullUniValue;
            CWallet* const pwallet = wallet.get();

            const uint8_t sidechain_id = ParseUint8Value(request.params[0], "sidechain_id");
            const uint256 destination_commitment = ParseHashV(request.params[1], "destination_commitment");
            const CScript refund_script = ParseRpcScriptObject(request.params[2], "refund_destination");

            if (!HasValiditySidechainInChain(*pwallet, sidechain_id)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "sidechain_id is not registered on the active chain");
            }

            ValiditySidechainDepositData deposit;
            deposit.amount = AmountFromValue(request.params[3]);
            deposit.destination_commitment = destination_commitment;
            deposit.refund_script_commitment = ComputeRpcScriptCommitment(refund_script);
            deposit.nonce = (request.params.size() > 4 && !request.params[4].isNull())
                ? ParseUint64Value(request.params[4], "nonce")
                : FastRandomContext().rand64();
            deposit.deposit_id = (request.params.size() > 5 && !request.params[5].isNull())
                ? ParseHashV(request.params[5], "deposit_id")
                : GetRandHash();

            bool subtract_fee_from_amount = false;
            if (request.params.size() > 6 && !request.params[6].isNull()) {
                subtract_fee_from_amount = request.params[6].get_bool();
            }

            LOCK(pwallet->cs_wallet);
            EnsureWalletIsUnlocked(pwallet);

            CCoinControl coin_control;
            const std::string txid = SendToDrivechainScript(
                *pwallet,
                BuildValiditySidechainDepositScript(sidechain_id, deposit),
                deposit.amount,
                coin_control,
                subtract_fee_from_amount);

            UniValue result(UniValue::VOBJ);
            result.pushKV("txid", txid);
            result.pushKV("deposit_id", deposit.deposit_id.GetHex());
            result.pushKV("deposit_message_hash", ComputeValiditySidechainDepositMessageHash(sidechain_id, deposit).GetHex());
            result.pushKV("nonce", deposit.nonce);
            return result;
        },
    };
}

static RPCHelpMan sendforceexitrequest()
{
    return RPCHelpMan{
        "sendforceexitrequest",
        "Create, fund, sign and broadcast a validity-sidechain REQUEST_FORCE_EXIT transaction.\n",
        {
            {"sidechain_id", RPCArg::Type::NUM, RPCArg::Optional::NO, "Sidechain id (0-255)"},
            {"account_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte account identifier"},
            {"exit_asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte asset identifier"},
            {"max_exit_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Maximum exit amount in " + CURRENCY_UNIT},
            {"destination", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Exit destination on Litecoin",
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Litecoin destination address"},
                    {"script", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Raw destination scriptPubKey hex"},
                }},
            {"nonce", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Optional force-exit nonce (default: random uint64)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
                {RPCResult::Type::STR_HEX, "request_hash", "The force-exit request hash"},
                {RPCResult::Type::NUM, "nonce", "The force-exit nonce"},
            }},
        RPCExamples{
            HelpExampleCli("sendforceexitrequest",
                "7 \"55...55\" \"66...66\" 0.5 '{\"address\":\"rltc1q...\"}' 9")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) return NullUniValue;
            CWallet* const pwallet = wallet.get();

            const uint8_t sidechain_id = ParseUint8Value(request.params[0], "sidechain_id");

            if (!HasValiditySidechainInChain(*pwallet, sidechain_id)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "sidechain_id is not registered on the active chain");
            }

            ValiditySidechainForceExitData request_data;
            request_data.account_id = ParseHashV(request.params[1], "account_id");
            request_data.exit_asset_id = ParseHashV(request.params[2], "exit_asset_id");
            request_data.max_exit_amount = AmountFromValue(request.params[3]);
            request_data.destination_commitment = ComputeRpcScriptCommitment(ParseRpcScriptObject(request.params[4], "destination"));
            request_data.nonce = (request.params.size() > 5 && !request.params[5].isNull())
                ? ParseUint64Value(request.params[5], "nonce")
                : FastRandomContext().rand64();

            LOCK(pwallet->cs_wallet);
            EnsureWalletIsUnlocked(pwallet);

            CCoinControl coin_control;
            const std::string txid = SendToDrivechainScript(
                *pwallet,
                BuildValiditySidechainForceExitScript(sidechain_id, request_data),
                /*amount=*/0,
                coin_control,
                /*subtract_fee_from_amount=*/false);

            UniValue result(UniValue::VOBJ);
            result.pushKV("txid", txid);
            result.pushKV("request_hash", ComputeValiditySidechainForceExitHash(sidechain_id, request_data).GetHex());
            result.pushKV("nonce", request_data.nonce);
            return result;
        },
    };
}

static RPCHelpMan sendstaledepositreclaim()
{
    return RPCHelpMan{
        "sendstaledepositreclaim",
        "Create, fund, sign and broadcast a validity-sidechain RECLAIM_STALE_DEPOSIT transaction.\n",
        {
            {"sidechain_id", RPCArg::Type::NUM, RPCArg::Optional::NO, "Sidechain id (0-255)"},
            {"deposit", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Pending deposit metadata",
                {
                    {"deposit_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte deposit id"},
                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Deposit amount in " + CURRENCY_UNIT},
                    {"destination_commitment", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte sidechain destination commitment"},
                    {"nonce", RPCArg::Type::NUM, RPCArg::Optional::NO, "Deposit nonce"},
                }},
            {"refund_destination", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Refund destination on Litecoin",
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Litecoin refund address"},
                    {"script", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Raw refund scriptPubKey hex"},
                }},
            {"allow_unbroadcast", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "If true, skip preflight mempool rejection (default: false)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
                {RPCResult::Type::STR_HEX, "deposit_id", "The reclaimed deposit id"},
            }},
        RPCExamples{
            HelpExampleCli("sendstaledepositreclaim",
                "7 '{\"deposit_id\":\"44...44\",\"amount\":1.25,\"destination_commitment\":\"33...33\",\"nonce\":7}' '{\"address\":\"rltc1q...\"}'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) return NullUniValue;
            CWallet* const pwallet = wallet.get();

            const uint8_t sidechain_id = ParseUint8Value(request.params[0], "sidechain_id");

            if (!HasValiditySidechainInChain(*pwallet, sidechain_id)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "sidechain_id is not registered on the active chain");
            }

            const UniValue& deposit_obj = request.params[1].get_obj();
            const CScript refund_script = ParseRpcScriptObject(request.params[2], "refund_destination");

            ValiditySidechainDepositData deposit;
            deposit.deposit_id = ParseHashO(deposit_obj, "deposit_id");
            deposit.amount = AmountFromValue(find_value(deposit_obj, "amount"));
            deposit.destination_commitment = ParseHashO(deposit_obj, "destination_commitment");
            deposit.refund_script_commitment = ComputeRpcScriptCommitment(refund_script);
            deposit.nonce = ParseUint64Value(find_value(deposit_obj, "nonce"), "deposit.nonce");

            bool allow_unbroadcast = false;
            if (request.params.size() > 3 && !request.params[3].isNull()) {
                allow_unbroadcast = request.params[3].get_bool();
            }

            std::vector<CRecipient> recipients;
            recipients.reserve(2);
            recipients.push_back({BuildValiditySidechainReclaimDepositScript(sidechain_id, deposit), /*nAmount=*/0, /*subtract_fee=*/false});
            recipients.push_back({refund_script, deposit.amount, /*subtract_fee=*/false});

            CCoinControl coin_control;
            mapValue_t map_value;
            LOCK(pwallet->cs_wallet);
            EnsureWalletIsUnlocked(pwallet);
            const std::string txid = SendMoneyNoShuffle(
                pwallet,
                coin_control,
                recipients,
                map_value,
                /*verbose=*/false,
                /*preflight_mempool_accept=*/!allow_unbroadcast).get_str();

            UniValue result(UniValue::VOBJ);
            result.pushKV("txid", txid);
            result.pushKV("deposit_id", deposit.deposit_id.GetHex());
            return result;
        },
    };
}

static RPCHelpMan sendvaliditybatch()
{
    return RPCHelpMan{
        "sendvaliditybatch",
        "Create, fund, sign and broadcast a validity-sidechain COMMIT_VALIDITY_BATCH transaction.\n"
        "If proof_bytes is omitted and the sidechain profile supports local auto proof generation, the wallet builds proof bytes automatically.\n",
        {
            {"sidechain_id", RPCArg::Type::NUM, RPCArg::Optional::NO, "Sidechain id (0-255)"},
            {"public_inputs", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Batch public inputs",
                {
                    {"batch_number", RPCArg::Type::NUM, RPCArg::Optional::NO, "Batch number"},
                    {"prior_state_root", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Prior finalized state root"},
                    {"new_state_root", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "New finalized state root"},
                    {"l1_message_root_before", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Queue root before batch consumption"},
                    {"l1_message_root_after", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Queue root after batch consumption"},
                    {"consumed_queue_messages", RPCArg::Type::NUM, RPCArg::Optional::NO, "Number of consumed queue messages"},
                    {"queue_prefix_commitment", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Optional commitment to the exact consumed queue prefix. If omitted, the wallet computes it from the active chainstate."},
                    {"withdrawal_root", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Withdrawal root"},
                    {"data_root", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Data-availability root"},
                    {"data_size", RPCArg::Type::NUM, RPCArg::Optional::NO, "Published data size in bytes"},
                    {"withdrawal_leaves", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Optional experimental prover witness for the real profile. Ignored by consensus encoding.",
                        {
                            {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                                {
                                    {"withdrawal_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte withdrawal id"},
                                    {"address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Destination address (exactly one of address/script)"},
                                    {"script", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Raw destination scriptPubKey hex (exactly one of address/script)"},
                                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Withdrawal amount in " + CURRENCY_UNIT},
                                }
                            }
                        }},
                }},
            {"proof_bytes", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Optional proof bytes. Omit to auto-build the scaffold proof envelope when supported."},
            {"data_chunks", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Optional array of DA chunk hex strings",
                {
                    {"chunk", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Data chunk hex"},
                }},
            {"allow_unbroadcast", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "If true, skip preflight mempool rejection (default: false)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
              {
                  {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
                  {RPCResult::Type::STR_HEX, "batch_commitment_hash", "The batch commitment hash"},
                  {RPCResult::Type::BOOL, "auto_scaffold_proof", "True if the wallet auto-built the scaffold proof envelope"},
                  {RPCResult::Type::BOOL, "auto_external_proof", "True if the wallet auto-built proof bytes through the configured external prover command"},
                  {RPCResult::Type::STR, "auto_proof_backend", "Which auto-proof backend was used: none, scaffold, or external_command"},
              }},
        RPCExamples{
            HelpExampleCli("sendvaliditybatch",
                "7 '{\"batch_number\":1,\"prior_state_root\":\"11...11\",\"new_state_root\":\"11...11\","
                "\"l1_message_root_before\":\"00...00\",\"l1_message_root_after\":\"00...00\","
                "\"consumed_queue_messages\":0,\"withdrawal_root\":\"22...22\",\"data_root\":\"00...00\",\"data_size\":0}'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) return NullUniValue;
            CWallet* const pwallet = wallet.get();

            const uint8_t sidechain_id = ParseUint8Value(request.params[0], "sidechain_id");

            ValiditySidechain sidechain;
            if (!GetValiditySidechainFromChain(*pwallet, sidechain_id, sidechain)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "sidechain_id is not registered on the active chain");
            }

            const UniValue& public_inputs_obj = request.params[1].get_obj();
            ValiditySidechainBatchPublicInputs public_inputs =
                ParseValiditySidechainBatchPublicInputsObject(public_inputs_obj);
            if (find_value(public_inputs_obj, "queue_prefix_commitment").isNull()) {
                std::string queue_error;
                if (!ComputeValiditySidechainQueuePrefixCommitment(
                        sidechain,
                        sidechain_id,
                        public_inputs.consumed_queue_messages,
                        public_inputs.queue_prefix_commitment,
                        &queue_error)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, queue_error);
                }
            }
            const std::vector<std::vector<unsigned char>> data_chunks =
                (request.params.size() > 3 && !request.params[3].isNull())
                    ? ParseHexArray(request.params[3], "data_chunks")
                    : std::vector<std::vector<unsigned char>>{};
            std::vector<ValiditySidechainQueueEntry> consumed_queue_entries;
            std::string queue_entries_error;
            if (!GetValiditySidechainConsumedQueueEntries(
                    sidechain,
                    public_inputs.consumed_queue_messages,
                    consumed_queue_entries,
                    &queue_entries_error)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, queue_entries_error);
            }
            std::vector<ValiditySidechainWithdrawalLeaf> experimental_withdrawal_leaves;
            std::vector<CRecipient> experimental_payout_recipients;
            const UniValue& withdrawal_leaves = find_value(public_inputs_obj, "withdrawal_leaves");
            if (!withdrawal_leaves.isNull()) {
                ParseValidityWithdrawalLeaves(
                    withdrawal_leaves,
                    experimental_withdrawal_leaves,
                    experimental_payout_recipients);
            }

            std::vector<unsigned char> proof_bytes;
            bool auto_scaffold_proof = false;
            bool auto_external_proof = false;
            std::string auto_proof_backend = "none";
            if (request.params.size() > 2 && !request.params[2].isNull()) {
                proof_bytes = ParseHexV(request.params[2], "proof_bytes");
            } else {
                const ValiditySidechainBatchVerifierMode verifier_mode = GetValiditySidechainBatchVerifierMode(sidechain.config);
                if (verifier_mode == ValiditySidechainBatchVerifierMode::SCAFFOLD_QUEUE_PREFIX_ONLY ||
                    verifier_mode == ValiditySidechainBatchVerifierMode::SCAFFOLD_TRANSITION_COMMITMENT) {
                    proof_bytes = BuildValiditySidechainScaffoldBatchProof(
                        sidechain_id,
                        public_inputs,
                        sidechain.current_state_root,
                        sidechain.current_withdrawal_root,
                        sidechain.current_data_root,
                        sidechain.queue_state.root);
                    auto_scaffold_proof = true;
                    auto_proof_backend = "scaffold";
                } else {
                    std::string proof_error;
                    if (!BuildValiditySidechainBatchProofWithExternalProver(
                            sidechain.config,
                            sidechain_id,
                            public_inputs,
                            consumed_queue_entries,
                            experimental_withdrawal_leaves,
                            data_chunks,
                            proof_bytes,
                            &proof_error)) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, proof_error);
                    }
                    auto_external_proof = true;
                    auto_proof_backend = "external_command";
                }
            }

            bool allow_unbroadcast = false;
            if (request.params.size() > 4 && !request.params[4].isNull()) {
                allow_unbroadcast = request.params[4].get_bool();
            }

            LOCK(pwallet->cs_wallet);
            EnsureWalletIsUnlocked(pwallet);

            CCoinControl coin_control;
            const std::string txid = SendToDrivechainScript(
                *pwallet,
                BuildValiditySidechainCommitScript(sidechain_id, public_inputs, proof_bytes, data_chunks),
                /*amount=*/0,
                coin_control,
                /*subtract_fee_from_amount=*/false,
                /*preflight_mempool_accept=*/!allow_unbroadcast);

            UniValue result(UniValue::VOBJ);
            result.pushKV("txid", txid);
            result.pushKV("batch_commitment_hash", ComputeValiditySidechainBatchCommitmentHash(sidechain_id, public_inputs).GetHex());
            result.pushKV("auto_scaffold_proof", auto_scaffold_proof);
            result.pushKV("auto_external_proof", auto_external_proof);
            result.pushKV("auto_proof_backend", auto_proof_backend);
            return result;
        },
    };
}

static RPCHelpMan sendverifiedwithdrawals()
{
    return RPCHelpMan{
        "sendverifiedwithdrawals",
        "Create, fund, sign and broadcast a validity-sidechain EXECUTE_VERIFIED_WITHDRAWALS transaction.\n"
        "The wallet deterministically builds Merkle proofs from the ordered withdrawal list and requires the resulting withdrawal root to match the accepted batch tracked by this node.\n",
        {
            {"sidechain_id", RPCArg::Type::NUM, RPCArg::Optional::NO, "Sidechain id (0-255)"},
            {"batch_number", RPCArg::Type::NUM, RPCArg::Optional::NO, "Accepted batch number"},
            {"withdrawals", RPCArg::Type::ARR, RPCArg::Optional::NO, "Ordered list of withdrawal leaves to execute",
                {
                    {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                        {
                            {"withdrawal_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte withdrawal id"},
                            {"address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Destination address (exactly one of address/script)"},
                            {"script", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Raw destination scriptPubKey hex (exactly one of address/script)"},
                            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Withdrawal amount in " + CURRENCY_UNIT},
                        }
                    }
                }
            },
            {"allow_unbroadcast", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "If true, skip preflight mempool rejection (default: false)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
                {RPCResult::Type::STR_HEX, "accepted_batch_id", "The accepted batch id committed by the marker output"},
                {RPCResult::Type::STR_HEX, "withdrawal_root", "The withdrawal root matched against the accepted batch"},
                {RPCResult::Type::NUM, "withdrawal_count", "Number of executed withdrawals"},
            }},
        RPCExamples{
            HelpExampleCli("sendverifiedwithdrawals",
                "7 1 "
                "'[{\"withdrawal_id\":\"aa...aa\",\"script\":\"0014...\",\"amount\":0.25},"
                "{\"withdrawal_id\":\"bb...bb\",\"script\":\"0014...\",\"amount\":0.5}]'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) return NullUniValue;
            CWallet* const pwallet = wallet.get();

            const uint8_t sidechain_id = ParseUint8Value(request.params[0], "sidechain_id");
            const uint32_t batch_number = ParseUint32Value(request.params[1], "batch_number");

            ValiditySidechain sidechain;
            if (!GetValiditySidechainFromChain(*pwallet, sidechain_id, sidechain)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "sidechain_id is not registered on the active chain");
            }

            const ValiditySidechainAcceptedBatch* accepted_batch = FindAcceptedValidityBatch(sidechain, batch_number);
            if (accepted_batch == nullptr) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "accepted batch not found");
            }

            std::vector<ValiditySidechainWithdrawalLeaf> withdrawals;
            std::vector<CRecipient> payout_recipients;
            ParseValidityWithdrawalLeaves(request.params[2], withdrawals, payout_recipients);

            const uint256 computed_root = ComputeValiditySidechainWithdrawalRoot(withdrawals);
            if (computed_root != accepted_batch->withdrawal_root) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "withdrawal list does not match the accepted batch withdrawal root");
            }

            std::vector<ValiditySidechainWithdrawalProof> withdrawal_proofs;
            withdrawal_proofs.reserve(withdrawals.size());
            for (uint32_t i = 0; i < withdrawals.size(); ++i) {
                ValiditySidechainWithdrawalProof proof;
                if (!BuildValiditySidechainWithdrawalProof(withdrawals, i, proof)) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "failed to build withdrawal proof");
                }
                withdrawal_proofs.push_back(std::move(proof));
            }

            std::vector<CRecipient> recipients;
            recipients.reserve(1 + payout_recipients.size());
            recipients.push_back({
                BuildValiditySidechainExecuteScript(
                    sidechain_id,
                    batch_number,
                    accepted_batch->withdrawal_root,
                    withdrawal_proofs),
                /*nAmount=*/0,
                /*subtract_fee=*/false});
            recipients.insert(recipients.end(), payout_recipients.begin(), payout_recipients.end());

            bool allow_unbroadcast = false;
            if (request.params.size() > 3 && !request.params[3].isNull()) {
                allow_unbroadcast = request.params[3].get_bool();
            }

            CCoinControl coin_control;
            mapValue_t map_value;
            LOCK(pwallet->cs_wallet);
            EnsureWalletIsUnlocked(pwallet);
            const std::string txid = SendMoneyNoShuffle(
                pwallet,
                coin_control,
                recipients,
                map_value,
                /*verbose=*/false,
                /*preflight_mempool_accept=*/!allow_unbroadcast).get_str();

            UniValue result(UniValue::VOBJ);
            result.pushKV("txid", txid);
            result.pushKV("accepted_batch_id", ComputeValiditySidechainAcceptedBatchId(
                sidechain_id,
                batch_number,
                accepted_batch->withdrawal_root).GetHex());
            result.pushKV("withdrawal_root", accepted_batch->withdrawal_root.GetHex());
            result.pushKV("withdrawal_count", static_cast<int64_t>(withdrawals.size()));
            return result;
        },
    };
}

static RPCHelpMan sendescapeexit()
{
    return RPCHelpMan{
        "sendescapeexit",
        "Create, fund, sign and broadcast a validity-sidechain EXECUTE_ESCAPE_EXIT transaction.\n"
        "The wallet deterministically builds Merkle proofs from the ordered exit list and requires the resulting state root to match the current state root tracked by this node.\n"
        "This execution path is currently scaffold-only; non-scaffold profiles hard-fail pending real state-root proof semantics.\n",
        {
            {"sidechain_id", RPCArg::Type::NUM, RPCArg::Optional::NO, "Sidechain id (0-255)"},
            {"state_root_reference", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Current finalized state root reference"},
            {"exits", RPCArg::Type::ARR, RPCArg::Optional::NO, "Ordered list of escape-exit leaves to execute",
                {
                    {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                        {
                            {"exit_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte exit id"},
                            {"address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Destination address (exactly one of address/script)"},
                            {"script", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Raw destination scriptPubKey hex (exactly one of address/script)"},
                            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Exit amount in " + CURRENCY_UNIT},
                        }
                    }
                }
            },
            {"allow_unbroadcast", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "If true, skip preflight mempool rejection (default: false)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
                {RPCResult::Type::STR_HEX, "state_root_reference", "The state root referenced by the marker output"},
                {RPCResult::Type::NUM, "exit_count", "Number of executed escape exits"},
            }},
        RPCExamples{
            HelpExampleCli("sendescapeexit",
                "7 11...11 "
                "'[{\"exit_id\":\"cc...cc\",\"script\":\"0014...\",\"amount\":0.25}]'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) return NullUniValue;
            CWallet* const pwallet = wallet.get();

            const uint8_t sidechain_id = ParseUint8Value(request.params[0], "sidechain_id");
            const uint256 state_root_reference = ParseHashV(request.params[1], "state_root_reference");

            ValiditySidechain sidechain;
            if (!GetValiditySidechainFromChain(*pwallet, sidechain_id, sidechain)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "sidechain_id is not registered on the active chain");
            }
            if (state_root_reference != sidechain.current_state_root) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "state_root_reference does not match the current state root");
            }

            std::vector<ValiditySidechainEscapeExitLeaf> exits;
            std::vector<CRecipient> payout_recipients;
            ParseValidityEscapeExitLeaves(request.params[2], exits, payout_recipients);

            const uint256 computed_root = ComputeValiditySidechainEscapeExitRoot(exits);
            if (computed_root != state_root_reference) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "escape-exit list does not match the referenced state root");
            }

            std::vector<ValiditySidechainEscapeExitProof> exit_proofs;
            exit_proofs.reserve(exits.size());
            for (uint32_t i = 0; i < exits.size(); ++i) {
                ValiditySidechainEscapeExitProof proof;
                if (!BuildValiditySidechainEscapeExitProof(exits, i, proof)) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "failed to build escape-exit proof");
                }
                exit_proofs.push_back(std::move(proof));
            }

            std::vector<CRecipient> recipients;
            recipients.reserve(1 + payout_recipients.size());
            recipients.push_back({
                BuildValiditySidechainEscapeExitScript(sidechain_id, state_root_reference, exit_proofs),
                /*nAmount=*/0,
                /*subtract_fee=*/false});
            recipients.insert(recipients.end(), payout_recipients.begin(), payout_recipients.end());

            bool allow_unbroadcast = false;
            if (request.params.size() > 3 && !request.params[3].isNull()) {
                allow_unbroadcast = request.params[3].get_bool();
            }

            CCoinControl coin_control;
            mapValue_t map_value;
            LOCK(pwallet->cs_wallet);
            EnsureWalletIsUnlocked(pwallet);
            const std::string txid = SendMoneyNoShuffle(
                pwallet,
                coin_control,
                recipients,
                map_value,
                /*verbose=*/false,
                /*preflight_mempool_accept=*/!allow_unbroadcast).get_str();

            UniValue result(UniValue::VOBJ);
            result.pushKV("txid", txid);
            result.pushKV("state_root_reference", state_root_reference.GetHex());
            result.pushKV("exit_count", static_cast<int64_t>(exits.size()));
            return result;
        },
    };
}

static RPCHelpMan sendtoaddress()
{
    return RPCHelpMan{"sendtoaddress",
                "\nSend an amount to a given address." +
        HELP_REQUIRING_PASSPHRASE,
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The litecoin address to send to."},
                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The amount in " + CURRENCY_UNIT + " to send. eg 0.1"},
                    {"comment", RPCArg::Type::STR, RPCArg::Optional::OMITTED_NAMED_ARG, "A comment used to store what the transaction is for.\n"
                                         "This is not part of the transaction, just kept in your wallet."},
                    {"comment_to", RPCArg::Type::STR, RPCArg::Optional::OMITTED_NAMED_ARG, "A comment to store the name of the person or organization\n"
                                         "to which you're sending the transaction. This is not part of the \n"
                                         "transaction, just kept in your wallet."},
                    {"subtractfeefromamount", RPCArg::Type::BOOL, /* default */ "false", "The fee will be deducted from the amount being sent.\n"
                                         "The recipient will receive less bitcoins than you enter in the amount field."},
                    {"replaceable", RPCArg::Type::BOOL, /* default */ "wallet default", "Allow this transaction to be replaced by a transaction with higher fees via BIP 125"},
                    {"conf_target", RPCArg::Type::NUM, /* default */ "wallet -txconfirmtarget", "Confirmation target in blocks"},
                    {"estimate_mode", RPCArg::Type::STR, /* default */ "unset", std::string() + "The fee estimate mode, must be one of (case insensitive):\n"
            "       \"" + FeeModes("\"\n\"") + "\""},
                    {"avoid_reuse", RPCArg::Type::BOOL, /* default */ "true", "(only available if avoid_reuse wallet flag is set) Avoid spending from dirty addresses; addresses are considered\n"
                                         "dirty if they have previously been used in a transaction."},
                    {"fee_rate", RPCArg::Type::AMOUNT, /* default */ "not set, fall back to wallet fee estimation", "Specify a fee rate in " + CURRENCY_ATOM + "/vB."},
                    {"verbose", RPCArg::Type::BOOL, /* default */ "false", "If true, return extra information about the transaction."},
                },
                {
                    RPCResult{"if verbose is not set or set to false",
                        RPCResult::Type::STR_HEX, "txid", "The transaction id."
                    },
                    RPCResult{"if verbose is set to true",
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "txid", "The transaction id."},
                            {RPCResult::Type::STR, "fee reason", "The transaction fee reason."}
                        },
                    },
                },
                RPCExamples{
                    "\nSend 0.1 BTC\n"
                    + HelpExampleCli("sendtoaddress", "\"" + EXAMPLE_ADDRESS[0] + "\" 0.1") +
                    "\nSend 0.1 BTC with a confirmation target of 6 blocks in economical fee estimate mode using positional arguments\n"
                    + HelpExampleCli("sendtoaddress", "\"" + EXAMPLE_ADDRESS[0] + "\" 0.1 \"donation\" \"sean's outpost\" false true 6 economical") +
                    "\nSend 0.1 BTC with a fee rate of 1.1 " + CURRENCY_ATOM + "/vB, subtract fee from amount, BIP125-replaceable, using positional arguments\n"
                    + HelpExampleCli("sendtoaddress", "\"" + EXAMPLE_ADDRESS[0] + "\" 0.1 \"drinks\" \"room77\" true true null \"unset\" null 1.1") +
                    "\nSend 0.2 BTC with a confirmation target of 6 blocks in economical fee estimate mode using named arguments\n"
                    + HelpExampleCli("-named sendtoaddress", "address=\"" + EXAMPLE_ADDRESS[0] + "\" amount=0.2 conf_target=6 estimate_mode=\"economical\"") +
                    "\nSend 0.5 BTC with a fee rate of 25 " + CURRENCY_ATOM + "/vB using named arguments\n"
                    + HelpExampleCli("-named sendtoaddress", "address=\"" + EXAMPLE_ADDRESS[0] + "\" amount=0.5 fee_rate=25")
                    + HelpExampleCli("-named sendtoaddress", "address=\"" + EXAMPLE_ADDRESS[0] + "\" amount=0.5 fee_rate=25 subtractfeefromamount=false replaceable=true avoid_reuse=true comment=\"2 pizzas\" comment_to=\"jeremy\" verbose=true")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    // Wallet comments
    mapValue_t mapValue;
    if (!request.params[2].isNull() && !request.params[2].get_str().empty())
        mapValue["comment"] = request.params[2].get_str();
    if (!request.params[3].isNull() && !request.params[3].get_str().empty())
        mapValue["to"] = request.params[3].get_str();

    bool fSubtractFeeFromAmount = false;
    if (!request.params[4].isNull()) {
        fSubtractFeeFromAmount = request.params[4].get_bool();
    }

    CCoinControl coin_control;
    if (!request.params[5].isNull()) {
        coin_control.m_signal_bip125_rbf = request.params[5].get_bool();
    }

    coin_control.m_avoid_address_reuse = GetAvoidReuseFlag(pwallet, request.params[8]);
    // We also enable partial spend avoidance if reuse avoidance is set.
    coin_control.m_avoid_partial_spends |= coin_control.m_avoid_address_reuse;

    SetFeeEstimateMode(*pwallet, coin_control, /* conf_target */ request.params[6], /* estimate_mode */ request.params[7], /* fee_rate */ request.params[9], /* override_min_fee */ false);

    EnsureWalletIsUnlocked(pwallet);

    UniValue address_amounts(UniValue::VOBJ);
    const std::string address = request.params[0].get_str();
    address_amounts.pushKV(address, request.params[1]);
    UniValue subtractFeeFromAmount(UniValue::VARR);
    if (fSubtractFeeFromAmount) {
        subtractFeeFromAmount.push_back(address);
    }

    std::vector<CRecipient> recipients;
    ParseRecipients(address_amounts, subtractFeeFromAmount, recipients);
    const bool verbose{request.params[10].isNull() ? false : request.params[10].get_bool()};

    return SendMoney(pwallet, coin_control, recipients, mapValue, verbose);
},
    };
}

static RPCHelpMan listaddressgroupings()
{
    return RPCHelpMan{"listaddressgroupings",
                "\nLists groups of addresses which have had their common ownership\n"
                "made public by common use as inputs or as the resulting change\n"
                "in past transactions\n",
                {},
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::ARR, "", "",
                        {
                            {RPCResult::Type::ARR, "", "",
                            {
                                {RPCResult::Type::STR, "address", "The litecoin address"},
                                {RPCResult::Type::STR_AMOUNT, "amount", "The amount in " + CURRENCY_UNIT},
                                {RPCResult::Type::STR, "label", /* optional */ true, "The label"},
                            }},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("listaddressgroupings", "")
            + HelpExampleRpc("listaddressgroupings", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    const CWallet* const pwallet = wallet.get();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    UniValue jsonGroupings(UniValue::VARR);
    std::map<CTxDestination, CAmount> balances = pwallet->GetAddressBalances();
    for (const std::set<CTxDestination>& grouping : pwallet->GetAddressGroupings()) {
        UniValue jsonGrouping(UniValue::VARR);
        for (const CTxDestination& address : grouping)
        {
            UniValue addressInfo(UniValue::VARR);
            addressInfo.push_back(EncodeDestination(address));
            addressInfo.push_back(ValueFromAmount(balances[address]));
            {
                const auto* address_book_entry = pwallet->FindAddressBookEntry(address);
                if (address_book_entry) {
                    addressInfo.push_back(address_book_entry->GetLabel());
                }
            }
            jsonGrouping.push_back(addressInfo);
        }
        jsonGroupings.push_back(jsonGrouping);
    }
    return jsonGroupings;
},
    };
}

static RPCHelpMan signmessage()
{
    return RPCHelpMan{"signmessage",
                "\nSign a message with the private key of an address" +
        HELP_REQUIRING_PASSPHRASE,
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The litecoin address to use for the private key."},
                    {"message", RPCArg::Type::STR, RPCArg::Optional::NO, "The message to create a signature of."},
                },
                RPCResult{
                    RPCResult::Type::STR, "signature", "The signature of the message encoded in base 64"
                },
                RPCExamples{
            "\nUnlock the wallet for 30 seconds\n"
            + HelpExampleCli("walletpassphrase", "\"mypassphrase\" 30") +
            "\nCreate the signature\n"
            + HelpExampleCli("signmessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"signature\" \"my message\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("signmessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\", \"my message\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    const CWallet* const pwallet = wallet.get();

    LOCK(pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet);

    std::string strAddress = request.params[0].get_str();
    std::string strMessage = request.params[1].get_str();

    CTxDestination dest = DecodeDestination(strAddress);
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");
    }

    const PKHash *pkhash = boost::get<PKHash>(&dest);
    if (!pkhash) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");
    }

    std::string signature;
    SigningResult err = pwallet->SignMessage(strMessage, *pkhash, signature);
    if (err == SigningResult::SIGNING_FAILED) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, SigningResultString(err));
    } else if (err != SigningResult::OK){
        throw JSONRPCError(RPC_WALLET_ERROR, SigningResultString(err));
    }

    return signature;
},
    };
}

static CAmount GetReceived(const CWallet& wallet, const UniValue& params, bool by_label) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    std::set<CTxDestination> address_set;

    if (by_label) {
        // Get the set of addresses assigned to label
        std::string label = LabelFromValue(params[0]);
        address_set = wallet.GetLabelAddresses(label);
    } else {
        // Get the address
        CTxDestination dest = DecodeDestination(params[0].get_str());
        if (!IsValidDestination(dest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Litecoin address");
        }
        if (!wallet.IsMine(dest)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Address not found in wallet");
        }
        address_set.insert(dest);
    }

    // Minimum confirmations
    int min_depth = 1;
    if (!params[1].isNull())
        min_depth = params[1].get_int();

    // Tally
    CAmount amount = 0;
    for (const std::pair<const uint256, CWalletTx>& wtx_pair : wallet.mapWallet) {
        const CWalletTx& wtx = wtx_pair.second;
        if (wtx.IsCoinBase() || !wallet.chain().checkFinalTx(*wtx.tx) || wtx.GetDepthInMainChain() < min_depth) {
            continue;
        }

        for (const CTxOut& txout : wtx.tx->vout) {
            CTxDestination address;
            if (ExtractDestination(txout.scriptPubKey, address) && wallet.IsMine(address) && address_set.count(address)) {
                amount += txout.nValue;
            }
        }
    }

    return amount;
}

static RPCHelpMan getreceivedbyaddress()
{
    return RPCHelpMan{"getreceivedbyaddress",
                "\nReturns the total amount received by the given address in transactions with at least minconf confirmations.\n",
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The litecoin address for transactions."},
                    {"minconf", RPCArg::Type::NUM, /* default */ "1", "Only include transactions confirmed at least this many times."},
                },
                RPCResult{
                    RPCResult::Type::STR_AMOUNT, "amount", "The total amount in " + CURRENCY_UNIT + " received at this address."
                },
                RPCExamples{
            "\nThe amount from transactions with at least 1 confirmation\n"
            + HelpExampleCli("getreceivedbyaddress", "\"" + EXAMPLE_ADDRESS[0] + "\"") +
            "\nThe amount including unconfirmed transactions, zero confirmations\n"
            + HelpExampleCli("getreceivedbyaddress", "\"" + EXAMPLE_ADDRESS[0] + "\" 0") +
            "\nThe amount with at least 6 confirmations\n"
            + HelpExampleCli("getreceivedbyaddress", "\"" + EXAMPLE_ADDRESS[0] + "\" 6") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("getreceivedbyaddress", "\"" + EXAMPLE_ADDRESS[0] + "\", 6")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    const CWallet* const pwallet = wallet.get();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    return ValueFromAmount(GetReceived(*pwallet, request.params, /* by_label */ false));
},
    };
}

static RPCHelpMan getreceivedbylabel()
{
    return RPCHelpMan{"getreceivedbylabel",
                "\nReturns the total amount received by addresses with <label> in transactions with at least [minconf] confirmations.\n",
                {
                    {"label", RPCArg::Type::STR, RPCArg::Optional::NO, "The selected label, may be the default label using \"\"."},
                    {"minconf", RPCArg::Type::NUM, /* default */ "1", "Only include transactions confirmed at least this many times."},
                },
                RPCResult{
                    RPCResult::Type::STR_AMOUNT, "amount", "The total amount in " + CURRENCY_UNIT + " received for this label."
                },
                RPCExamples{
            "\nAmount received by the default label with at least 1 confirmation\n"
            + HelpExampleCli("getreceivedbylabel", "\"\"") +
            "\nAmount received at the tabby label including unconfirmed amounts with zero confirmations\n"
            + HelpExampleCli("getreceivedbylabel", "\"tabby\" 0") +
            "\nThe amount with at least 6 confirmations\n"
            + HelpExampleCli("getreceivedbylabel", "\"tabby\" 6") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("getreceivedbylabel", "\"tabby\", 6")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    const CWallet* const pwallet = wallet.get();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    return ValueFromAmount(GetReceived(*pwallet, request.params, /* by_label */ true));
},
    };
}

static RPCHelpMan getbalance()
{
    return RPCHelpMan{"getbalance",
                "\nReturns the total available balance.\n"
                "The available balance is what the wallet considers currently spendable, and is\n"
                "thus affected by options which limit spendability such as -spendzeroconfchange.\n",
                {
                    {"dummy", RPCArg::Type::STR, RPCArg::Optional::OMITTED_NAMED_ARG, "Remains for backward compatibility. Must be excluded or set to \"*\"."},
                    {"minconf", RPCArg::Type::NUM, /* default */ "0", "Only include transactions confirmed at least this many times."},
                    {"include_watchonly", RPCArg::Type::BOOL, /* default */ "true for watch-only wallets, otherwise false", "Also include balance in watch-only addresses (see 'importaddress')"},
                    {"avoid_reuse", RPCArg::Type::BOOL, /* default */ "true", "(only available if avoid_reuse wallet flag is set) Do not include balance in dirty outputs; addresses are considered dirty if they have previously been used in a transaction."},
                },
                RPCResult{
                    RPCResult::Type::STR_AMOUNT, "amount", "The total amount in " + CURRENCY_UNIT + " received for this wallet."
                },
                RPCExamples{
            "\nThe total amount in the wallet with 0 or more confirmations\n"
            + HelpExampleCli("getbalance", "") +
            "\nThe total amount in the wallet with at least 6 confirmations\n"
            + HelpExampleCli("getbalance", "\"*\" 6") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("getbalance", "\"*\", 6")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    const CWallet* const pwallet = wallet.get();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    const UniValue& dummy_value = request.params[0];
    if (!dummy_value.isNull() && dummy_value.get_str() != "*") {
        throw JSONRPCError(RPC_METHOD_DEPRECATED, "dummy first argument must be excluded or set to \"*\".");
    }

    int min_depth = 0;
    if (!request.params[1].isNull()) {
        min_depth = request.params[1].get_int();
    }

    bool include_watchonly = ParseIncludeWatchonly(request.params[2], *pwallet);

    bool avoid_reuse = GetAvoidReuseFlag(pwallet, request.params[3]);

    const auto bal = pwallet->GetBalance(min_depth, avoid_reuse);

    return ValueFromAmount(bal.m_mine_trusted + (include_watchonly ? bal.m_watchonly_trusted : 0));
},
    };
}

static RPCHelpMan getunconfirmedbalance()
{
    return RPCHelpMan{"getunconfirmedbalance",
                "DEPRECATED\nIdentical to getbalances().mine.untrusted_pending\n",
                {},
                RPCResult{RPCResult::Type::NUM, "", "The balance"},
                RPCExamples{""},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    const CWallet* const pwallet = wallet.get();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    return ValueFromAmount(pwallet->GetBalance().m_mine_untrusted_pending);
},
    };
}

static RPCHelpMan sendmany()
{
    return RPCHelpMan{"sendmany",
                "\nSend multiple times. Amounts are double-precision floating point numbers." +
        HELP_REQUIRING_PASSPHRASE,
                {
                    {"dummy", RPCArg::Type::STR, RPCArg::Optional::NO, "Must be set to \"\" for backwards compatibility.", "\"\""},
                    {"amounts", RPCArg::Type::OBJ, RPCArg::Optional::NO, "The addresses and amounts",
                        {
                            {"address", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The litecoin address is the key, the numeric amount (can be string) in " + CURRENCY_UNIT + " is the value"},
                        },
                    },
                    {"minconf", RPCArg::Type::NUM, RPCArg::Optional::OMITTED_NAMED_ARG, "Ignored dummy value"},
                    {"comment", RPCArg::Type::STR, RPCArg::Optional::OMITTED_NAMED_ARG, "A comment"},
                    {"subtractfeefrom", RPCArg::Type::ARR, RPCArg::Optional::OMITTED_NAMED_ARG, "The addresses.\n"
                                       "The fee will be equally deducted from the amount of each selected address.\n"
                                       "Those recipients will receive less bitcoins than you enter in their corresponding amount field.\n"
                                       "If no addresses are specified here, the sender pays the fee.",
                        {
                            {"address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Subtract fee from this address"},
                        },
                    },
                    {"replaceable", RPCArg::Type::BOOL, /* default */ "wallet default", "Allow this transaction to be replaced by a transaction with higher fees via BIP 125"},
                    {"conf_target", RPCArg::Type::NUM, /* default */ "wallet -txconfirmtarget", "Confirmation target in blocks"},
                    {"estimate_mode", RPCArg::Type::STR, /* default */ "unset", std::string() + "The fee estimate mode, must be one of (case insensitive):\n"
            "       \"" + FeeModes("\"\n\"") + "\""},
                    {"fee_rate", RPCArg::Type::AMOUNT, /* default */ "not set, fall back to wallet fee estimation", "Specify a fee rate in " + CURRENCY_ATOM + "/vB."},
                    {"verbose", RPCArg::Type::BOOL, /* default */ "false", "If true, return extra infomration about the transaction."},
                },
                {
                    RPCResult{"if verbose is not set or set to false",
                        RPCResult::Type::STR_HEX, "txid", "The transaction id for the send. Only 1 transaction is created regardless of\n"
                "the number of addresses."
                    },
                    RPCResult{"if verbose is set to true",
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "txid", "The transaction id for the send. Only 1 transaction is created regardless of\n"
                "the number of addresses."},
                            {RPCResult::Type::STR, "fee reason", "The transaction fee reason."}
                        },
                    },
                },
                RPCExamples{
            "\nSend two amounts to two different addresses:\n"
            + HelpExampleCli("sendmany", "\"\" \"{\\\"" + EXAMPLE_ADDRESS[0] + "\\\":0.01,\\\"" + EXAMPLE_ADDRESS[1] + "\\\":0.02}\"") +
            "\nSend two amounts to two different addresses setting the confirmation and comment:\n"
            + HelpExampleCli("sendmany", "\"\" \"{\\\"" + EXAMPLE_ADDRESS[0] + "\\\":0.01,\\\"" + EXAMPLE_ADDRESS[1] + "\\\":0.02}\" 6 \"testing\"") +
            "\nSend two amounts to two different addresses, subtract fee from amount:\n"
            + HelpExampleCli("sendmany", "\"\" \"{\\\"" + EXAMPLE_ADDRESS[0] + "\\\":0.01,\\\"" + EXAMPLE_ADDRESS[1] + "\\\":0.02}\" 1 \"\" \"[\\\"" + EXAMPLE_ADDRESS[0] + "\\\",\\\"" + EXAMPLE_ADDRESS[1] + "\\\"]\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("sendmany", "\"\", {\"" + EXAMPLE_ADDRESS[0] + "\":0.01,\"" + EXAMPLE_ADDRESS[1] + "\":0.02}, 6, \"testing\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    if (!request.params[0].isNull() && !request.params[0].get_str().empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Dummy value must be set to \"\"");
    }
    UniValue sendTo = request.params[1].get_obj();

    mapValue_t mapValue;
    if (!request.params[3].isNull() && !request.params[3].get_str().empty())
        mapValue["comment"] = request.params[3].get_str();

    UniValue subtractFeeFromAmount(UniValue::VARR);
    if (!request.params[4].isNull())
        subtractFeeFromAmount = request.params[4].get_array();

    CCoinControl coin_control;
    if (!request.params[5].isNull()) {
        coin_control.m_signal_bip125_rbf = request.params[5].get_bool();
    }

    SetFeeEstimateMode(*pwallet, coin_control, /* conf_target */ request.params[6], /* estimate_mode */ request.params[7], /* fee_rate */ request.params[8], /* override_min_fee */ false);

    std::vector<CRecipient> recipients;
    ParseRecipients(sendTo, subtractFeeFromAmount, recipients);
    const bool verbose{request.params[9].isNull() ? false : request.params[9].get_bool()};

    return SendMoney(pwallet, coin_control, recipients, std::move(mapValue), verbose);
},
    };
}

static RPCHelpMan addmultisigaddress()
{
    return RPCHelpMan{"addmultisigaddress",
                "\nAdd an nrequired-to-sign multisignature address to the wallet. Requires a new wallet backup.\n"
                "Each key is a Litecoin address or hex-encoded public key.\n"
                "This functionality is only intended for use with non-watchonly addresses.\n"
                "See `importaddress` for watchonly p2sh address support.\n"
                "If 'label' is specified, assign address to that label.\n",
                {
                    {"nrequired", RPCArg::Type::NUM, RPCArg::Optional::NO, "The number of required signatures out of the n keys or addresses."},
                    {"keys", RPCArg::Type::ARR, RPCArg::Optional::NO, "The litecoin addresses or hex-encoded public keys",
                        {
                            {"key", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "litecoin address or hex-encoded public key"},
                        },
                        },
                    {"label", RPCArg::Type::STR, RPCArg::Optional::OMITTED_NAMED_ARG, "A label to assign the addresses to."},
                    {"address_type", RPCArg::Type::STR, /* default */ "set by -addresstype", "The address type to use. Options are \"legacy\", \"p2sh-segwit\", and \"bech32\"."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "address", "The value of the new multisig address"},
                        {RPCResult::Type::STR_HEX, "redeemScript", "The string value of the hex-encoded redemption script"},
                        {RPCResult::Type::STR, "descriptor", "The descriptor for this multisig"},
                    }
                },
                RPCExamples{
            "\nAdd a multisig address from 2 addresses\n"
            + HelpExampleCli("addmultisigaddress", "2 \"[\\\"" + EXAMPLE_ADDRESS[0] + "\\\",\\\"" + EXAMPLE_ADDRESS[1] + "\\\"]\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("addmultisigaddress", "2, \"[\\\"" + EXAMPLE_ADDRESS[0] + "\\\",\\\"" + EXAMPLE_ADDRESS[1] + "\\\"]\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    LegacyScriptPubKeyMan& spk_man = EnsureLegacyScriptPubKeyMan(*pwallet);

    LOCK2(pwallet->cs_wallet, spk_man.cs_KeyStore);

    std::string label;
    if (!request.params[2].isNull())
        label = LabelFromValue(request.params[2]);

    int required = request.params[0].get_int();

    // Get the public keys
    const UniValue& keys_or_addrs = request.params[1].get_array();
    std::vector<CPubKey> pubkeys;
    for (unsigned int i = 0; i < keys_or_addrs.size(); ++i) {
        if (IsHex(keys_or_addrs[i].get_str()) && (keys_or_addrs[i].get_str().length() == 66 || keys_or_addrs[i].get_str().length() == 130)) {
            pubkeys.push_back(HexToPubKey(keys_or_addrs[i].get_str()));
        } else {
            pubkeys.push_back(AddrToPubKey(spk_man, keys_or_addrs[i].get_str()));
        }
    }

    OutputType output_type = pwallet->m_default_address_type;
    if (!request.params[3].isNull()) {
        if (!ParseOutputType(request.params[3].get_str(), output_type)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Unknown address type '%s'", request.params[3].get_str()));
        }
    }

    // Construct using pay-to-script-hash:
    CScript inner;
    CTxDestination dest = AddAndGetMultisigDestination(required, pubkeys, output_type, spk_man, inner);
    pwallet->SetAddressBook(dest, label, "send");

    // Make the descriptor
    std::unique_ptr<Descriptor> descriptor = InferDescriptor(DestinationAddr(dest), spk_man);

    UniValue result(UniValue::VOBJ);
    result.pushKV("address", EncodeDestination(dest));
    result.pushKV("redeemScript", HexStr(inner));
    result.pushKV("descriptor", descriptor->ToString());
    return result;
},
    };
}

struct tallyitem
{
    CAmount nAmount{0};
    int nConf{std::numeric_limits<int>::max()};
    std::vector<uint256> txids;
    bool fIsWatchonly{false};
    tallyitem()
    {
    }
};

static UniValue ListReceived(const CWallet* const pwallet, const UniValue& params, bool by_label) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet)
{
    // Minimum confirmations
    int nMinDepth = 1;
    if (!params[0].isNull())
        nMinDepth = params[0].get_int();

    // Whether to include empty labels
    bool fIncludeEmpty = false;
    if (!params[1].isNull())
        fIncludeEmpty = params[1].get_bool();

    isminefilter filter = ISMINE_SPENDABLE;

    if (ParseIncludeWatchonly(params[2], *pwallet)) {
        filter |= ISMINE_WATCH_ONLY;
    }

    bool has_filtered_address = false;
    CTxDestination filtered_address = CNoDestination();
    if (!by_label && params.size() > 3) {
        if (!IsValidDestinationString(params[3].get_str())) {
            throw JSONRPCError(RPC_WALLET_ERROR, "address_filter parameter was invalid");
        }
        filtered_address = DecodeDestination(params[3].get_str());
        has_filtered_address = true;
    }

    // Tally
    std::map<CTxDestination, tallyitem> mapTally;
    for (const std::pair<const uint256, CWalletTx>& pairWtx : pwallet->mapWallet) {
        const CWalletTx& wtx = pairWtx.second;

        if (wtx.IsCoinBase() || !pwallet->chain().checkFinalTx(*wtx.tx)) {
            continue;
        }

        int nDepth = wtx.GetDepthInMainChain();
        if (nDepth < nMinDepth)
            continue;

        std::vector<CTxOutput> outputs = wtx.tx->GetOutputs();
        for (size_t i = 0; i < outputs.size(); i++)
        {
            const CTxOutput& txout = outputs[i];
            CTxDestination address;
            if (!pwallet->ExtractOutputDestination(txout, address))
                continue;

            if (has_filtered_address && !(filtered_address == address)) {
                continue;
            }

            isminefilter mine = pwallet->IsMine(address);
            if(!(mine & filter))
                continue;

            
            // Skip displaying hog-ex outputs when we have the MWEB transaction that contains the pegout.
            // The original MWEB transaction will be displayed instead.
            if (wtx.IsHogEx() && wtx.pegout_indices.size() > i) {
                mw::Hash kernel_id = wtx.pegout_indices[i].first;
                if (pwallet->FindWalletTxByKernelId(kernel_id) != nullptr) {
                    continue;
                }
            }

            tallyitem& item = mapTally[address];
            item.nAmount += pwallet->GetValue(txout);
            item.nConf = std::min(item.nConf, nDepth);
            item.txids.push_back(wtx.GetHash());
            if (mine & ISMINE_WATCH_ONLY)
                item.fIsWatchonly = true;
        }

        for (const PegOutCoin& pegout : wtx.tx->mweb_tx.GetPegOuts())
        {
            CTxDestination address;
            if (!::ExtractDestination(pegout.GetScriptPubKey(), address))
                continue;

            if (has_filtered_address && !(filtered_address == address)) {
                continue;
            }

            isminefilter mine = pwallet->IsMine(address);
            if(!(mine & filter))
                continue;

            tallyitem& item = mapTally[address];
            item.nAmount += pegout.GetAmount();
            item.nConf = std::min(item.nConf, nDepth);
            item.txids.push_back(wtx.GetHash());
            if (mine & ISMINE_WATCH_ONLY)
                item.fIsWatchonly = true;
        }
    }

    // Reply
    UniValue ret(UniValue::VARR);
    std::map<std::string, tallyitem> label_tally;

    // Create m_address_book iterator
    // If we aren't filtering, go from begin() to end()
    auto start = pwallet->m_address_book.begin();
    auto end = pwallet->m_address_book.end();
    // If we are filtering, find() the applicable entry
    if (has_filtered_address) {
        start = pwallet->m_address_book.find(filtered_address);
        if (start != end) {
            end = std::next(start);
        }
    }

    for (auto item_it = start; item_it != end; ++item_it)
    {
        if (item_it->second.IsChange()) continue;
        const CTxDestination& address = item_it->first;
        const std::string& label = item_it->second.GetLabel();
        auto it = mapTally.find(address);
        if (it == mapTally.end() && !fIncludeEmpty)
            continue;

        CAmount nAmount = 0;
        int nConf = std::numeric_limits<int>::max();
        bool fIsWatchonly = false;
        if (it != mapTally.end())
        {
            nAmount = (*it).second.nAmount;
            nConf = (*it).second.nConf;
            fIsWatchonly = (*it).second.fIsWatchonly;
        }

        if (by_label)
        {
            tallyitem& _item = label_tally[label];
            _item.nAmount += nAmount;
            _item.nConf = std::min(_item.nConf, nConf);
            _item.fIsWatchonly = fIsWatchonly;
        }
        else
        {
            UniValue obj(UniValue::VOBJ);
            if(fIsWatchonly)
                obj.pushKV("involvesWatchonly", true);
            obj.pushKV("address",       EncodeDestination(address));
            obj.pushKV("amount",        ValueFromAmount(nAmount));
            obj.pushKV("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf));
            obj.pushKV("label", label);
            UniValue transactions(UniValue::VARR);
            if (it != mapTally.end())
            {
                for (const uint256& _item : (*it).second.txids)
                {
                    transactions.push_back(_item.GetHex());
                }
            }
            obj.pushKV("txids", transactions);
            ret.push_back(obj);
        }
    }

    if (by_label)
    {
        for (const auto& entry : label_tally)
        {
            CAmount nAmount = entry.second.nAmount;
            int nConf = entry.second.nConf;
            UniValue obj(UniValue::VOBJ);
            if (entry.second.fIsWatchonly)
                obj.pushKV("involvesWatchonly", true);
            obj.pushKV("amount",        ValueFromAmount(nAmount));
            obj.pushKV("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf));
            obj.pushKV("label",         entry.first);
            ret.push_back(obj);
        }
    }

    return ret;
}

static RPCHelpMan listreceivedbyaddress()
{
    return RPCHelpMan{"listreceivedbyaddress",
                "\nList balances by receiving address.\n",
                {
                    {"minconf", RPCArg::Type::NUM, /* default */ "1", "The minimum number of confirmations before payments are included."},
                    {"include_empty", RPCArg::Type::BOOL, /* default */ "false", "Whether to include addresses that haven't received any payments."},
                    {"include_watchonly", RPCArg::Type::BOOL, /* default */ "true for watch-only wallets, otherwise false", "Whether to include watch-only addresses (see 'importaddress')"},
                    {"address_filter", RPCArg::Type::STR, RPCArg::Optional::OMITTED_NAMED_ARG, "If present, only return information on this address."},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::BOOL, "involvesWatchonly", "Only returns true if imported addresses were involved in transaction"},
                            {RPCResult::Type::STR, "address", "The receiving address"},
                            {RPCResult::Type::STR_AMOUNT, "amount", "The total amount in " + CURRENCY_UNIT + " received by the address"},
                            {RPCResult::Type::NUM, "confirmations", "The number of confirmations of the most recent transaction included"},
                            {RPCResult::Type::STR, "label", "The label of the receiving address. The default label is \"\""},
                            {RPCResult::Type::ARR, "txids", "",
                            {
                                {RPCResult::Type::STR_HEX, "txid", "The ids of transactions received with the address"},
                            }},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("listreceivedbyaddress", "")
            + HelpExampleCli("listreceivedbyaddress", "6 true")
            + HelpExampleRpc("listreceivedbyaddress", "6, true, true")
            + HelpExampleRpc("listreceivedbyaddress", "6, true, true, \"" + EXAMPLE_ADDRESS[0] + "\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    const CWallet* const pwallet = wallet.get();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    return ListReceived(pwallet, request.params, false);
},
    };
}

static RPCHelpMan listreceivedbylabel()
{
    return RPCHelpMan{"listreceivedbylabel",
                "\nList received transactions by label.\n",
                {
                    {"minconf", RPCArg::Type::NUM, /* default */ "1", "The minimum number of confirmations before payments are included."},
                    {"include_empty", RPCArg::Type::BOOL, /* default */ "false", "Whether to include labels that haven't received any payments."},
                    {"include_watchonly", RPCArg::Type::BOOL, /* default */ "true for watch-only wallets, otherwise false", "Whether to include watch-only addresses (see 'importaddress')"},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::BOOL, "involvesWatchonly", "Only returns true if imported addresses were involved in transaction"},
                            {RPCResult::Type::STR_AMOUNT, "amount", "The total amount received by addresses with this label"},
                            {RPCResult::Type::NUM, "confirmations", "The number of confirmations of the most recent transaction included"},
                            {RPCResult::Type::STR, "label", "The label of the receiving address. The default label is \"\""},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("listreceivedbylabel", "")
            + HelpExampleCli("listreceivedbylabel", "6 true")
            + HelpExampleRpc("listreceivedbylabel", "6, true, true")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    const CWallet* const pwallet = wallet.get();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    return ListReceived(pwallet, request.params, true);
},
    };
}

static void MaybePushAddress(UniValue & entry, const CTxDestination &dest)
{
    if (IsValidDestination(dest)) {
        entry.pushKV("address", EncodeDestination(dest));
    }
}

/**
 * List transactions based on the given criteria.
 *
 * @param  pwallet        The wallet.
 * @param  wtx            The wallet transaction.
 * @param  nMinDepth      The minimum confirmation depth.
 * @param  fLong          Whether to include the JSON version of the transaction.
 * @param  ret            The UniValue into which the result is stored.
 * @param  filter_ismine  The "is mine" filter flags.
 * @param  filter_label   Optional label string to filter incoming transactions.
 */
static void ListTransactions(const CWallet* const pwallet, const CWalletTx& wtx, int nMinDepth, bool fLong, UniValue& ret, const isminefilter& filter_ismine, const std::string* filter_label) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet)
{
    CAmount nFee;
    std::list<COutputEntry> listReceived;
    std::list<COutputEntry> listSent;

    wtx.GetAmounts(listReceived, listSent, nFee, filter_ismine);

    bool involvesWatchonly = wtx.IsFromMe(ISMINE_WATCH_ONLY);

    // Sent
    if (!filter_label)
    {
        for (const COutputEntry& s : listSent)
        {
            UniValue entry(UniValue::VOBJ);
            if (involvesWatchonly || (pwallet->IsMine(s.destination) & ISMINE_WATCH_ONLY)) {
                entry.pushKV("involvesWatchonly", true);
            }
            MaybePushAddress(entry, s.destination);
            entry.pushKV("category", "send");
            entry.pushKV("amount", ValueFromAmount(-s.amount));
            const auto* address_book_entry = pwallet->FindAddressBookEntry(s.destination);
            if (address_book_entry) {
                entry.pushKV("label", address_book_entry->GetLabel());
            }

            if (s.index.type() == typeid(COutPoint)) {
                entry.pushKV("vout", (int)boost::get<COutPoint>(s.index).n);
            } else if (!boost::get<mw::Hash>(s.index).IsZero()) {
                entry.pushKV("mweb_out", boost::get<mw::Hash>(s.index).ToHex());
            }

            entry.pushKV("fee", ValueFromAmount(-nFee));
            if (fLong)
                WalletTxToJSON(pwallet->chain(), wtx, entry);
            entry.pushKV("abandoned", wtx.isAbandoned());
            ret.push_back(entry);
        }
    }

    // Received
    if (listReceived.size() > 0 && wtx.GetDepthInMainChain() >= nMinDepth) {
        for (const COutputEntry& r : listReceived)
        {
            std::string label;
            const auto* address_book_entry = pwallet->FindAddressBookEntry(r.destination);
            if (address_book_entry) {
                label = address_book_entry->GetLabel();
            }
            if (filter_label && label != *filter_label) {
                continue;
            }
            UniValue entry(UniValue::VOBJ);
            if (involvesWatchonly || (pwallet->IsMine(r.destination) & ISMINE_WATCH_ONLY)) {
                entry.pushKV("involvesWatchonly", true);
            }
            MaybePushAddress(entry, r.destination);
            if (wtx.IsCoinBase() || wtx.IsHogEx())
            {
                if (wtx.GetDepthInMainChain() < 1)
                    entry.pushKV("category", "orphan");
                else if (wtx.IsImmature())
                    entry.pushKV("category", "immature");
                else if (wtx.IsCoinBase())
                    entry.pushKV("category", "generate");
                else
                    entry.pushKV("category", "hogex");
            }
            else
            {
                entry.pushKV("category", "receive");
            }
            entry.pushKV("amount", ValueFromAmount(r.amount));
            if (address_book_entry) {
                entry.pushKV("label", label);
            }

            if (r.index.type() == typeid(COutPoint)) {
                entry.pushKV("vout", (int)boost::get<COutPoint>(r.index).n);
            } else {
                entry.pushKV("mweb_out", boost::get<mw::Hash>(r.index).ToHex());
            }

            if (fLong)
                WalletTxToJSON(pwallet->chain(), wtx, entry);
            ret.push_back(entry);
        }
    }
}

static const std::vector<RPCResult> TransactionDescriptionString()
{
    return{{RPCResult::Type::NUM, "confirmations", "The number of confirmations for the transaction. Negative confirmations means the\n"
               "transaction conflicted that many blocks ago."},
           {RPCResult::Type::BOOL, "generated", "Only present if transaction only input is a coinbase one."},
           {RPCResult::Type::BOOL, "trusted", "Only present if we consider transaction to be trusted and so safe to spend from."},
           {RPCResult::Type::STR_HEX, "blockhash", "The block hash containing the transaction."},
           {RPCResult::Type::NUM, "blockheight", "The block height containing the transaction."},
           {RPCResult::Type::NUM, "blockindex", "The index of the transaction in the block that includes it."},
           {RPCResult::Type::NUM_TIME, "blocktime", "The block time expressed in " + UNIX_EPOCH_TIME + "."},
           {RPCResult::Type::STR_HEX, "txid", "The transaction id."},
           {RPCResult::Type::ARR, "walletconflicts", "Conflicting transaction ids.",
           {
               {RPCResult::Type::STR_HEX, "txid", "The transaction id."},
           }},
           {RPCResult::Type::NUM_TIME, "time", "The transaction time expressed in " + UNIX_EPOCH_TIME + "."},
           {RPCResult::Type::NUM_TIME, "timereceived", "The time received expressed in " + UNIX_EPOCH_TIME + "."},
           {RPCResult::Type::STR, "comment", "If a comment is associated with the transaction, only present if not empty."},
           {RPCResult::Type::STR, "bip125-replaceable", "(\"yes|no|unknown\") Whether this transaction could be replaced due to BIP125 (replace-by-fee);\n"
               "may be unknown for unconfirmed transactions not in the mempool"}};
}

static RPCHelpMan listtransactions()
{
    return RPCHelpMan{"listtransactions",
                "\nIf a label name is provided, this will return only incoming transactions paying to addresses with the specified label.\n"
                "\nReturns up to 'count' most recent transactions skipping the first 'from' transactions.\n",
                {
                    {"label|dummy", RPCArg::Type::STR, RPCArg::Optional::OMITTED_NAMED_ARG, "If set, should be a valid label name to return only incoming transactions\n"
                          "with the specified label, or \"*\" to disable filtering and return all transactions."},
                    {"count", RPCArg::Type::NUM, /* default */ "10", "The number of transactions to return"},
                    {"skip", RPCArg::Type::NUM, /* default */ "0", "The number of transactions to skip"},
                    {"include_watchonly", RPCArg::Type::BOOL, /* default */ "true for watch-only wallets, otherwise false", "Include transactions to watch-only addresses (see 'importaddress')"},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::OBJ, "", "", Cat(Cat<std::vector<RPCResult>>(
                        {
                            {RPCResult::Type::BOOL, "involvesWatchonly", "Only returns true if imported addresses were involved in transaction."},
                            {RPCResult::Type::STR, "address", "The litecoin address of the transaction."},
                            {RPCResult::Type::STR, "category", "The transaction category.\n"
                                "\"send\"                  Transactions sent.\n"
                                "\"receive\"               Non-coinbase transactions received.\n"
                                "\"generate\"              Coinbase transactions received with more than 100 confirmations.\n"
                                "\"immature\"              Coinbase transactions received with 100 or fewer confirmations.\n"
                                "\"orphan\"                Orphaned coinbase transactions received."},
                            {RPCResult::Type::STR_AMOUNT, "amount", "The amount in " + CURRENCY_UNIT + ". This is negative for the 'send' category, and is positive\n"
                                "for all other categories"},
                            {RPCResult::Type::STR, "label", "A comment for the address/transaction, if any"},
                            {RPCResult::Type::NUM, "vout", "the vout value"},
                            {RPCResult::Type::STR_AMOUNT, "fee", "The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the\n"
                                 "'send' category of transactions."},
                        },
                        TransactionDescriptionString()),
                        {
                            {RPCResult::Type::BOOL, "abandoned", "'true' if the transaction has been abandoned (inputs are respendable). Only available for the \n"
                                 "'send' category of transactions."},
                        })},
                    }
                },
                RPCExamples{
            "\nList the most recent 10 transactions in the systems\n"
            + HelpExampleCli("listtransactions", "") +
            "\nList transactions 100 to 120\n"
            + HelpExampleCli("listtransactions", "\"*\" 20 100") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("listtransactions", "\"*\", 20, 100")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    const CWallet* const pwallet = wallet.get();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    const std::string* filter_label = nullptr;
    if (!request.params[0].isNull() && request.params[0].get_str() != "*") {
        filter_label = &request.params[0].get_str();
        if (filter_label->empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Label argument must be a valid label name or \"*\".");
        }
    }
    int nCount = 10;
    if (!request.params[1].isNull())
        nCount = request.params[1].get_int();
    int nFrom = 0;
    if (!request.params[2].isNull())
        nFrom = request.params[2].get_int();
    isminefilter filter = ISMINE_SPENDABLE;

    if (ParseIncludeWatchonly(request.params[3], *pwallet)) {
        filter |= ISMINE_WATCH_ONLY;
    }

    if (nCount < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative count");
    if (nFrom < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative from");

    UniValue ret(UniValue::VARR);

    {
        LOCK(pwallet->cs_wallet);

        const CWallet::TxItems & txOrdered = pwallet->wtxOrdered;

        // iterate backwards until we have nCount items to return:
        for (CWallet::TxItems::const_reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it)
        {
            CWalletTx *const pwtx = (*it).second;
            ListTransactions(pwallet, *pwtx, 0, true, ret, filter, filter_label);
            if ((int)ret.size() >= (nCount+nFrom)) break;
        }
    }

    // ret is newest to oldest

    if (nFrom > (int)ret.size())
        nFrom = ret.size();
    if ((nFrom + nCount) > (int)ret.size())
        nCount = ret.size() - nFrom;

    const std::vector<UniValue>& txs = ret.getValues();
    UniValue result{UniValue::VARR};
    result.push_backV({ txs.rend() - nFrom - nCount, txs.rend() - nFrom }); // Return oldest to newest
    return result;
},
    };
}

static RPCHelpMan listwallettransactions()
{
    return RPCHelpMan{"listwallettransactions",
                "\nIf a label name is provided, this will return only incoming transactions paying to addresses with the specified label.\n"
                "\nReturns the list of transactions as they would be displayed in the GUI.\n",
                {
                    {"txid", RPCArg::Type::STR, RPCArg::Optional::OMITTED_NAMED_ARG, "The transaction id"},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::OBJ, "", "", Cat(Cat<std::vector<RPCResult>>(
                        {
                            {RPCResult::Type::BOOL, "involvesWatchonly", "Only returns true if imported addresses were involved in transaction."},
                            {RPCResult::Type::STR, "address", "The litecoin address of the transaction."},
                            {RPCResult::Type::STR, "category", "The transaction category.\n"
                                "\"send\"                  Transactions sent.\n"
                                "\"receive\"               Non-coinbase transactions received.\n"
                                "\"generate\"              Coinbase transactions received with more than 100 confirmations.\n"
                                "\"immature\"              Coinbase transactions received with 100 or fewer confirmations.\n"
                                "\"orphan\"                Orphaned coinbase transactions received."},
                            {RPCResult::Type::STR_AMOUNT, "amount", "The amount in " + CURRENCY_UNIT + ". This is negative for the 'send' category, and is positive\n"
                                "for all other categories"},
                            {RPCResult::Type::STR, "label", "A comment for the address/transaction, if any"},
                            {RPCResult::Type::NUM, "vout", "the vout value"},
                            {RPCResult::Type::STR_AMOUNT, "fee", "The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the\n"
                                 "'send' category of transactions."},
                        },
                        TransactionDescriptionString()),
                        {
                            {RPCResult::Type::BOOL, "abandoned", "'true' if the transaction has been abandoned (inputs are respendable). Only available for the \n"
                                 "'send' category of transactions."},
                        })},
                    }
                },
                RPCExamples{
            "\nList the wallet's transaction records\n"
            + HelpExampleCli("listwallettransactions", "") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("listwallettransactions", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    const CWallet* const pwallet = wallet.get();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    UniValue ret(UniValue::VARR);

    {
        LOCK(pwallet->cs_wallet);

        std::vector<WalletTxRecord> tx_records;
        if (request.params[0].isNull()) {
            tx_records = TxList(*pwallet).ListAll(ISMINE_ALL);
        } else {
            uint256 hash(ParseHashV(request.params[0], "txid"));
            auto iter = pwallet->mapWallet.find(hash);
            if (iter == pwallet->mapWallet.end()) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-wallet transaction id");
            }
            
            tx_records = TxList(*pwallet).List(iter->second, ISMINE_ALL, boost::none, boost::none);
        }

        for (WalletTxRecord& tx_record : tx_records) {
            tx_record.UpdateStatusIfNeeded(pwallet->GetLastBlockHash());
        }

        std::sort(tx_records.begin(), tx_records.end(), [](const WalletTxRecord& a, const WalletTxRecord& b) {
            return a.status.sortKey > b.status.sortKey;
        });

        
        for (WalletTxRecord& tx_record : tx_records) {
            UniValue entry = tx_record.ToUniValue();
            WalletTxToJSON(pwallet->chain(), tx_record.GetWTX(), entry);
            ret.push_back(entry);
        }
    }

    return ret;
},
    };
}

static RPCHelpMan listsinceblock()
{
    return RPCHelpMan{"listsinceblock",
                "\nGet all transactions in blocks since block [blockhash], or all transactions if omitted.\n"
                "If \"blockhash\" is no longer a part of the main chain, transactions from the fork point onward are included.\n"
                "Additionally, if include_removed is set, transactions affecting the wallet which were removed are returned in the \"removed\" array.\n",
                {
                    {"blockhash", RPCArg::Type::STR, RPCArg::Optional::OMITTED_NAMED_ARG, "If set, the block hash to list transactions since, otherwise list all transactions."},
                    {"target_confirmations", RPCArg::Type::NUM, /* default */ "1", "Return the nth block hash from the main chain. e.g. 1 would mean the best block hash. Note: this is not used as a filter, but only affects [lastblock] in the return value"},
                    {"include_watchonly", RPCArg::Type::BOOL, /* default */ "true for watch-only wallets, otherwise false", "Include transactions to watch-only addresses (see 'importaddress')"},
                    {"include_removed", RPCArg::Type::BOOL, /* default */ "true", "Show transactions that were removed due to a reorg in the \"removed\" array\n"
                                                                       "(not guaranteed to work on pruned nodes)"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::ARR, "transactions", "",
                        {
                            {RPCResult::Type::OBJ, "", "", Cat(Cat<std::vector<RPCResult>>(
                            {
                                {RPCResult::Type::BOOL, "involvesWatchonly", "Only returns true if imported addresses were involved in transaction."},
                                {RPCResult::Type::STR, "address", "The litecoin address of the transaction."},
                                {RPCResult::Type::STR, "category", "The transaction category.\n"
                                    "\"send\"                  Transactions sent.\n"
                                    "\"receive\"               Non-coinbase transactions received.\n"
                                    "\"generate\"              Coinbase transactions received with more than 100 confirmations.\n"
                                    "\"immature\"              Coinbase transactions received with 100 or fewer confirmations.\n"
                                    "\"orphan\"                Orphaned coinbase transactions received."},
                                {RPCResult::Type::STR_AMOUNT, "amount", "The amount in " + CURRENCY_UNIT + ". This is negative for the 'send' category, and is positive\n"
                                    "for all other categories"},
                                {RPCResult::Type::NUM, "vout", "the vout value"},
                                {RPCResult::Type::STR_AMOUNT, "fee", "The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the\n"
                                     "'send' category of transactions."},
                            },
                            TransactionDescriptionString()),
                            {
                                {RPCResult::Type::BOOL, "abandoned", "'true' if the transaction has been abandoned (inputs are respendable). Only available for the \n"
                                     "'send' category of transactions."},
                                {RPCResult::Type::STR, "label", "A comment for the address/transaction, if any"},
                                {RPCResult::Type::STR, "to", "If a comment to is associated with the transaction."},
                            })},
                        }},
                        {RPCResult::Type::ARR, "removed", "<structure is the same as \"transactions\" above, only present if include_removed=true>\n"
                            "Note: transactions that were re-added in the active chain will appear as-is in this array, and may thus have a positive confirmation count."
                        , {{RPCResult::Type::ELISION, "", ""},}},
                        {RPCResult::Type::STR_HEX, "lastblock", "The hash of the block (target_confirmations-1) from the best block on the main chain, or the genesis hash if the referenced block does not exist yet. This is typically used to feed back into listsinceblock the next time you call it. So you would generally use a target_confirmations of say 6, so you will be continually re-notified of transactions until they've reached 6 confirmations plus any new ones"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("listsinceblock", "")
            + HelpExampleCli("listsinceblock", "\"000000000000000bacf66f7497b7dc45ef753ee9a7d38571037cdb1a57f663ad\" 6")
            + HelpExampleRpc("listsinceblock", "\"000000000000000bacf66f7497b7dc45ef753ee9a7d38571037cdb1a57f663ad\", 6")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;

    const CWallet& wallet = *pwallet;
    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    wallet.BlockUntilSyncedToCurrentChain();

    LOCK(wallet.cs_wallet);

    // The way the 'height' is initialized is just a workaround for the gcc bug #47679 since version 4.6.0.
    Optional<int> height = MakeOptional(false, int()); // Height of the specified block or the common ancestor, if the block provided was in a deactivated chain.
    Optional<int> altheight; // Height of the specified block, even if it's in a deactivated chain.
    int target_confirms = 1;
    isminefilter filter = ISMINE_SPENDABLE;

    uint256 blockId;
    if (!request.params[0].isNull() && !request.params[0].get_str().empty()) {
        blockId = ParseHashV(request.params[0], "blockhash");
        height = int{};
        altheight = int{};
        if (!wallet.chain().findCommonAncestor(blockId, wallet.GetLastBlockHash(), /* ancestor out */ FoundBlock().height(*height), /* blockId out */ FoundBlock().height(*altheight))) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
    }

    if (!request.params[1].isNull()) {
        target_confirms = request.params[1].get_int();

        if (target_confirms < 1) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter");
        }
    }

    if (ParseIncludeWatchonly(request.params[2], wallet)) {
        filter |= ISMINE_WATCH_ONLY;
    }

    bool include_removed = (request.params[3].isNull() || request.params[3].get_bool());

    int depth = height ? wallet.GetLastBlockHeight() + 1 - *height : -1;

    UniValue transactions(UniValue::VARR);

    for (const std::pair<const uint256, CWalletTx>& pairWtx : wallet.mapWallet) {
        const CWalletTx& tx = pairWtx.second;

        if (depth == -1 || abs(tx.GetDepthInMainChain()) < depth) {
            ListTransactions(&wallet, tx, 0, true, transactions, filter, nullptr /* filter_label */);
        }
    }

    // when a reorg'd block is requested, we also list any relevant transactions
    // in the blocks of the chain that was detached
    UniValue removed(UniValue::VARR);
    while (include_removed && altheight && *altheight > *height) {
        CBlock block;
        if (!wallet.chain().findBlock(blockId, FoundBlock().data(block)) || block.IsNull()) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");
        }
        for (const CTransactionRef& tx : block.vtx) {
            auto it = wallet.mapWallet.find(tx->GetHash());
            if (it != wallet.mapWallet.end()) {
                // We want all transactions regardless of confirmation count to appear here,
                // even negative confirmation ones, hence the big negative.
                ListTransactions(&wallet, it->second, -100000000, true, removed, filter, nullptr /* filter_label */);
            }
        }
        blockId = block.hashPrevBlock;
        --*altheight;
    }

    uint256 lastblock;
    target_confirms = std::min(target_confirms, wallet.GetLastBlockHeight() + 1);
    CHECK_NONFATAL(wallet.chain().findAncestorByHeight(wallet.GetLastBlockHash(), wallet.GetLastBlockHeight() + 1 - target_confirms, FoundBlock().hash(lastblock)));

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("transactions", transactions);
    if (include_removed) ret.pushKV("removed", removed);
    ret.pushKV("lastblock", lastblock.GetHex());

    return ret;
},
    };
}

static RPCHelpMan gettransaction()
{
    return RPCHelpMan{"gettransaction",
                "\nGet detailed information about in-wallet transaction <txid>\n",
                {
                    {"txid", RPCArg::Type::STR, RPCArg::Optional::NO, "The transaction id"},
                    {"include_watchonly", RPCArg::Type::BOOL, /* default */ "true for watch-only wallets, otherwise false",
                            "Whether to include watch-only addresses in balance calculation and details[]"},
                    {"verbose", RPCArg::Type::BOOL, /* default */ "false",
                            "Whether to include a `decoded` field containing the decoded transaction (equivalent to RPC decoderawtransaction)"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "", Cat(Cat<std::vector<RPCResult>>(
                    {
                        {RPCResult::Type::STR_AMOUNT, "amount", "The amount in " + CURRENCY_UNIT},
                        {RPCResult::Type::STR_AMOUNT, "fee", "The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the\n"
                                     "'send' category of transactions."},
                    },
                    TransactionDescriptionString()),
                    {
                        {RPCResult::Type::ARR, "details", "",
                        {
                            {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::BOOL, "involvesWatchonly", "Only returns true if imported addresses were involved in transaction."},
                                {RPCResult::Type::STR, "address", "The litecoin address involved in the transaction."},
                                {RPCResult::Type::STR, "category", "The transaction category.\n"
                                    "\"send\"                  Transactions sent.\n"
                                    "\"receive\"               Non-coinbase transactions received.\n"
                                    "\"generate\"              Coinbase transactions received with more than 100 confirmations.\n"
                                    "\"immature\"              Coinbase transactions received with 100 or fewer confirmations.\n"
                                    "\"orphan\"                Orphaned coinbase transactions received."},
                                {RPCResult::Type::STR_AMOUNT, "amount", "The amount in " + CURRENCY_UNIT},
                                {RPCResult::Type::STR, "label", "A comment for the address/transaction, if any"},
                                {RPCResult::Type::NUM, "vout", "the vout value"},
                                {RPCResult::Type::STR_AMOUNT, "fee", "The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the \n"
                                    "'send' category of transactions."},
                                {RPCResult::Type::BOOL, "abandoned", "'true' if the transaction has been abandoned (inputs are respendable). Only available for the \n"
                                     "'send' category of transactions."},
                            }},
                        }},
                        {RPCResult::Type::STR_HEX, "hex", "Raw data for transaction"},
                        {RPCResult::Type::OBJ, "decoded", "Optional, the decoded transaction (only present when `verbose` is passed)",
                        {
                            {RPCResult::Type::ELISION, "", "Equivalent to the RPC decoderawtransaction method, or the RPC getrawtransaction method when `verbose` is passed."},
                        }},
                    })
                },
                RPCExamples{
                    HelpExampleCli("gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
            + HelpExampleCli("gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\" true")
            + HelpExampleCli("gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\" false true")
            + HelpExampleRpc("gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    const CWallet* const pwallet = wallet.get();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    uint256 hash(ParseHashV(request.params[0], "txid"));

    isminefilter filter = ISMINE_SPENDABLE;

    if (ParseIncludeWatchonly(request.params[1], *pwallet)) {
        filter |= ISMINE_WATCH_ONLY;
    }

    bool verbose = request.params[2].isNull() ? false : request.params[2].get_bool();

    UniValue entry(UniValue::VOBJ);
    auto it = pwallet->mapWallet.find(hash);
    if (it == pwallet->mapWallet.end()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-wallet transaction id");
    }
    const CWalletTx& wtx = it->second;

    CAmount nCredit = wtx.GetCredit(filter);
    CAmount nDebit = wtx.GetDebit(filter);
    CAmount nNet = nCredit - nDebit;
    CAmount nFee = -wtx.GetFee(filter);

    entry.pushKV("amount", ValueFromAmount(nNet - nFee));
    if (wtx.IsFromMe(filter))
        entry.pushKV("fee", ValueFromAmount(nFee));

    WalletTxToJSON(pwallet->chain(), wtx, entry);

    UniValue details(UniValue::VARR);
    ListTransactions(pwallet, wtx, 0, false, details, filter, nullptr /* filter_label */);
    entry.pushKV("details", details);

    std::string strHex = EncodeHexTx(*wtx.tx, pwallet->chain().rpcSerializationFlags());
    entry.pushKV("hex", strHex);

    if (verbose) {
        UniValue decoded(UniValue::VOBJ);
        TxToUniv(*wtx.tx, uint256(), decoded, false);
        entry.pushKV("decoded", decoded);
    }

    return entry;
},
    };
}

static RPCHelpMan abandontransaction()
{
    return RPCHelpMan{"abandontransaction",
                "\nMark in-wallet transaction <txid> as abandoned\n"
                "This will mark this transaction and all its in-wallet descendants as abandoned which will allow\n"
                "for their inputs to be respent.  It can be used to replace \"stuck\" or evicted transactions.\n"
                "It only works on transactions which are not included in a block and are not currently in the mempool.\n"
                "It has no effect on transactions which are already abandoned.\n",
                {
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("abandontransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
            + HelpExampleRpc("abandontransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    uint256 hash(ParseHashV(request.params[0], "txid"));

    if (!pwallet->mapWallet.count(hash)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-wallet transaction id");
    }
    if (!pwallet->AbandonTransaction(hash)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not eligible for abandonment");
    }

    return NullUniValue;
},
    };
}


static RPCHelpMan backupwallet()
{
    return RPCHelpMan{"backupwallet",
                "\nSafely copies current wallet file to destination, which can be a directory or a path with filename.\n",
                {
                    {"destination", RPCArg::Type::STR, RPCArg::Optional::NO, "The destination directory or file"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("backupwallet", "\"backup.dat\"")
            + HelpExampleRpc("backupwallet", "\"backup.dat\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    const CWallet* const pwallet = wallet.get();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    std::string strDest = request.params[0].get_str();
    if (!pwallet->BackupWallet(strDest)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Wallet backup failed!");
    }

    return NullUniValue;
},
    };
}


static RPCHelpMan keypoolrefill()
{
    return RPCHelpMan{"keypoolrefill",
                "\nFills the keypool."+
        HELP_REQUIRING_PASSPHRASE,
                {
                    {"newsize", RPCArg::Type::NUM, /* default */ "100", "The new keypool size"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("keypoolrefill", "")
            + HelpExampleRpc("keypoolrefill", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    if (pwallet->IsLegacy() && pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Private keys are disabled for this wallet");
    }

    LOCK(pwallet->cs_wallet);

    // 0 is interpreted by TopUpKeyPool() as the default keypool size given by -keypool
    unsigned int kpSize = 0;
    if (!request.params[0].isNull()) {
        if (request.params[0].get_int() < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected valid size.");
        kpSize = (unsigned int)request.params[0].get_int();
    }

    EnsureWalletIsUnlocked(pwallet);
    pwallet->TopUpKeyPool(kpSize);

    if (pwallet->GetKeyPoolSize() < kpSize) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error refreshing keypool.");
    }

    return NullUniValue;
},
    };
}


static RPCHelpMan walletpassphrase()
{
    return RPCHelpMan{"walletpassphrase",
                "\nStores the wallet decryption key in memory for 'timeout' seconds.\n"
                "This is needed prior to performing transactions related to private keys such as sending litecoins\n"
            "\nNote:\n"
            "Issuing the walletpassphrase command while the wallet is already unlocked will set a new unlock\n"
            "time that overrides the old one.\n",
                {
                    {"passphrase", RPCArg::Type::STR, RPCArg::Optional::NO, "The wallet passphrase"},
                    {"timeout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The time to keep the decryption key in seconds; capped at 100000000 (~3 years)."},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
            "\nUnlock the wallet for 60 seconds\n"
            + HelpExampleCli("walletpassphrase", "\"my pass phrase\" 60") +
            "\nLock the wallet again (before 60 seconds)\n"
            + HelpExampleCli("walletlock", "") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("walletpassphrase", "\"my pass phrase\", 60")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    int64_t nSleepTime;
    int64_t relock_time;
    // Prevent concurrent calls to walletpassphrase with the same wallet.
    LOCK(pwallet->m_unlock_mutex);
    {
        LOCK(pwallet->cs_wallet);

        if (!pwallet->IsCrypted()) {
            throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletpassphrase was called.");
        }

        // Note that the walletpassphrase is stored in request.params[0] which is not mlock()ed
        SecureString strWalletPass;
        strWalletPass.reserve(100);
        // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
        // Alternately, find a way to make request.params[0] mlock()'d to begin with.
        strWalletPass = request.params[0].get_str().c_str();

        // Get the timeout
        nSleepTime = request.params[1].get_int64();
        // Timeout cannot be negative, otherwise it will relock immediately
        if (nSleepTime < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Timeout cannot be negative.");
        }
        // Clamp timeout
        constexpr int64_t MAX_SLEEP_TIME = 100000000; // larger values trigger a macos/libevent bug?
        if (nSleepTime > MAX_SLEEP_TIME) {
            nSleepTime = MAX_SLEEP_TIME;
        }

        if (strWalletPass.empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "passphrase can not be empty");
        }

        if (!pwallet->Unlock(strWalletPass)) {
            throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");
        }

        pwallet->TopUpKeyPool();

        pwallet->nRelockTime = GetTime() + nSleepTime;
        relock_time = pwallet->nRelockTime;
    }

    // rpcRunLater must be called without cs_wallet held otherwise a deadlock
    // can occur. The deadlock would happen when RPCRunLater removes the
    // previous timer (and waits for the callback to finish if already running)
    // and the callback locks cs_wallet.
    AssertLockNotHeld(wallet->cs_wallet);
    // Keep a weak pointer to the wallet so that it is possible to unload the
    // wallet before the following callback is called. If a valid shared pointer
    // is acquired in the callback then the wallet is still loaded.
    std::weak_ptr<CWallet> weak_wallet = wallet;
    pwallet->chain().rpcRunLater(strprintf("lockwallet(%s)", pwallet->GetName()), [weak_wallet, relock_time] {
        if (auto shared_wallet = weak_wallet.lock()) {
            LOCK(shared_wallet->cs_wallet);
            // Skip if this is not the most recent rpcRunLater callback.
            if (shared_wallet->nRelockTime != relock_time) return;
            shared_wallet->Lock();
            shared_wallet->nRelockTime = 0;
        }
    }, nSleepTime);

    return NullUniValue;
},
    };
}


static RPCHelpMan walletpassphrasechange()
{
    return RPCHelpMan{"walletpassphrasechange",
                "\nChanges the wallet passphrase from 'oldpassphrase' to 'newpassphrase'.\n",
                {
                    {"oldpassphrase", RPCArg::Type::STR, RPCArg::Optional::NO, "The current passphrase"},
                    {"newpassphrase", RPCArg::Type::STR, RPCArg::Optional::NO, "The new passphrase"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("walletpassphrasechange", "\"old one\" \"new one\"")
            + HelpExampleRpc("walletpassphrasechange", "\"old one\", \"new one\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    LOCK(pwallet->cs_wallet);

    if (!pwallet->IsCrypted()) {
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletpassphrasechange was called.");
    }

    // TODO: get rid of these .c_str() calls by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make request.params[0] mlock()'d to begin with.
    SecureString strOldWalletPass;
    strOldWalletPass.reserve(100);
    strOldWalletPass = request.params[0].get_str().c_str();

    SecureString strNewWalletPass;
    strNewWalletPass.reserve(100);
    strNewWalletPass = request.params[1].get_str().c_str();

    if (strOldWalletPass.empty() || strNewWalletPass.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "passphrase can not be empty");
    }

    if (!pwallet->ChangeWalletPassphrase(strOldWalletPass, strNewWalletPass)) {
        throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");
    }

    return NullUniValue;
},
    };
}


static RPCHelpMan walletlock()
{
    return RPCHelpMan{"walletlock",
                "\nRemoves the wallet encryption key from memory, locking the wallet.\n"
                "After calling this method, you will need to call walletpassphrase again\n"
                "before being able to call any methods which require the wallet to be unlocked.\n",
                {},
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
            "\nSet the passphrase for 2 minutes to perform a transaction\n"
            + HelpExampleCli("walletpassphrase", "\"my pass phrase\" 120") +
            "\nPerform a send (requires passphrase set)\n"
            + HelpExampleCli("sendtoaddress", "\"" + EXAMPLE_ADDRESS[0] + "\" 1.0") +
            "\nClear the passphrase since we are done before 2 minutes is up\n"
            + HelpExampleCli("walletlock", "") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("walletlock", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    LOCK(pwallet->cs_wallet);

    if (!pwallet->IsCrypted()) {
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletlock was called.");
    }

    pwallet->Lock();
    pwallet->nRelockTime = 0;

    return NullUniValue;
},
    };
}


static RPCHelpMan encryptwallet()
{
    return RPCHelpMan{"encryptwallet",
                "\nEncrypts the wallet with 'passphrase'. This is for first time encryption.\n"
                "After this, any calls that interact with private keys such as sending or signing \n"
                "will require the passphrase to be set prior the making these calls.\n"
                "Use the walletpassphrase call for this, and then walletlock call.\n"
                "If the wallet is already encrypted, use the walletpassphrasechange call.\n",
                {
                    {"passphrase", RPCArg::Type::STR, RPCArg::Optional::NO, "The pass phrase to encrypt the wallet with. It must be at least 1 character, but should be long."},
                },
                RPCResult{RPCResult::Type::STR, "", "A string with further instructions"},
                RPCExamples{
            "\nEncrypt your wallet\n"
            + HelpExampleCli("encryptwallet", "\"my pass phrase\"") +
            "\nNow set the passphrase to use the wallet, such as for signing or sending litecoin\n"
            + HelpExampleCli("walletpassphrase", "\"my pass phrase\"") +
            "\nNow we can do something like sign\n"
            + HelpExampleCli("signmessage", "\"address\" \"test message\"") +
            "\nNow lock the wallet again by removing the passphrase\n"
            + HelpExampleCli("walletlock", "") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("encryptwallet", "\"my pass phrase\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    LOCK(pwallet->cs_wallet);

    if (pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        throw JSONRPCError(RPC_WALLET_ENCRYPTION_FAILED, "Error: wallet does not contain private keys, nothing to encrypt.");
    }

    if (pwallet->IsCrypted()) {
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an encrypted wallet, but encryptwallet was called.");
    }

    // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make request.params[0] mlock()'d to begin with.
    SecureString strWalletPass;
    strWalletPass.reserve(100);
    strWalletPass = request.params[0].get_str().c_str();

    if (strWalletPass.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "passphrase can not be empty");
    }

    if (!pwallet->EncryptWallet(strWalletPass)) {
        throw JSONRPCError(RPC_WALLET_ENCRYPTION_FAILED, "Error: Failed to encrypt the wallet.");
    }

    return "wallet encrypted; The keypool has been flushed and a new HD seed was generated (if you are using HD). You need to make a new backup.";
},
    };
}

static RPCHelpMan lockunspent()
{
    return RPCHelpMan{"lockunspent",
                "\nUpdates list of temporarily unspendable outputs.\n"
                "Temporarily lock (unlock=false) or unlock (unlock=true) specified transaction outputs.\n"
                "If no transaction outputs are specified when unlocking then all current locked transaction outputs are unlocked.\n"
                "A locked transaction output will not be chosen by automatic coin selection, when spending litecoins.\n"
                "Manually selected coins are automatically unlocked.\n"
                "Locks are stored in memory only. Nodes start with zero locked outputs, and the locked output list\n"
                "is always cleared (by virtue of process exit) when a node stops or fails.\n"
                "Also see the listunspent call\n",
                {
                    {"unlock", RPCArg::Type::BOOL, RPCArg::Optional::NO, "Whether to unlock (true) or lock (false) the specified transactions"},
                    {"transactions", RPCArg::Type::ARR, /* default */ "empty array", "The transaction outputs and within each, the txid (string) vout (numeric).",
                        {
                            {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                                {
                                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                                    {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                                },
                            },
                        },
                    },
                },
                RPCResult{
                    RPCResult::Type::BOOL, "", "Whether the command was successful or not"
                },
                RPCExamples{
            "\nList the unspent transactions\n"
            + HelpExampleCli("listunspent", "") +
            "\nLock an unspent transaction\n"
            + HelpExampleCli("lockunspent", "false \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
            "\nList the locked transactions\n"
            + HelpExampleCli("listlockunspent", "") +
            "\nUnlock the transaction again\n"
            + HelpExampleCli("lockunspent", "true \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("lockunspent", "false, \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    RPCTypeCheckArgument(request.params[0], UniValue::VBOOL);

    bool fUnlock = request.params[0].get_bool();

    if (request.params[1].isNull()) {
        if (fUnlock)
            pwallet->UnlockAllCoins();
        return true;
    }

    RPCTypeCheckArgument(request.params[1], UniValue::VARR);

    const UniValue& output_params = request.params[1];

    // Create and validate the COutPoints first.

    std::vector<COutPoint> outputs;
    outputs.reserve(output_params.size());

    for (unsigned int idx = 0; idx < output_params.size(); idx++) {
        const UniValue& o = output_params[idx].get_obj();

        // MW: TODO - Support locking MWEB output IDs
        RPCTypeCheckObj(o,
            {
                {"txid", UniValueType(UniValue::VSTR)},
                {"vout", UniValueType(UniValue::VNUM)},
            });

        const uint256 txid(ParseHashO(o, "txid"));
        const int nOutput = find_value(o, "vout").get_int();
        if (nOutput < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout cannot be negative");
        }

        const COutPoint outpt(txid, nOutput);

        const auto it = pwallet->mapWallet.find(outpt.hash);
        if (it == pwallet->mapWallet.end()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, unknown transaction");
        }

        const CWalletTx& trans = it->second;

        if (outpt.n >= trans.tx->vout.size()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout index out of bounds");
        }

        if (pwallet->IsSpent(COutPoint(outpt.hash, outpt.n))) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected unspent output");
        }

        const bool is_locked = pwallet->IsLockedCoin(outpt);

        if (fUnlock && !is_locked) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected locked output");
        }

        if (!fUnlock && is_locked) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, output already locked");
        }

        outputs.push_back(outpt);
    }

    // Atomically set (un)locked status for the outputs.
    for (const COutPoint& outpt : outputs) {
        if (fUnlock) pwallet->UnlockCoin(outpt);
        else pwallet->LockCoin(outpt);
    }

    return true;
},
    };
}

static RPCHelpMan listlockunspent()
{
    return RPCHelpMan{"listlockunspent",
                "\nReturns list of temporarily unspendable outputs.\n"
                "See the lockunspent call to lock and unlock transactions for spending.\n",
                {},
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "txid", "The transaction id locked"},
                            {RPCResult::Type::NUM, "vout", "The vout value"},
                        }},
                    }
                },
                RPCExamples{
            "\nList the unspent transactions\n"
            + HelpExampleCli("listunspent", "") +
            "\nLock an unspent transaction\n"
            + HelpExampleCli("lockunspent", "false \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
            "\nList the locked transactions\n"
            + HelpExampleCli("listlockunspent", "") +
            "\nUnlock the transaction again\n"
            + HelpExampleCli("lockunspent", "true \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("listlockunspent", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    const CWallet* const pwallet = wallet.get();

    LOCK(pwallet->cs_wallet);

    std::vector<OutputIndex> vOutpts;
    pwallet->ListLockedCoins(vOutpts);

    UniValue ret(UniValue::VARR);

    for (const OutputIndex& output : vOutpts) {
        UniValue o(UniValue::VOBJ);

        if (output.type() == typeid(COutPoint)) {
            const COutPoint& outpt = boost::get<COutPoint>(output);
            o.pushKV("txid", outpt.hash.GetHex());
            o.pushKV("vout", (int)outpt.n);
        } else {
            o.pushKV("mweb_out", boost::get<mw::Hash>(output).ToHex());
        }

        ret.push_back(o);
    }

    return ret;
},
    };
}

static RPCHelpMan settxfee()
{
    return RPCHelpMan{"settxfee",
                "\nSet the transaction fee per kB for this wallet. Overrides the global -paytxfee command line parameter.\n"
                "Can be deactivated by passing 0 as the fee. In that case automatic fee selection will be used by default.\n",
                {
                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The transaction fee in " + CURRENCY_UNIT + "/kvB"},
                },
                RPCResult{
                    RPCResult::Type::BOOL, "", "Returns true if successful"
                },
                RPCExamples{
                    HelpExampleCli("settxfee", "0.00001")
            + HelpExampleRpc("settxfee", "0.00001")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    LOCK(pwallet->cs_wallet);

    CAmount nAmount = AmountFromValue(request.params[0]);
    CFeeRate tx_fee_rate(nAmount, 1000, 0);
    CFeeRate max_tx_fee_rate(pwallet->m_default_max_tx_fee, 1000, 0);
    if (tx_fee_rate == CFeeRate(0)) {
        // automatic selection
    } else if (tx_fee_rate < pwallet->chain().relayMinFee()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("txfee cannot be less than min relay tx fee (%s)", pwallet->chain().relayMinFee().ToString()));
    } else if (tx_fee_rate < pwallet->m_min_fee) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("txfee cannot be less than wallet min fee (%s)", pwallet->m_min_fee.ToString()));
    } else if (tx_fee_rate > max_tx_fee_rate) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("txfee cannot be more than wallet max tx fee (%s)", max_tx_fee_rate.ToString()));
    }

    pwallet->m_pay_tx_fee = tx_fee_rate;
    return true;
},
    };
}

static RPCHelpMan getbalances()
{
    return RPCHelpMan{
        "getbalances",
        "Returns an object with all balances in " + CURRENCY_UNIT + ".\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::OBJ, "mine", "balances from outputs that the wallet can sign",
                {
                    {RPCResult::Type::STR_AMOUNT, "trusted", "trusted balance (outputs created by the wallet or confirmed outputs)"},
                    {RPCResult::Type::STR_AMOUNT, "untrusted_pending", "untrusted pending balance (outputs created by others that are in the mempool)"},
                    {RPCResult::Type::STR_AMOUNT, "immature", "balance from immature coinbase outputs"},
                    {RPCResult::Type::STR_AMOUNT, "used", "(only present if avoid_reuse is set) balance from coins sent to addresses that were previously spent from (potentially privacy violating)"},
                }},
                {RPCResult::Type::OBJ, "watchonly", "watchonly balances (not present if wallet does not watch anything)",
                {
                    {RPCResult::Type::STR_AMOUNT, "trusted", "trusted balance (outputs created by the wallet or confirmed outputs)"},
                    {RPCResult::Type::STR_AMOUNT, "untrusted_pending", "untrusted pending balance (outputs created by others that are in the mempool)"},
                    {RPCResult::Type::STR_AMOUNT, "immature", "balance from immature coinbase outputs"},
                }},
            }
            },
        RPCExamples{
            HelpExampleCli("getbalances", "") +
            HelpExampleRpc("getbalances", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const rpc_wallet = GetWalletForJSONRPCRequest(request);
    if (!rpc_wallet) return NullUniValue;
    CWallet& wallet = *rpc_wallet;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    wallet.BlockUntilSyncedToCurrentChain();

    LOCK(wallet.cs_wallet);

    const auto bal = wallet.GetBalance();
    UniValue balances{UniValue::VOBJ};
    {
        UniValue balances_mine{UniValue::VOBJ};
        balances_mine.pushKV("trusted", ValueFromAmount(bal.m_mine_trusted));
        balances_mine.pushKV("untrusted_pending", ValueFromAmount(bal.m_mine_untrusted_pending));
        balances_mine.pushKV("immature", ValueFromAmount(bal.m_mine_immature));
        if (wallet.IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE)) {
            // If the AVOID_REUSE flag is set, bal has been set to just the un-reused address balance. Get
            // the total balance, and then subtract bal to get the reused address balance.
            const auto full_bal = wallet.GetBalance(0, false);
            balances_mine.pushKV("used", ValueFromAmount(full_bal.m_mine_trusted + full_bal.m_mine_untrusted_pending - bal.m_mine_trusted - bal.m_mine_untrusted_pending));
        }
        balances.pushKV("mine", balances_mine);
    }
    auto spk_man = wallet.GetLegacyScriptPubKeyMan();
    if (spk_man && spk_man->HaveWatchOnly()) {
        UniValue balances_watchonly{UniValue::VOBJ};
        balances_watchonly.pushKV("trusted", ValueFromAmount(bal.m_watchonly_trusted));
        balances_watchonly.pushKV("untrusted_pending", ValueFromAmount(bal.m_watchonly_untrusted_pending));
        balances_watchonly.pushKV("immature", ValueFromAmount(bal.m_watchonly_immature));
        balances.pushKV("watchonly", balances_watchonly);
    }
    return balances;
},
    };
}

static RPCHelpMan getwalletinfo()
{
    return RPCHelpMan{"getwalletinfo",
                "Returns an object containing various wallet state info.\n",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {
                        {RPCResult::Type::STR, "walletname", "the wallet name"},
                        {RPCResult::Type::NUM, "walletversion", "the wallet version"},
                        {RPCResult::Type::STR, "format", "the database format (bdb or sqlite)"},
                        {RPCResult::Type::STR_AMOUNT, "balance", "DEPRECATED. Identical to getbalances().mine.trusted"},
                        {RPCResult::Type::STR_AMOUNT, "unconfirmed_balance", "DEPRECATED. Identical to getbalances().mine.untrusted_pending"},
                        {RPCResult::Type::STR_AMOUNT, "immature_balance", "DEPRECATED. Identical to getbalances().mine.immature"},
                        {RPCResult::Type::NUM, "txcount", "the total number of transactions in the wallet"},
                        {RPCResult::Type::NUM_TIME, "keypoololdest", "the " + UNIX_EPOCH_TIME + " of the oldest pre-generated key in the key pool. Legacy wallets only."},
                        {RPCResult::Type::NUM, "keypoolsize", "how many new keys are pre-generated (only counts external keys)"},
                        {RPCResult::Type::NUM, "keypoolsize_hd_internal", "how many new keys are pre-generated for internal use (used for change outputs, only appears if the wallet is using this feature, otherwise external keys are used)"},
                        {RPCResult::Type::NUM_TIME, "unlocked_until", /* optional */ true, "the " + UNIX_EPOCH_TIME + " until which the wallet is unlocked for transfers, or 0 if the wallet is locked (only present for passphrase-encrypted wallets)"},
                        {RPCResult::Type::STR_AMOUNT, "paytxfee", "the transaction fee configuration, set in " + CURRENCY_UNIT + "/kvB"},
                        {RPCResult::Type::STR_HEX, "hdseedid", /* optional */ true, "the Hash160 of the HD seed (only present when HD is enabled)"},
                        {RPCResult::Type::BOOL, "private_keys_enabled", "false if privatekeys are disabled for this wallet (enforced watch-only wallet)"},
                        {RPCResult::Type::BOOL, "avoid_reuse", "whether this wallet tracks clean/dirty coins in terms of reuse"},
                        {RPCResult::Type::OBJ, "scanning", "current scanning details, or false if no scan is in progress",
                        {
                            {RPCResult::Type::NUM, "duration", "elapsed seconds since scan start"},
                            {RPCResult::Type::NUM, "progress", "scanning progress percentage [0.0, 1.0]"},
                        }},
                        {RPCResult::Type::BOOL, "descriptors", "whether this wallet uses descriptors for scriptPubKey management"},
                    }},
                },
                RPCExamples{
                    HelpExampleCli("getwalletinfo", "")
            + HelpExampleRpc("getwalletinfo", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    const CWallet* const pwallet = wallet.get();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    UniValue obj(UniValue::VOBJ);

    size_t kpExternalSize = pwallet->KeypoolCountExternalKeys();
    const auto bal = pwallet->GetBalance();
    int64_t kp_oldest = pwallet->GetOldestKeyPoolTime();
    obj.pushKV("walletname", pwallet->GetName());
    obj.pushKV("walletversion", pwallet->GetVersion());
    obj.pushKV("format", pwallet->GetDatabase().Format());
    obj.pushKV("balance", ValueFromAmount(bal.m_mine_trusted));
    obj.pushKV("unconfirmed_balance", ValueFromAmount(bal.m_mine_untrusted_pending));
    obj.pushKV("immature_balance", ValueFromAmount(bal.m_mine_immature));
    obj.pushKV("txcount",       (int)pwallet->mapWallet.size());
    if (kp_oldest > 0) {
        obj.pushKV("keypoololdest", kp_oldest);
    }
    obj.pushKV("keypoolsize", (int64_t)kpExternalSize);

    LegacyScriptPubKeyMan* spk_man = pwallet->GetLegacyScriptPubKeyMan();
    if (spk_man) {
        CKeyID seed_id = spk_man->GetHDChain().seed_id;
        if (!seed_id.IsNull()) {
            obj.pushKV("hdseedid", seed_id.GetHex());
        }
    }

    if (pwallet->CanSupportFeature(FEATURE_HD_SPLIT)) {
        obj.pushKV("keypoolsize_hd_internal",   (int64_t)(pwallet->GetKeyPoolSize() - kpExternalSize));
    }
    if (pwallet->IsCrypted()) {
        obj.pushKV("unlocked_until", pwallet->nRelockTime);
    }
    obj.pushKV("paytxfee", ValueFromAmount(pwallet->m_pay_tx_fee.GetFeePerK()));
    obj.pushKV("private_keys_enabled", !pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS));
    obj.pushKV("avoid_reuse", pwallet->IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE));
    if (pwallet->IsScanning()) {
        UniValue scanning(UniValue::VOBJ);
        scanning.pushKV("duration", pwallet->ScanningDuration() / 1000);
        scanning.pushKV("progress", pwallet->ScanningProgress());
        obj.pushKV("scanning", scanning);
    } else {
        obj.pushKV("scanning", false);
    }
    obj.pushKV("descriptors", pwallet->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));
    return obj;
},
    };
}

static RPCHelpMan listwalletdir()
{
    return RPCHelpMan{"listwalletdir",
                "Returns a list of wallets in the wallet directory.\n",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::ARR, "wallets", "",
                        {
                            {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR, "name", "The wallet name"},
                            }},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("listwalletdir", "")
            + HelpExampleRpc("listwalletdir", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue wallets(UniValue::VARR);
    for (const auto& path : ListWalletDir()) {
        UniValue wallet(UniValue::VOBJ);
        wallet.pushKV("name", path.string());
        wallets.push_back(wallet);
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("wallets", wallets);
    return result;
},
    };
}

static RPCHelpMan listwallets()
{
    return RPCHelpMan{"listwallets",
                "Returns a list of currently loaded wallets.\n"
                "For full information on the wallet, use \"getwalletinfo\"\n",
                {},
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::STR, "walletname", "the wallet name"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("listwallets", "")
            + HelpExampleRpc("listwallets", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue obj(UniValue::VARR);

    for (const std::shared_ptr<CWallet>& wallet : GetWallets()) {
        LOCK(wallet->cs_wallet);
        obj.push_back(wallet->GetName());
    }

    return obj;
},
    };
}

static RPCHelpMan loadwallet()
{
    return RPCHelpMan{"loadwallet",
                "\nLoads a wallet from a wallet file or directory."
                "\nNote that all wallet command-line options used when starting litecoind will be"
                "\napplied to the new wallet (eg -rescan, etc).\n",
                {
                    {"filename", RPCArg::Type::STR, RPCArg::Optional::NO, "The wallet directory or .dat file."},
                    {"load_on_startup", RPCArg::Type::BOOL, /* default */ "null", "Save wallet name to persistent settings and load on startup. True to add wallet to startup list, false to remove, null to leave unchanged."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "name", "The wallet name if loaded successfully."},
                        {RPCResult::Type::STR, "warning", "Warning message if wallet was not loaded cleanly."},
                    }
                },
                RPCExamples{
                    HelpExampleCli("loadwallet", "\"test.dat\"")
            + HelpExampleRpc("loadwallet", "\"test.dat\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    WalletContext& context = EnsureWalletContext(request.context);
    const std::string name(request.params[0].get_str());

    DatabaseOptions options;
    DatabaseStatus status;
    options.require_existing = true;
    bilingual_str error;
    std::vector<bilingual_str> warnings;
    Optional<bool> load_on_start = request.params[1].isNull() ? nullopt : Optional<bool>(request.params[1].get_bool());
    std::shared_ptr<CWallet> const wallet = LoadWallet(*context.chain, name, load_on_start, options, status, error, warnings);
    if (!wallet) {
        // Map bad format to not found, since bad format is returned when the
        // wallet directory exists, but doesn't contain a data file.
        RPCErrorCode code = status == DatabaseStatus::FAILED_NOT_FOUND || status == DatabaseStatus::FAILED_BAD_FORMAT ? RPC_WALLET_NOT_FOUND : RPC_WALLET_ERROR;
        throw JSONRPCError(code, error.original);
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("name", wallet->GetName());
    obj.pushKV("warning", Join(warnings, Untranslated("\n")).original);

    return obj;
},
    };
}

static RPCHelpMan setwalletflag()
{
            std::string flags = "";
            for (auto& it : WALLET_FLAG_MAP)
                if (it.second & MUTABLE_WALLET_FLAGS)
                    flags += (flags == "" ? "" : ", ") + it.first;

    return RPCHelpMan{"setwalletflag",
                "\nChange the state of the given wallet flag for a wallet.\n",
                {
                    {"flag", RPCArg::Type::STR, RPCArg::Optional::NO, "The name of the flag to change. Current available flags: " + flags},
                    {"value", RPCArg::Type::BOOL, /* default */ "true", "The new state."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "flag_name", "The name of the flag that was modified"},
                        {RPCResult::Type::BOOL, "flag_state", "The new state of the flag"},
                        {RPCResult::Type::STR, "warnings", "Any warnings associated with the change"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("setwalletflag", "avoid_reuse")
                  + HelpExampleRpc("setwalletflag", "\"avoid_reuse\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    std::string flag_str = request.params[0].get_str();
    bool value = request.params[1].isNull() || request.params[1].get_bool();

    if (!WALLET_FLAG_MAP.count(flag_str)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Unknown wallet flag: %s", flag_str));
    }

    auto flag = WALLET_FLAG_MAP.at(flag_str);

    if (!(flag & MUTABLE_WALLET_FLAGS)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Wallet flag is immutable: %s", flag_str));
    }

    UniValue res(UniValue::VOBJ);

    if (pwallet->IsWalletFlagSet(flag) == value) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Wallet flag is already set to %s: %s", value ? "true" : "false", flag_str));
    }

    res.pushKV("flag_name", flag_str);
    res.pushKV("flag_state", value);

    if (value) {
        pwallet->SetWalletFlag(flag);
    } else {
        pwallet->UnsetWalletFlag(flag);
    }

    if (flag && value && WALLET_FLAG_CAVEATS.count(flag)) {
        res.pushKV("warnings", WALLET_FLAG_CAVEATS.at(flag));
    }

    return res;
},
    };
}

static RPCHelpMan createwallet()
{
    return RPCHelpMan{
        "createwallet",
        "\nCreates and loads a new wallet.\n",
        {
            {"wallet_name", RPCArg::Type::STR, RPCArg::Optional::NO, "The name for the new wallet. If this is a path, the wallet will be created at the path location."},
            {"disable_private_keys", RPCArg::Type::BOOL, /* default */ "false", "Disable the possibility of private keys (only watchonlys are possible in this mode)."},
            {"blank", RPCArg::Type::BOOL, /* default */ "false", "Create a blank wallet. A blank wallet has no keys or HD seed. One can be set using sethdseed."},
            {"passphrase", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Encrypt the wallet with this passphrase."},
            {"avoid_reuse", RPCArg::Type::BOOL, /* default */ "false", "Keep track of coin reuse, and treat dirty and clean coins differently with privacy considerations in mind."},
            {"descriptors", RPCArg::Type::BOOL, /* default */ "false", "Create a native descriptor wallet. The wallet will use descriptors internally to handle address creation"},
            {"load_on_startup", RPCArg::Type::BOOL, /* default */ "null", "Save wallet name to persistent settings and load on startup. True to add wallet to startup list, false to remove, null to leave unchanged."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "name", "The wallet name if created successfully. If the wallet was created using a full path, the wallet_name will be the full path."},
                {RPCResult::Type::STR, "warning", "Warning message if wallet was not loaded cleanly."},
            }
        },
        RPCExamples{
            HelpExampleCli("createwallet", "\"testwallet\"")
            + HelpExampleRpc("createwallet", "\"testwallet\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    WalletContext& context = EnsureWalletContext(request.context);
    uint64_t flags = 0;
    if (!request.params[1].isNull() && request.params[1].get_bool()) {
        flags |= WALLET_FLAG_DISABLE_PRIVATE_KEYS;
    }

    if (!request.params[2].isNull() && request.params[2].get_bool()) {
        flags |= WALLET_FLAG_BLANK_WALLET;
    }
    SecureString passphrase;
    passphrase.reserve(100);
    std::vector<bilingual_str> warnings;
    if (!request.params[3].isNull()) {
        passphrase = request.params[3].get_str().c_str();
        if (passphrase.empty()) {
            // Empty string means unencrypted
            warnings.emplace_back(Untranslated("Empty string given as passphrase, wallet will not be encrypted."));
        }
    }

    if (!request.params[4].isNull() && request.params[4].get_bool()) {
        flags |= WALLET_FLAG_AVOID_REUSE;
    }
    if (!request.params[5].isNull() && request.params[5].get_bool()) {
#ifndef USE_SQLITE
        throw JSONRPCError(RPC_WALLET_ERROR, "Compiled without sqlite support (required for descriptor wallets)");
#endif
        flags |= WALLET_FLAG_DESCRIPTORS;
        warnings.emplace_back(Untranslated("Wallet is an experimental descriptor wallet"));
    }

    DatabaseOptions options;
    DatabaseStatus status;
    options.require_create = true;
    options.create_flags = flags;
    options.create_passphrase = passphrase;
    bilingual_str error;
    Optional<bool> load_on_start = request.params[6].isNull() ? nullopt : Optional<bool>(request.params[6].get_bool());
    std::shared_ptr<CWallet> wallet = CreateWallet(*context.chain, request.params[0].get_str(), load_on_start, options, status, error, warnings);
    if (!wallet) {
        RPCErrorCode code = status == DatabaseStatus::FAILED_ENCRYPT ? RPC_WALLET_ENCRYPTION_FAILED : RPC_WALLET_ERROR;
        throw JSONRPCError(code, error.original);
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("name", wallet->GetName());
    obj.pushKV("warning", Join(warnings, Untranslated("\n")).original);

    return obj;
},
    };
}

static RPCHelpMan unloadwallet()
{
    return RPCHelpMan{"unloadwallet",
                "Unloads the wallet referenced by the request endpoint otherwise unloads the wallet specified in the argument.\n"
                "Specifying the wallet name on a wallet endpoint is invalid.",
                {
                    {"wallet_name", RPCArg::Type::STR, /* default */ "the wallet name from the RPC endpoint", "The name of the wallet to unload. Must be provided in the RPC endpoint or this parameter (but not both)."},
                    {"load_on_startup", RPCArg::Type::BOOL, /* default */ "null", "Save wallet name to persistent settings and load on startup. True to add wallet to startup list, false to remove, null to leave unchanged."},
                },
                RPCResult{RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::STR, "warning", "Warning message if wallet was not unloaded cleanly."},
                }},
                RPCExamples{
                    HelpExampleCli("unloadwallet", "wallet_name")
            + HelpExampleRpc("unloadwallet", "wallet_name")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::string wallet_name;
    if (GetWalletNameFromJSONRPCRequest(request, wallet_name)) {
        if (!request.params[0].isNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Both the RPC endpoint wallet and wallet_name parameter were provided (only one allowed)");
        }
    } else {
        wallet_name = request.params[0].get_str();
    }

    std::shared_ptr<CWallet> wallet = GetWallet(wallet_name);
    if (!wallet) {
        throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Requested wallet does not exist or is not loaded");
    }

    // Release the "main" shared pointer and prevent further notifications.
    // Note that any attempt to load the same wallet would fail until the wallet
    // is destroyed (see CheckUniqueFileid).
    std::vector<bilingual_str> warnings;
    Optional<bool> load_on_start = request.params[1].isNull() ? nullopt : Optional<bool>(request.params[1].get_bool());
    if (!RemoveWallet(wallet, load_on_start, warnings)) {
        throw JSONRPCError(RPC_MISC_ERROR, "Requested wallet already unloaded");
    }

    UnloadWallet(std::move(wallet));

    UniValue result(UniValue::VOBJ);
    result.pushKV("warning", Join(warnings, Untranslated("\n")).original);
    return result;
},
    };
}

static RPCHelpMan listunspent()
{
    return RPCHelpMan{
                "listunspent",
                "\nReturns array of unspent transaction outputs\n"
                "with between minconf and maxconf (inclusive) confirmations.\n"
                "Optionally filter to only include txouts paid to specified addresses.\n",
                {
                    {"minconf", RPCArg::Type::NUM, /* default */ "1", "The minimum confirmations to filter"},
                    {"maxconf", RPCArg::Type::NUM, /* default */ "9999999", "The maximum confirmations to filter"},
                    {"addresses", RPCArg::Type::ARR, /* default */ "empty array", "The litecoin addresses to filter",
                        {
                            {"address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "litecoin address"},
                        },
                    },
                    {"include_unsafe", RPCArg::Type::BOOL, /* default */ "true", "Include outputs that are not safe to spend\n"
                              "See description of \"safe\" attribute below."},
                    {"query_options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED_NAMED_ARG, "JSON with query options",
                        {
                            {"minimumAmount", RPCArg::Type::AMOUNT, /* default */ "0", "Minimum value of each UTXO in " + CURRENCY_UNIT + ""},
                            {"maximumAmount", RPCArg::Type::AMOUNT, /* default */ "unlimited", "Maximum value of each UTXO in " + CURRENCY_UNIT + ""},
                            {"maximumCount", RPCArg::Type::NUM, /* default */ "unlimited", "Maximum number of UTXOs"},
                            {"minimumSumAmount", RPCArg::Type::AMOUNT, /* default */ "unlimited", "Minimum sum value of all UTXOs in " + CURRENCY_UNIT + ""},
                        },
                        "query_options"},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "txid", "the transaction id"},
                            {RPCResult::Type::NUM, "vout", "the vout value"},
                            {RPCResult::Type::STR, "address", "the litecoin address"},
                            {RPCResult::Type::STR, "label", "The associated label, or \"\" for the default label"},
                            {RPCResult::Type::STR, "scriptPubKey", "the script key"},
                            {RPCResult::Type::STR_AMOUNT, "amount", "the transaction output amount in " + CURRENCY_UNIT},
                            {RPCResult::Type::NUM, "confirmations", "The number of confirmations"},
                            {RPCResult::Type::STR_HEX, "redeemScript", "The redeemScript if scriptPubKey is P2SH"},
                            {RPCResult::Type::STR, "witnessScript", "witnessScript if the scriptPubKey is P2WSH or P2SH-P2WSH"},
                            {RPCResult::Type::BOOL, "spendable", "Whether we have the private keys to spend this output"},
                            {RPCResult::Type::BOOL, "solvable", "Whether we know how to spend this output, ignoring the lack of keys"},
                            {RPCResult::Type::BOOL, "reused", "(only present if avoid_reuse is set) Whether this output is reused/dirty (sent to an address that was previously spent from)"},
                            {RPCResult::Type::STR, "desc", "(only when solvable) A descriptor for spending this output"},
                            {RPCResult::Type::BOOL, "safe", "Whether this output is considered safe to spend. Unconfirmed transactions\n"
                                                            "from outside keys and unconfirmed replacement transactions are considered unsafe\n"
                                                            "and are not eligible for spending by fundrawtransaction and sendtoaddress."},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("listunspent", "")
            + HelpExampleCli("listunspent", "6 9999999 \"[\\\"" + EXAMPLE_ADDRESS[0] + "\\\",\\\"" + EXAMPLE_ADDRESS[1] + "\\\"]\"")
            + HelpExampleRpc("listunspent", "6, 9999999 \"[\\\"" + EXAMPLE_ADDRESS[0] + "\\\",\\\"" + EXAMPLE_ADDRESS[1] + "\\\"]\"")
            + HelpExampleCli("listunspent", "6 9999999 '[]' true '{ \"minimumAmount\": 0.005 }'")
            + HelpExampleRpc("listunspent", "6, 9999999, [] , true, { \"minimumAmount\": 0.005 } ")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    const CWallet* const pwallet = wallet.get();

    int nMinDepth = 1;
    if (!request.params[0].isNull()) {
        RPCTypeCheckArgument(request.params[0], UniValue::VNUM);
        nMinDepth = request.params[0].get_int();
    }

    int nMaxDepth = 9999999;
    if (!request.params[1].isNull()) {
        RPCTypeCheckArgument(request.params[1], UniValue::VNUM);
        nMaxDepth = request.params[1].get_int();
    }

    std::set<CTxDestination> destinations;
    if (!request.params[2].isNull()) {
        RPCTypeCheckArgument(request.params[2], UniValue::VARR);
        UniValue inputs = request.params[2].get_array();
        for (unsigned int idx = 0; idx < inputs.size(); idx++) {
            const UniValue& input = inputs[idx];
            CTxDestination dest = DecodeDestination(input.get_str());
            if (!IsValidDestination(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Litecoin address: ") + input.get_str());
            }
            if (!destinations.insert(dest).second) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameter, duplicated address: ") + input.get_str());
            }
        }
    }

    bool include_unsafe = true;
    if (!request.params[3].isNull()) {
        RPCTypeCheckArgument(request.params[3], UniValue::VBOOL);
        include_unsafe = request.params[3].get_bool();
    }

    CAmount nMinimumAmount = 0;
    CAmount nMaximumAmount = MAX_MONEY;
    CAmount nMinimumSumAmount = MAX_MONEY;
    uint64_t nMaximumCount = 0;

    if (!request.params[4].isNull()) {
        const UniValue& options = request.params[4].get_obj();

        RPCTypeCheckObj(options,
            {
                {"minimumAmount", UniValueType()},
                {"maximumAmount", UniValueType()},
                {"minimumSumAmount", UniValueType()},
                {"maximumCount", UniValueType(UniValue::VNUM)},
            },
            true, true);

        if (options.exists("minimumAmount"))
            nMinimumAmount = AmountFromValue(options["minimumAmount"]);

        if (options.exists("maximumAmount"))
            nMaximumAmount = AmountFromValue(options["maximumAmount"]);

        if (options.exists("minimumSumAmount"))
            nMinimumSumAmount = AmountFromValue(options["minimumSumAmount"]);

        if (options.exists("maximumCount"))
            nMaximumCount = options["maximumCount"].get_int64();
    }

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    UniValue results(UniValue::VARR);
    std::vector<COutputCoin> vecOutputs;
    {
        CCoinControl cctl;
        cctl.m_avoid_address_reuse = false;
        cctl.m_min_depth = nMinDepth;
        cctl.m_max_depth = nMaxDepth;
        LOCK(pwallet->cs_wallet);
        pwallet->AvailableCoins(vecOutputs, !include_unsafe, &cctl, nMinimumAmount, nMaximumAmount, nMinimumSumAmount, nMaximumCount);
    }

    LOCK(pwallet->cs_wallet);

    const bool avoid_reuse = pwallet->IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE);

    for (const COutputCoin& output_coin : vecOutputs) {
        CTxDestination address;
        bool fValidAddress = output_coin.GetDestination(address);

        if (destinations.size() && (!fValidAddress || !destinations.count(address)))
            continue;

        UniValue entry(UniValue::VOBJ);
        entry.pushKV("txid", output_coin.GetWalletTx()->GetHash().GetHex());
        entry.pushKV("amount", ValueFromAmount(output_coin.GetValue()));
        entry.pushKV("confirmations", output_coin.GetDepth());
        entry.pushKV("spendable", output_coin.IsSpendable());
        if (fValidAddress) {
            entry.pushKV("address", EncodeDestination(address));

            const auto* address_book_entry = pwallet->FindAddressBookEntry(address);
            if (address_book_entry) {
                entry.pushKV("label", address_book_entry->GetLabel());
            }
        }

        if (output_coin.IsMWEB()) {
            results.push_back(entry);
            continue;
        }

        const COutput& out = boost::get<COutput>(output_coin.m_output);
        const CScript& scriptPubKey = out.tx->tx->vout[out.i].scriptPubKey;

        entry.pushKV("vout", out.i);
        entry.pushKV("scriptPubKey", HexStr(scriptPubKey));
        entry.pushKV("solvable", out.fSolvable);
        if (out.fSolvable) {
            std::unique_ptr<SigningProvider> provider = pwallet->GetSolvingProvider(scriptPubKey);
            if (provider) {
                auto descriptor = InferDescriptor(scriptPubKey, *provider);
                entry.pushKV("desc", descriptor->ToString());
            }
        }

        if (avoid_reuse) entry.pushKV("reused", pwallet->IsSpentKey(out.tx->tx->GetOutput(output_coin.GetIndex())));
        entry.pushKV("safe", out.fSafe);
        if (fValidAddress) {
            std::unique_ptr<SigningProvider> provider = pwallet->GetSolvingProvider(scriptPubKey);
            if (provider) {
                if (scriptPubKey.IsPayToScriptHash()) {
                    const CScriptID& hash = CScriptID(boost::get<ScriptHash>(address));
                    CScript redeemScript;
                    if (provider->GetCScript(hash, redeemScript)) {
                        entry.pushKV("redeemScript", HexStr(redeemScript));
                        // Now check if the redeemScript is actually a P2WSH script
                        CTxDestination witness_destination;
                        if (redeemScript.IsPayToWitnessScriptHash()) {
                            bool extracted = ExtractDestination(redeemScript, witness_destination);
                            CHECK_NONFATAL(extracted);
                            // Also return the witness script
                            const WitnessV0ScriptHash& whash = boost::get<WitnessV0ScriptHash>(witness_destination);
                            CScriptID id;
                            CRIPEMD160().Write(whash.begin(), whash.size()).Finalize(id.begin());
                            CScript witnessScript;
                            if (provider->GetCScript(id, witnessScript)) {
                                entry.pushKV("witnessScript", HexStr(witnessScript));
                            }
                        }
                    }
                } else if (scriptPubKey.IsPayToWitnessScriptHash()) {
                    const WitnessV0ScriptHash& whash = boost::get<WitnessV0ScriptHash>(address);
                    CScriptID id;
                    CRIPEMD160().Write(whash.begin(), whash.size()).Finalize(id.begin());
                    CScript witnessScript;
                    if (provider->GetCScript(id, witnessScript)) {
                        entry.pushKV("witnessScript", HexStr(witnessScript));
                    }
                }
            }
        }

        results.push_back(entry);
    }

    return results;
},
    };
}

void FundTransaction(CWallet* const pwallet, CMutableTransaction& tx, CAmount& fee_out, int& change_position, const UniValue& options, CCoinControl& coinControl, bool override_min_fee)
{
    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    change_position = -1;
    bool lockUnspents = false;
    UniValue subtractFeeFromOutputs;
    std::set<int> setSubtractFeeFromOutputs;

    if (!options.isNull()) {
      if (options.type() == UniValue::VBOOL) {
        // backward compatibility bool only fallback
        coinControl.fAllowWatchOnly = options.get_bool();
      }
      else {
        RPCTypeCheckArgument(options, UniValue::VOBJ);
        RPCTypeCheckObj(options,
            {
                {"add_inputs", UniValueType(UniValue::VBOOL)},
                {"add_to_wallet", UniValueType(UniValue::VBOOL)},
                {"changeAddress", UniValueType(UniValue::VSTR)},
                {"change_address", UniValueType(UniValue::VSTR)},
                {"changePosition", UniValueType(UniValue::VNUM)},
                {"change_position", UniValueType(UniValue::VNUM)},
                {"change_type", UniValueType(UniValue::VSTR)},
                {"includeWatching", UniValueType(UniValue::VBOOL)},
                {"include_watching", UniValueType(UniValue::VBOOL)},
                {"inputs", UniValueType(UniValue::VARR)},
                {"lockUnspents", UniValueType(UniValue::VBOOL)},
                {"lock_unspents", UniValueType(UniValue::VBOOL)},
                {"locktime", UniValueType(UniValue::VNUM)},
                {"fee_rate", UniValueType()}, // will be checked by AmountFromValue() in SetFeeEstimateMode()
                {"feeRate", UniValueType()}, // will be checked by AmountFromValue() below
                {"psbt", UniValueType(UniValue::VBOOL)},
                {"subtractFeeFromOutputs", UniValueType(UniValue::VARR)},
                {"subtract_fee_from_outputs", UniValueType(UniValue::VARR)},
                {"replaceable", UniValueType(UniValue::VBOOL)},
                {"conf_target", UniValueType(UniValue::VNUM)},
                {"estimate_mode", UniValueType(UniValue::VSTR)},
            },
            true, true);

        if (options.exists("add_inputs") ) {
            coinControl.m_add_inputs = options["add_inputs"].get_bool();
        }

        if (options.exists("changeAddress") || options.exists("change_address")) {
            const std::string change_address_str = (options.exists("change_address") ? options["change_address"] : options["changeAddress"]).get_str();
            CTxDestination dest = DecodeDestination(change_address_str);

            if (!IsValidDestination(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Change address must be a valid litecoin address");
            }

            coinControl.destChange = dest;
        }

        if (options.exists("changePosition") || options.exists("change_position")) {
            change_position = (options.exists("change_position") ? options["change_position"] : options["changePosition"]).get_int();
        }

        if (options.exists("change_type")) {
            if (options.exists("changeAddress") || options.exists("change_address")) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot specify both change address and address type options");
            }
            OutputType out_type;
            if (!ParseOutputType(options["change_type"].get_str(), out_type)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Unknown change type '%s'", options["change_type"].get_str()));
            }
            coinControl.m_change_type.emplace(out_type);
        }

        const UniValue include_watching_option = options.exists("include_watching") ? options["include_watching"] : options["includeWatching"];
        coinControl.fAllowWatchOnly = ParseIncludeWatchonly(include_watching_option, *pwallet);

        if (options.exists("lockUnspents") || options.exists("lock_unspents")) {
            lockUnspents = (options.exists("lock_unspents") ? options["lock_unspents"] : options["lockUnspents"]).get_bool();
        }

        if (options.exists("feeRate")) {
            if (options.exists("fee_rate")) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot specify both fee_rate (" + CURRENCY_ATOM + "/vB) and feeRate (" + CURRENCY_UNIT + "/kvB)");
            }
            if (options.exists("conf_target")) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot specify both conf_target and feeRate. Please provide either a confirmation target in blocks for automatic fee estimation, or an explicit fee rate.");
            }
            if (options.exists("estimate_mode")) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot specify both estimate_mode and feeRate");
            }
            coinControl.m_feerate = CFeeRate(AmountFromValue(options["feeRate"]));
            coinControl.fOverrideFeeRate = true;
        }

        if (options.exists("subtractFeeFromOutputs") || options.exists("subtract_fee_from_outputs") )
            subtractFeeFromOutputs = (options.exists("subtract_fee_from_outputs") ? options["subtract_fee_from_outputs"] : options["subtractFeeFromOutputs"]).get_array();

        if (options.exists("replaceable")) {
            coinControl.m_signal_bip125_rbf = options["replaceable"].get_bool();
        }
        SetFeeEstimateMode(*pwallet, coinControl, options["conf_target"], options["estimate_mode"], options["fee_rate"], override_min_fee);
      }
    } else {
        // if options is null and not a bool
        coinControl.fAllowWatchOnly = ParseIncludeWatchonly(NullUniValue, *pwallet);
    }

    if (tx.vout.size() == 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "TX must have at least one output");

    if (change_position != -1 && (change_position < 0 || (unsigned int)change_position > tx.vout.size()))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "changePosition out of bounds");

    for (unsigned int idx = 0; idx < subtractFeeFromOutputs.size(); idx++) {
        int pos = subtractFeeFromOutputs[idx].get_int();
        if (setSubtractFeeFromOutputs.count(pos))
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid parameter, duplicated position: %d", pos));
        if (pos < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid parameter, negative position: %d", pos));
        if (pos >= int(tx.vout.size()))
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid parameter, position too large: %d", pos));
        setSubtractFeeFromOutputs.insert(pos);
    }

    bilingual_str error;

    if (!pwallet->FundTransaction(tx, fee_out, change_position, error, lockUnspents, setSubtractFeeFromOutputs, coinControl)) {
        throw JSONRPCError(RPC_WALLET_ERROR, error.original);
    }
}

static RPCHelpMan fundrawtransaction()
{
    return RPCHelpMan{"fundrawtransaction",
                "\nIf the transaction has no inputs, they will be automatically selected to meet its out value.\n"
                "It will add at most one change output to the outputs.\n"
                "No existing outputs will be modified unless \"subtractFeeFromOutputs\" is specified.\n"
                "Note that inputs which were signed may need to be resigned after completion since in/outputs have been added.\n"
                "The inputs added will not be signed, use signrawtransactionwithkey\n"
                " or signrawtransactionwithwallet for that.\n"
                "Note that all existing inputs must have their previous output transaction be in the wallet.\n"
                "Note that all inputs selected must be of standard form and P2SH scripts must be\n"
                "in the wallet using importaddress or addmultisigaddress (to calculate fees).\n"
                "You can see whether this is the case by checking the \"solvable\" field in the listunspent output.\n"
                "Only pay-to-pubkey, multisig, and P2SH versions thereof are currently supported for watch-only\n",
                {
                    {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hex string of the raw transaction"},
                    {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED_NAMED_ARG, "for backward compatibility: passing in a true instead of an object will result in {\"includeWatching\":true}",
                        {
                            {"add_inputs", RPCArg::Type::BOOL, /* default */ "true", "For a transaction with existing inputs, automatically include more if they are not enough."},
                            {"changeAddress", RPCArg::Type::STR, /* default */ "pool address", "The litecoin address to receive the change"},
                            {"changePosition", RPCArg::Type::NUM, /* default */ "random", "The index of the change output"},
                            {"change_type", RPCArg::Type::STR, /* default */ "set by -changetype", "The output type to use. Only valid if changeAddress is not specified. Options are \"legacy\", \"p2sh-segwit\", and \"bech32\"."},
                            {"includeWatching", RPCArg::Type::BOOL, /* default */ "true for watch-only wallets, otherwise false", "Also select inputs which are watch only.\n"
                                                          "Only solvable inputs can be used. Watch-only destinations are solvable if the public key and/or output script was imported,\n"
                                                          "e.g. with 'importpubkey' or 'importmulti' with the 'pubkeys' or 'desc' field."},
                            {"lockUnspents", RPCArg::Type::BOOL, /* default */ "false", "Lock selected unspent outputs"},
                            {"fee_rate", RPCArg::Type::AMOUNT, /* default */ "not set, fall back to wallet fee estimation", "Specify a fee rate in " + CURRENCY_ATOM + "/vB."},
                            {"feeRate", RPCArg::Type::AMOUNT, /* default */ "not set, fall back to wallet fee estimation", "Specify a fee rate in " + CURRENCY_UNIT + "/kvB."},
                            {"subtractFeeFromOutputs", RPCArg::Type::ARR, /* default */ "empty array", "The integers.\n"
                                                          "The fee will be equally deducted from the amount of each specified output.\n"
                                                          "Those recipients will receive less litecoins than you enter in their corresponding amount field.\n"
                                                          "If no outputs are specified here, the sender pays the fee.",
                                {
                                    {"vout_index", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "The zero-based output index, before a change output is added."},
                                },
                            },
                            {"replaceable", RPCArg::Type::BOOL, /* default */ "wallet default", "Marks this transaction as BIP125 replaceable.\n"
                                                          "Allows this transaction to be replaced by a transaction with higher fees"},
                            {"conf_target", RPCArg::Type::NUM, /* default */ "wallet -txconfirmtarget", "Confirmation target in blocks"},
                            {"estimate_mode", RPCArg::Type::STR, /* default */ "unset", std::string() + "The fee estimate mode, must be one of (case insensitive):\n"
                            "       \"" + FeeModes("\"\n\"") + "\""},
                        },
                        "options"},
                    {"iswitness", RPCArg::Type::BOOL, /* default */ "depends on heuristic tests", "Whether the transaction hex is a serialized witness transaction.\n"
                        "If iswitness is not present, heuristic tests will be used in decoding.\n"
                        "If true, only witness deserialization will be tried.\n"
                        "If false, only non-witness deserialization will be tried.\n"
                        "This boolean should reflect whether the transaction has inputs\n"
                        "(e.g. fully valid, or on-chain transactions), if known by the caller."
                    },
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "hex", "The resulting raw transaction (hex-encoded string)"},
                        {RPCResult::Type::STR_AMOUNT, "fee", "Fee in " + CURRENCY_UNIT + " the resulting transaction pays"},
                        {RPCResult::Type::NUM, "changepos", "The position of the added change output, or -1"},
                    }
                                },
                                RPCExamples{
                            "\nCreate a transaction with no inputs\n"
                            + HelpExampleCli("createrawtransaction", "\"[]\" \"{\\\"myaddress\\\":0.01}\"") +
                            "\nAdd sufficient unsigned inputs to meet the output value\n"
                            + HelpExampleCli("fundrawtransaction", "\"rawtransactionhex\"") +
                            "\nSign the transaction\n"
                            + HelpExampleCli("signrawtransactionwithwallet", "\"fundedtransactionhex\"") +
                            "\nSend the transaction\n"
                            + HelpExampleCli("sendrawtransaction", "\"signedtransactionhex\"")
                                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    RPCTypeCheck(request.params, {UniValue::VSTR, UniValueType(), UniValue::VBOOL});

    // parse hex string from parameter
    CMutableTransaction tx;
    bool try_witness = request.params[2].isNull() ? true : request.params[2].get_bool();
    bool try_no_witness = request.params[2].isNull() ? true : !request.params[2].get_bool();
    if (!DecodeHexTx(tx, request.params[0].get_str(), try_no_witness, try_witness)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    CAmount fee;
    int change_position;
    CCoinControl coin_control;
    // Automatically select (additional) coins. Can be overridden by options.add_inputs.
    coin_control.m_add_inputs = true;
    FundTransaction(pwallet, tx, fee, change_position, request.params[1], coin_control, /* override_min_fee */ true);

    UniValue result(UniValue::VOBJ);
    result.pushKV("hex", EncodeHexTx(CTransaction(tx)));
    result.pushKV("fee", ValueFromAmount(fee));
    result.pushKV("changepos", change_position);

    return result;
},
    };
}

RPCHelpMan signrawtransactionwithwallet()
{
    return RPCHelpMan{"signrawtransactionwithwallet",
                "\nSign inputs for raw transaction (serialized, hex-encoded).\n"
                "The second optional argument (may be null) is an array of previous transaction outputs that\n"
                "this transaction depends on but may not yet be in the block chain." +
        HELP_REQUIRING_PASSPHRASE,
                {
                    {"hexstring", RPCArg::Type::STR, RPCArg::Optional::NO, "The transaction hex string"},
                    {"prevtxs", RPCArg::Type::ARR, RPCArg::Optional::OMITTED_NAMED_ARG, "The previous dependent transaction outputs",
                        {
                            {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                                {
                                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                                    {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                                    {"scriptPubKey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "script key"},
                                    {"redeemScript", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "(required for P2SH) redeem script"},
                                    {"witnessScript", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "(required for P2WSH or P2SH-P2WSH) witness script"},
                                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "(required for Segwit inputs) the amount spent"},
                                },
                            },
                        },
                    },
                    {"sighashtype", RPCArg::Type::STR, /* default */ "ALL", "The signature hash type. Must be one of\n"
            "       \"ALL\"\n"
            "       \"NONE\"\n"
            "       \"SINGLE\"\n"
            "       \"ALL|ANYONECANPAY\"\n"
            "       \"NONE|ANYONECANPAY\"\n"
            "       \"SINGLE|ANYONECANPAY\""},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "hex", "The hex-encoded raw transaction with signature(s)"},
                        {RPCResult::Type::BOOL, "complete", "If the transaction has a complete set of signatures"},
                        {RPCResult::Type::ARR, "errors", /* optional */ true, "Script verification errors (if there are any)",
                        {
                            {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR_HEX, "txid", "The hash of the referenced, previous transaction"},
                                {RPCResult::Type::NUM, "vout", "The index of the output to spent and used as input"},
                                {RPCResult::Type::STR_HEX, "scriptSig", "The hex-encoded signature script"},
                                {RPCResult::Type::NUM, "sequence", "Script sequence number"},
                                {RPCResult::Type::STR, "error", "Verification or signing error related to the input"},
                            }},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("signrawtransactionwithwallet", "\"myhex\"")
            + HelpExampleRpc("signrawtransactionwithwallet", "\"myhex\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    const CWallet* const pwallet = wallet.get();

    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VARR, UniValue::VSTR}, true);

    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, request.params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed. Make sure the tx has at least one input.");
    }

    // Sign the transaction
    LOCK(pwallet->cs_wallet);
    EnsureWalletIsUnlocked(pwallet);

    // Fetch previous transactions (inputs):
    std::map<COutPoint, Coin> coins;
    for (const CTxIn& txin : mtx.vin) {
        coins[txin.prevout]; // Create empty map entry keyed by prevout.
    }
    pwallet->chain().findCoins(coins);

    // Parse the prevtxs array
    ParsePrevouts(request.params[1], nullptr, coins);

    int nHashType = ParseSighashString(request.params[2]);

    // Script verification errors
    std::map<int, std::string> input_errors;

    bool complete = pwallet->SignTransaction(mtx, coins, nHashType, input_errors);
    UniValue result(UniValue::VOBJ);
    SignTransactionResultToJSON(mtx, complete, coins, input_errors, result);
    return result;
},
    };
}

static RPCHelpMan bumpfee_helper(std::string method_name)
{
    bool want_psbt = method_name == "psbtbumpfee";
    const std::string incremental_fee{CFeeRate(DEFAULT_INCREMENTAL_RELAY_FEE).ToString(FeeEstimateMode::SAT_VB)};

    return RPCHelpMan{method_name,
        "\nBumps the fee of an opt-in-RBF transaction T, replacing it with a new transaction B.\n"
        + std::string(want_psbt ? "Returns a PSBT instead of creating and signing a new transaction.\n" : "") +
        "An opt-in RBF transaction with the given txid must be in the wallet.\n"
        "The command will pay the additional fee by reducing change outputs or adding inputs when necessary.\n"
        "It may add a new change output if one does not already exist.\n"
        "All inputs in the original transaction will be included in the replacement transaction.\n"
        "The command will fail if the wallet or mempool contains a transaction that spends one of T's outputs.\n"
        "By default, the new fee will be calculated automatically using the estimatesmartfee RPC.\n"
        "The user can specify a confirmation target for estimatesmartfee.\n"
        "Alternatively, the user can specify a fee rate in " + CURRENCY_ATOM + "/vB for the new transaction.\n"
        "At a minimum, the new fee rate must be high enough to pay an additional new relay fee (incrementalfee\n"
        "returned by getnetworkinfo) to enter the node's mempool.\n"
        "* WARNING: before version 0.21, fee_rate was in " + CURRENCY_UNIT + "/kvB. As of 0.21, fee_rate is in " + CURRENCY_ATOM + "/vB. *\n",
        {
            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The txid to be bumped"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED_NAMED_ARG, "",
                {
                    {"conf_target", RPCArg::Type::NUM, /* default */ "wallet -txconfirmtarget", "Confirmation target in blocks\n"},
                    {"fee_rate", RPCArg::Type::AMOUNT, /* default */ "not set, fall back to wallet fee estimation",
                             "\nSpecify a fee rate in " + CURRENCY_ATOM + "/vB instead of relying on the built-in fee estimator.\n"
                             "Must be at least " + incremental_fee + " higher than the current transaction fee rate.\n"
                             "WARNING: before version 0.21, fee_rate was in " + CURRENCY_UNIT + "/kvB. As of 0.21, fee_rate is in " + CURRENCY_ATOM + "/vB.\n"},
                    {"replaceable", RPCArg::Type::BOOL, /* default */ "true", "Whether the new transaction should still be\n"
                             "marked bip-125 replaceable. If true, the sequence numbers in the transaction will\n"
                             "be left unchanged from the original. If false, any input sequence numbers in the\n"
                             "original transaction that were less than 0xfffffffe will be increased to 0xfffffffe\n"
                             "so the new transaction will not be explicitly bip-125 replaceable (though it may\n"
                             "still be replaceable in practice, for example if it has unconfirmed ancestors which\n"
                             "are replaceable).\n"},
                    {"estimate_mode", RPCArg::Type::STR, /* default */ "unset", std::string() + "The fee estimate mode, must be one of (case insensitive):\n"
    "         \"" + FeeModes("\"\n\"") + "\""},
                },
                "options"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "", Cat(Cat<std::vector<RPCResult>>(
            {
                {RPCResult::Type::STR, "psbt", "The base64-encoded unsigned PSBT of the new transaction." + std::string(want_psbt ? "" : " Only returned when wallet private keys are disabled. (DEPRECATED)")},
            },
            want_psbt ? std::vector<RPCResult>{} : std::vector<RPCResult>{{RPCResult::Type::STR_HEX, "txid", "The id of the new transaction. Only returned when wallet private keys are enabled."}}
            ),
            {
                {RPCResult::Type::STR_AMOUNT, "origfee", "The fee of the replaced transaction."},
                {RPCResult::Type::STR_AMOUNT, "fee", "The fee of the new transaction."},
                {RPCResult::Type::ARR, "errors", "Errors encountered during processing (may be empty).",
                {
                    {RPCResult::Type::STR, "", ""},
                }},
            })
        },
        RPCExamples{
    "\nBump the fee, get the new transaction\'s" + std::string(want_psbt ? "psbt" : "txid") + "\n" +
            HelpExampleCli(method_name, "<txid>")
        },
        [want_psbt](const RPCHelpMan& self, const JSONRPCRequest& request) mutable -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    if (pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS) && !want_psbt) {
        if (!pwallet->chain().rpcEnableDeprecated("bumpfee")) {
            throw JSONRPCError(RPC_METHOD_DEPRECATED, "Using bumpfee with wallets that have private keys disabled is deprecated. Use psbtbumpfee instead or restart litecoind with -deprecatedrpc=bumpfee. This functionality will be removed in 0.22");
        }
        want_psbt = true;
    }

    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VOBJ});
    uint256 hash(ParseHashV(request.params[0], "txid"));

    CCoinControl coin_control;
    coin_control.fAllowWatchOnly = pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
    // optional parameters
    coin_control.m_signal_bip125_rbf = true;

    if (!request.params[1].isNull()) {
        UniValue options = request.params[1];
        RPCTypeCheckObj(options,
            {
                {"confTarget", UniValueType(UniValue::VNUM)},
                {"conf_target", UniValueType(UniValue::VNUM)},
                {"fee_rate", UniValueType()}, // will be checked by AmountFromValue() in SetFeeEstimateMode()
                {"replaceable", UniValueType(UniValue::VBOOL)},
                {"estimate_mode", UniValueType(UniValue::VSTR)},
            },
            true, true);

        if (options.exists("confTarget") && options.exists("conf_target")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "confTarget and conf_target options should not both be set. Use conf_target (confTarget is deprecated).");
        }

        auto conf_target = options.exists("confTarget") ? options["confTarget"] : options["conf_target"];

        if (options.exists("replaceable")) {
            coin_control.m_signal_bip125_rbf = options["replaceable"].get_bool();
        }
        SetFeeEstimateMode(*pwallet, coin_control, conf_target, options["estimate_mode"], options["fee_rate"], /* override_min_fee */ false);
    }

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);
    EnsureWalletIsUnlocked(pwallet);


    std::vector<bilingual_str> errors;
    CAmount old_fee;
    CAmount new_fee;
    CMutableTransaction mtx;
    feebumper::Result res;
    // Targeting feerate bump.
    res = feebumper::CreateRateBumpTransaction(*pwallet, hash, coin_control, errors, old_fee, new_fee, mtx);
    if (res != feebumper::Result::OK) {
        switch(res) {
            case feebumper::Result::INVALID_ADDRESS_OR_KEY:
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, errors[0].original);
                break;
            case feebumper::Result::INVALID_REQUEST:
                throw JSONRPCError(RPC_INVALID_REQUEST, errors[0].original);
                break;
            case feebumper::Result::INVALID_PARAMETER:
                throw JSONRPCError(RPC_INVALID_PARAMETER, errors[0].original);
                break;
            case feebumper::Result::WALLET_ERROR:
                throw JSONRPCError(RPC_WALLET_ERROR, errors[0].original);
                break;
            default:
                throw JSONRPCError(RPC_MISC_ERROR, errors[0].original);
                break;
        }
    }

    UniValue result(UniValue::VOBJ);

    // If wallet private keys are enabled, return the new transaction id,
    // otherwise return the base64-encoded unsigned PSBT of the new transaction.
    if (!want_psbt) {
        if (!feebumper::SignTransaction(*pwallet, mtx)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Can't sign transaction.");
        }

        uint256 txid;
        if (feebumper::CommitTransaction(*pwallet, hash, std::move(mtx), errors, txid) != feebumper::Result::OK) {
            throw JSONRPCError(RPC_WALLET_ERROR, errors[0].original);
        }

        result.pushKV("txid", txid.GetHex());
    } else {
        PartiallySignedTransaction psbtx(mtx);
        bool complete = false;
        const TransactionError err = pwallet->FillPSBT(psbtx, complete, SIGHASH_ALL, false /* sign */, true /* bip32derivs */);
        CHECK_NONFATAL(err == TransactionError::OK);
        CHECK_NONFATAL(!complete);
        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << psbtx;
        result.pushKV("psbt", EncodeBase64(ssTx.str()));
    }

    result.pushKV("origfee", ValueFromAmount(old_fee));
    result.pushKV("fee", ValueFromAmount(new_fee));
    UniValue result_errors(UniValue::VARR);
    for (const bilingual_str& error : errors) {
        result_errors.push_back(error.original);
    }
    result.pushKV("errors", result_errors);

    return result;
},
    };
}

static RPCHelpMan bumpfee() { return bumpfee_helper("bumpfee"); }
static RPCHelpMan psbtbumpfee() { return bumpfee_helper("psbtbumpfee"); }

static RPCHelpMan rescanblockchain()
{
    return RPCHelpMan{"rescanblockchain",
                "\nRescan the local blockchain for wallet related transactions.\n"
                "Note: Use \"getwalletinfo\" to query the scanning progress.\n",
                {
                    {"start_height", RPCArg::Type::NUM, /* default */ "0", "block height where the rescan should start"},
                    {"stop_height", RPCArg::Type::NUM, RPCArg::Optional::OMITTED_NAMED_ARG, "the last block height that should be scanned. If none is provided it will rescan up to the tip at return time of this call."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM, "start_height", "The block height where the rescan started (the requested height or 0)"},
                        {RPCResult::Type::NUM, "stop_height", "The height of the last rescanned block. May be null in rare cases if there was a reorg and the call didn't scan any blocks because they were already scanned in the background."},
                    }
                },
                RPCExamples{
                    HelpExampleCli("rescanblockchain", "100000 120000")
            + HelpExampleRpc("rescanblockchain", "100000, 120000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    WalletRescanReserver reserver(*pwallet);
    if (!reserver.reserve()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is currently rescanning. Abort existing rescan or wait.");
    }

    int start_height = 0;
    Optional<int> stop_height = MakeOptional(false, int());
    uint256 start_block;
    {
        LOCK(pwallet->cs_wallet);
        int tip_height = pwallet->GetLastBlockHeight();

        if (!request.params[0].isNull()) {
            start_height = request.params[0].get_int();
            if (start_height < 0 || start_height > tip_height) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid start_height");
            }
        }

        if (!request.params[1].isNull()) {
            stop_height = request.params[1].get_int();
            if (*stop_height < 0 || *stop_height > tip_height) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid stop_height");
            } else if (*stop_height < start_height) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "stop_height must be greater than start_height");
            }
        }

        // We can't rescan beyond non-pruned blocks, stop and throw an error
        if (!pwallet->chain().hasBlocks(pwallet->GetLastBlockHash(), start_height, stop_height)) {
            throw JSONRPCError(RPC_MISC_ERROR, "Can't rescan beyond pruned data. Use RPC call getblockchaininfo to determine your pruned height.");
        }

        CHECK_NONFATAL(pwallet->chain().findAncestorByHeight(pwallet->GetLastBlockHash(), start_height, FoundBlock().hash(start_block)));
    }

    CWallet::ScanResult result =
        pwallet->ScanForWalletTransactions(start_block, start_height, stop_height, reserver, true /* fUpdate */);
    switch (result.status) {
    case CWallet::ScanResult::SUCCESS:
        break;
    case CWallet::ScanResult::FAILURE:
        throw JSONRPCError(RPC_MISC_ERROR, "Rescan failed. Potentially corrupted data files.");
    case CWallet::ScanResult::USER_ABORT:
        throw JSONRPCError(RPC_MISC_ERROR, "Rescan aborted.");
        // no default case, so the compiler can warn about missing cases
    }
    UniValue response(UniValue::VOBJ);
    response.pushKV("start_height", start_height);
    response.pushKV("stop_height", result.last_scanned_height ? *result.last_scanned_height : UniValue());
    return response;
},
    };
}

class DescribeWalletAddressVisitor : public boost::static_visitor<UniValue>
{
public:
    const SigningProvider * const provider;

    void ProcessSubScript(const CScript& subscript, UniValue& obj) const
    {
        // Always present: script type and redeemscript
        std::vector<std::vector<unsigned char>> solutions_data;
        TxoutType which_type = Solver(subscript, solutions_data);
        obj.pushKV("script", GetTxnOutputType(which_type));
        obj.pushKV("hex", HexStr(subscript));

        CTxDestination embedded;
        if (ExtractDestination(subscript, embedded)) {
            // Only when the script corresponds to an address.
            UniValue subobj(UniValue::VOBJ);
            UniValue detail = DescribeAddress(embedded);
            subobj.pushKVs(detail);
            UniValue wallet_detail = boost::apply_visitor(*this, embedded);
            subobj.pushKVs(wallet_detail);
            subobj.pushKV("address", EncodeDestination(embedded));
            subobj.pushKV("scriptPubKey", HexStr(subscript));
            // Always report the pubkey at the top level, so that `getnewaddress()['pubkey']` always works.
            if (subobj.exists("pubkey")) obj.pushKV("pubkey", subobj["pubkey"]);
            obj.pushKV("embedded", std::move(subobj));
        } else if (which_type == TxoutType::MULTISIG) {
            // Also report some information on multisig scripts (which do not have a corresponding address).
            // TODO: abstract out the common functionality between this logic and ExtractDestinations.
            obj.pushKV("sigsrequired", solutions_data[0][0]);
            UniValue pubkeys(UniValue::VARR);
            for (size_t i = 1; i < solutions_data.size() - 1; ++i) {
                CPubKey key(solutions_data[i].begin(), solutions_data[i].end());
                pubkeys.push_back(HexStr(key));
            }
            obj.pushKV("pubkeys", std::move(pubkeys));
        }
    }

    explicit DescribeWalletAddressVisitor(const SigningProvider* _provider) : provider(_provider) {}

    UniValue operator()(const CNoDestination& dest) const { return UniValue(UniValue::VOBJ); }

    UniValue operator()(const PKHash& pkhash) const
    {
        CKeyID keyID{ToKeyID(pkhash)};
        UniValue obj(UniValue::VOBJ);
        CPubKey vchPubKey;
        if (provider && provider->GetPubKey(keyID, vchPubKey)) {
            obj.pushKV("pubkey", HexStr(vchPubKey));
            obj.pushKV("iscompressed", vchPubKey.IsCompressed());
        }
        return obj;
    }

    UniValue operator()(const ScriptHash& scripthash) const
    {
        CScriptID scriptID(scripthash);
        UniValue obj(UniValue::VOBJ);
        CScript subscript;
        if (provider && provider->GetCScript(scriptID, subscript)) {
            ProcessSubScript(subscript, obj);
        }
        return obj;
    }

    UniValue operator()(const WitnessV0KeyHash& id) const
    {
        UniValue obj(UniValue::VOBJ);
        CPubKey pubkey;
        if (provider && provider->GetPubKey(ToKeyID(id), pubkey)) {
            obj.pushKV("pubkey", HexStr(pubkey));
        }
        return obj;
    }

    UniValue operator()(const WitnessV0ScriptHash& id) const
    {
        UniValue obj(UniValue::VOBJ);
        CScript subscript;
        CRIPEMD160 hasher;
        uint160 hash;
        hasher.Write(id.begin(), 32).Finalize(hash.begin());
        if (provider && provider->GetCScript(CScriptID(hash), subscript)) {
            ProcessSubScript(subscript, obj);
        }
        return obj;
    }

    UniValue operator()(const StealthAddress& id) const
    {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("scan_pubkey", id.GetScanPubKey().ToHex());
        obj.pushKV("spend_pubkey", id.GetSpendPubKey().ToHex());
        return obj;
    }

    UniValue operator()(const WitnessUnknown& id) const { return UniValue(UniValue::VOBJ); }
};

static UniValue DescribeWalletAddress(const CWallet* const pwallet, const CTxDestination& dest)
{
    UniValue ret(UniValue::VOBJ);
    UniValue detail = DescribeAddress(dest);
    CScript script = GetScriptForDestination(dest);
    std::unique_ptr<SigningProvider> provider = nullptr;
    if (pwallet) {
        provider = pwallet->GetSolvingProvider(script);
    }
    ret.pushKVs(detail);
    ret.pushKVs(boost::apply_visitor(DescribeWalletAddressVisitor(provider.get()), dest));
    return ret;
}

/** Convert CAddressBookData to JSON record.  */
static UniValue AddressBookDataToJSON(const CAddressBookData& data, const bool verbose)
{
    UniValue ret(UniValue::VOBJ);
    if (verbose) {
        ret.pushKV("name", data.GetLabel());
    }
    ret.pushKV("purpose", data.purpose);
    return ret;
}

RPCHelpMan getaddressinfo()
{
    return RPCHelpMan{"getaddressinfo",
                "\nReturn information about the given litecoin address.\n"
                "Some of the information will only be present if the address is in the active wallet.\n",
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The litecoin address for which to get information."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "address", "The litecoin address validated."},
                        {RPCResult::Type::STR_HEX, "scriptPubKey", "The hex-encoded scriptPubKey generated by the address."},
                        {RPCResult::Type::BOOL, "ismine", "If the address is yours."},
                        {RPCResult::Type::BOOL, "iswatchonly", "If the address is watchonly."},
                        {RPCResult::Type::BOOL, "solvable", "If we know how to spend coins sent to this address, ignoring the possible lack of private keys."},
                        {RPCResult::Type::STR, "desc", /* optional */ true, "A descriptor for spending coins sent to this address (only when solvable)."},
                        {RPCResult::Type::BOOL, "isscript", "If the key is a script."},
                        {RPCResult::Type::BOOL, "ischange", "If the address was used for change output."},
                        {RPCResult::Type::BOOL, "iswitness", "If the address is a witness address."},
                        {RPCResult::Type::NUM, "witness_version", /* optional */ true, "The version number of the witness program."},
                        {RPCResult::Type::STR_HEX, "witness_program", /* optional */ true, "The hex value of the witness program."},
                        {RPCResult::Type::STR, "script", /* optional */ true, "The output script type. Only if isscript is true and the redeemscript is known. Possible\n"
                                                                     "types: nonstandard, pubkey, pubkeyhash, scripthash, multisig, nulldata, witness_v0_keyhash,\n"
                            "witness_v0_scripthash, witness_unknown."},
                        {RPCResult::Type::STR_HEX, "hex", /* optional */ true, "The redeemscript for the p2sh address."},
                        {RPCResult::Type::ARR, "pubkeys", /* optional */ true, "Array of pubkeys associated with the known redeemscript (only if script is multisig).",
                        {
                            {RPCResult::Type::STR, "pubkey", ""},
                        }},
                        {RPCResult::Type::NUM, "sigsrequired", /* optional */ true, "The number of signatures required to spend multisig output (only if script is multisig)."},
                        {RPCResult::Type::STR_HEX, "pubkey", /* optional */ true, "The hex value of the raw public key for single-key addresses (possibly embedded in P2SH or P2WSH)."},
                        {RPCResult::Type::OBJ, "embedded", /* optional */ true, "Information about the address embedded in P2SH or P2WSH, if relevant and known.",
                        {
                            {RPCResult::Type::ELISION, "", "Includes all getaddressinfo output fields for the embedded address, excluding metadata (timestamp, hdkeypath, hdseedid)\n"
                            "and relation to the wallet (ismine, iswatchonly)."},
                        }},
                        {RPCResult::Type::BOOL, "iscompressed", /* optional */ true, "If the pubkey is compressed."},
                        {RPCResult::Type::NUM_TIME, "timestamp", /* optional */ true, "The creation time of the key, if available, expressed in " + UNIX_EPOCH_TIME + "."},
                        {RPCResult::Type::STR, "hdkeypath", /* optional */ true, "The HD keypath, if the key is HD and available."},
                        {RPCResult::Type::STR_HEX, "hdseedid", /* optional */ true, "The Hash160 of the HD seed."},
                        {RPCResult::Type::STR_HEX, "hdmasterfingerprint", /* optional */ true, "The fingerprint of the master key."},
                        {RPCResult::Type::ARR, "labels", "Array of labels associated with the address. Currently limited to one label but returned\n"
                            "as an array to keep the API stable if multiple labels are enabled in the future.",
                        {
                            {RPCResult::Type::STR, "label name", "Label name (defaults to \"\")."},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("getaddressinfo", "\"" + EXAMPLE_ADDRESS[0] + "\"") +
                    HelpExampleRpc("getaddressinfo", "\"" + EXAMPLE_ADDRESS[0] + "\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    const CWallet* const pwallet = wallet.get();

    LOCK(pwallet->cs_wallet);

    UniValue ret(UniValue::VOBJ);
    CTxDestination dest = DecodeDestination(request.params[0].get_str());
    // Make sure the destination is valid
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    std::string currentAddress = EncodeDestination(dest);
    ret.pushKV("address", currentAddress);

    DestinationAddr dest_addr(dest);

    if (!dest_addr.IsMWEB()) {
        ret.pushKV("scriptPubKey", HexStr(dest_addr.GetScript()));
    }

    std::unique_ptr<SigningProvider> provider = pwallet->GetSolvingProvider(dest_addr);

    isminetype mine = pwallet->IsMine(dest);
    ret.pushKV("ismine", bool(mine & ISMINE_SPENDABLE));

    bool solvable = provider && IsSolvable(*provider, dest_addr);
    ret.pushKV("solvable", solvable);

    if (solvable) {
       ret.pushKV("desc", InferDescriptor(dest_addr, *provider)->ToString());
    }

    ret.pushKV("iswatchonly", bool(mine & ISMINE_WATCH_ONLY));

    UniValue detail = DescribeWalletAddress(pwallet, dest);
    ret.pushKVs(detail);

    ret.pushKV("ischange", pwallet->IsChange(dest_addr));

    ScriptPubKeyMan* spk_man = pwallet->GetScriptPubKeyMan(dest_addr);
    if (spk_man) {
        if (const std::unique_ptr<CKeyMetadata> meta = spk_man->GetMetadata(dest)) {
            ret.pushKV("timestamp", meta->nCreateTime);
            if (meta->has_key_origin) {
                if (!!meta->mweb_index) {
                    ret.pushKV("hdkeypath", meta->hdKeypath);
                } else {
                    ret.pushKV("hdkeypath", WriteHDKeypath(meta->key_origin.path));
                }

                ret.pushKV("hdseedid", meta->hd_seed_id.GetHex());
                ret.pushKV("hdmasterfingerprint", HexStr(meta->key_origin.fingerprint));
            }
        }
    }

    // Return a `labels` array containing the label associated with the address,
    // equivalent to the `label` field above. Currently only one label can be
    // associated with an address, but we return an array so the API remains
    // stable if we allow multiple labels to be associated with an address in
    // the future.
    UniValue labels(UniValue::VARR);
    const auto* address_book_entry = pwallet->FindAddressBookEntry(dest);
    if (address_book_entry) {
        labels.push_back(address_book_entry->GetLabel());
    }
    ret.pushKV("labels", std::move(labels));

    return ret;
},
    };
}

static RPCHelpMan getaddressesbylabel()
{
    return RPCHelpMan{"getaddressesbylabel",
                "\nReturns the list of addresses assigned the specified label.\n",
                {
                    {"label", RPCArg::Type::STR, RPCArg::Optional::NO, "The label."},
                },
                RPCResult{
                    RPCResult::Type::OBJ_DYN, "", "json object with addresses as keys",
                    {
                        {RPCResult::Type::OBJ, "address", "json object with information about address",
                        {
                            {RPCResult::Type::STR, "purpose", "Purpose of address (\"send\" for sending address, \"receive\" for receiving address)"},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("getaddressesbylabel", "\"tabby\"")
            + HelpExampleRpc("getaddressesbylabel", "\"tabby\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    const CWallet* const pwallet = wallet.get();

    LOCK(pwallet->cs_wallet);

    std::string label = LabelFromValue(request.params[0]);

    // Find all addresses that have the given label
    UniValue ret(UniValue::VOBJ);
    std::set<std::string> addresses;
    for (const std::pair<const CTxDestination, CAddressBookData>& item : pwallet->m_address_book) {
        if (item.second.IsChange()) continue;
        if (item.second.GetLabel() == label) {
            std::string address = EncodeDestination(item.first);
            // CWallet::m_address_book is not expected to contain duplicate
            // address strings, but build a separate set as a precaution just in
            // case it does.
            bool unique = addresses.emplace(address).second;
            CHECK_NONFATAL(unique);
            // UniValue::pushKV checks if the key exists in O(N)
            // and since duplicate addresses are unexpected (checked with
            // std::set in O(log(N))), UniValue::__pushKV is used instead,
            // which currently is O(1).
            ret.__pushKV(address, AddressBookDataToJSON(item.second, false));
        }
    }

    if (ret.empty()) {
        throw JSONRPCError(RPC_WALLET_INVALID_LABEL_NAME, std::string("No addresses with label " + label));
    }

    return ret;
},
    };
}

static RPCHelpMan listlabels()
{
    return RPCHelpMan{"listlabels",
                "\nReturns the list of all labels, or labels that are assigned to addresses with a specific purpose.\n",
                {
                    {"purpose", RPCArg::Type::STR, RPCArg::Optional::OMITTED_NAMED_ARG, "Address purpose to list labels for ('send','receive'). An empty string is the same as not providing this argument."},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::STR, "label", "Label name"},
                    }
                },
                RPCExamples{
            "\nList all labels\n"
            + HelpExampleCli("listlabels", "") +
            "\nList labels that have receiving addresses\n"
            + HelpExampleCli("listlabels", "receive") +
            "\nList labels that have sending addresses\n"
            + HelpExampleCli("listlabels", "send") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("listlabels", "receive")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    const CWallet* const pwallet = wallet.get();

    LOCK(pwallet->cs_wallet);

    std::string purpose;
    if (!request.params[0].isNull()) {
        purpose = request.params[0].get_str();
    }

    // Add to a set to sort by label name, then insert into Univalue array
    std::set<std::string> label_set;
    for (const std::pair<const CTxDestination, CAddressBookData>& entry : pwallet->m_address_book) {
        if (entry.second.IsChange()) continue;
        if (purpose.empty() || entry.second.purpose == purpose) {
            label_set.insert(entry.second.GetLabel());
        }
    }

    UniValue ret(UniValue::VARR);
    for (const std::string& name : label_set) {
        ret.push_back(name);
    }

    return ret;
},
    };
}

static RPCHelpMan send()
{
    return RPCHelpMan{"send",
        "\nEXPERIMENTAL warning: this call may be changed in future releases.\n"
        "\nSend a transaction.\n",
        {
            {"outputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The outputs (key-value pairs), where none of the keys are duplicated.\n"
                    "That is, each address can only appear once and there can only be one 'data' object.\n"
                    "For convenience, a dictionary, which holds the key-value pairs directly, is also accepted.",
                {
                    {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                        {
                            {"address", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "A key-value pair. The key (string) is the litecoin address, the value (float or string) is the amount in " + CURRENCY_UNIT + ""},
                        },
                        },
                    {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                        {
                            {"data", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "A key-value pair. The key must be \"data\", the value is hex-encoded data"},
                        },
                    },
                },
            },
            {"conf_target", RPCArg::Type::NUM, /* default */ "wallet -txconfirmtarget", "Confirmation target in blocks"},
            {"estimate_mode", RPCArg::Type::STR, /* default */ "unset", std::string() + "The fee estimate mode, must be one of (case insensitive):\n"
                        "       \"" + FeeModes("\"\n\"") + "\""},
            {"fee_rate", RPCArg::Type::AMOUNT, /* default */ "not set, fall back to wallet fee estimation", "Specify a fee rate in " + CURRENCY_ATOM + "/vB."},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED_NAMED_ARG, "",
                {
                    {"add_inputs", RPCArg::Type::BOOL, /* default */ "false", "If inputs are specified, automatically include more if they are not enough."},
                    {"add_to_wallet", RPCArg::Type::BOOL, /* default */ "true", "When false, returns a serialized transaction which will not be added to the wallet or broadcast"},
                    {"change_address", RPCArg::Type::STR_HEX, /* default */ "pool address", "The litecoin address to receive the change"},
                    {"change_position", RPCArg::Type::NUM, /* default */ "random", "The index of the change output"},
                    {"change_type", RPCArg::Type::STR, /* default */ "set by -changetype", "The output type to use. Only valid if change_address is not specified. Options are \"legacy\", \"p2sh-segwit\", and \"bech32\"."},
                    {"conf_target", RPCArg::Type::NUM, /* default */ "wallet -txconfirmtarget", "Confirmation target in blocks"},
                    {"estimate_mode", RPCArg::Type::STR, /* default */ "unset", std::string() + "The fee estimate mode, must be one of (case insensitive):\n"
            "       \"" + FeeModes("\"\n\"") + "\""},
                    {"fee_rate", RPCArg::Type::AMOUNT, /* default */ "not set, fall back to wallet fee estimation", "Specify a fee rate in " + CURRENCY_ATOM + "/vB."},
                    {"include_watching", RPCArg::Type::BOOL, /* default */ "true for watch-only wallets, otherwise false", "Also select inputs which are watch only.\n"
                                          "Only solvable inputs can be used. Watch-only destinations are solvable if the public key and/or output script was imported,\n"
                                          "e.g. with 'importpubkey' or 'importmulti' with the 'pubkeys' or 'desc' field."},
                    {"inputs", RPCArg::Type::ARR, /* default */ "empty array", "Specify inputs instead of adding them automatically. A JSON array of JSON objects",
                        {
                            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                            {"sequence", RPCArg::Type::NUM, RPCArg::Optional::NO, "The sequence number"},
                        },
                    },
                    {"locktime", RPCArg::Type::NUM, /* default */ "0", "Raw locktime. Non-0 value also locktime-activates inputs"},
                    {"lock_unspents", RPCArg::Type::BOOL, /* default */ "false", "Lock selected unspent outputs"},
                    {"psbt", RPCArg::Type::BOOL,  /* default */ "automatic", "Always return a PSBT, implies add_to_wallet=false."},
                    {"subtract_fee_from_outputs", RPCArg::Type::ARR, /* default */ "empty array", "Outputs to subtract the fee from, specified as integer indices.\n"
                    "The fee will be equally deducted from the amount of each specified output.\n"
                    "Those recipients will receive less litecoins than you enter in their corresponding amount field.\n"
                    "If no outputs are specified here, the sender pays the fee.",
                        {
                            {"vout_index", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "The zero-based output index, before a change output is added."},
                        },
                    },
                    {"replaceable", RPCArg::Type::BOOL, /* default */ "wallet default", "Marks this transaction as BIP125 replaceable.\n"
                                                  "Allows this transaction to be replaced by a transaction with higher fees"},
                },
                "options"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::BOOL, "complete", "If the transaction has a complete set of signatures"},
                    {RPCResult::Type::STR_HEX, "txid", "The transaction id for the send. Only 1 transaction is created regardless of the number of addresses."},
                    {RPCResult::Type::STR_HEX, "hex", "If add_to_wallet is false, the hex-encoded raw transaction with signature(s)"},
                    {RPCResult::Type::STR, "psbt", "If more signatures are needed, or if add_to_wallet is false, the base64-encoded (partially) signed transaction"}
                }
        },
        RPCExamples{""
        "\nSend 0.1 BTC with a confirmation target of 6 blocks in economical fee estimate mode\n"
        + HelpExampleCli("send", "'{\"" + EXAMPLE_ADDRESS[0] + "\": 0.1}' 6 economical\n") +
        "Send 0.2 BTC with a fee rate of 1.1 " + CURRENCY_ATOM + "/vB using positional arguments\n"
        + HelpExampleCli("send", "'{\"" + EXAMPLE_ADDRESS[0] + "\": 0.2}' null \"unset\" 1.1\n") +
        "Send 0.2 BTC with a fee rate of 1 " + CURRENCY_ATOM + "/vB using the options argument\n"
        + HelpExampleCli("send", "'{\"" + EXAMPLE_ADDRESS[0] + "\": 0.2}' null \"unset\" null '{\"fee_rate\": 1}'\n") +
        "Send 0.3 BTC with a fee rate of 25 " + CURRENCY_ATOM + "/vB using named arguments\n"
        + HelpExampleCli("-named send", "outputs='{\"" + EXAMPLE_ADDRESS[0] + "\": 0.3}' fee_rate=25\n") +
        "Create a transaction that should confirm the next block, with a specific input, and return result without adding to wallet or broadcasting to the network\n"
        + HelpExampleCli("send", "'{\"" + EXAMPLE_ADDRESS[0] + "\": 0.1}' 1 economical '{\"add_to_wallet\": false, \"inputs\": [{\"txid\":\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\", \"vout\":1}]}'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            RPCTypeCheck(request.params, {
                UniValueType(), // outputs (ARR or OBJ, checked later)
                UniValue::VNUM, // conf_target
                UniValue::VSTR, // estimate_mode
                UniValueType(), // fee_rate, will be checked by AmountFromValue() in SetFeeEstimateMode()
                UniValue::VOBJ, // options
                }, true
            );

            std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) return NullUniValue;
            CWallet* const pwallet = wallet.get();

            UniValue options{request.params[4].isNull() ? UniValue::VOBJ : request.params[4]};
            if (options.exists("conf_target") || options.exists("estimate_mode")) {
                if (!request.params[1].isNull() || !request.params[2].isNull()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Pass conf_target and estimate_mode either as arguments or in the options object, but not both");
                }
            } else {
                options.pushKV("conf_target", request.params[1]);
                options.pushKV("estimate_mode", request.params[2]);
            }
            if (options.exists("fee_rate")) {
                if (!request.params[3].isNull()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Pass the fee_rate either as an argument, or in the options object, but not both");
                }
            } else {
                options.pushKV("fee_rate", request.params[3]);
            }
            if (!options["conf_target"].isNull() && (options["estimate_mode"].isNull() || (options["estimate_mode"].get_str() == "unset"))) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Specify estimate_mode");
            }
            if (options.exists("feeRate")) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Use fee_rate (" + CURRENCY_ATOM + "/vB) instead of feeRate");
            }
            if (options.exists("changeAddress")) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Use change_address");
            }
            if (options.exists("changePosition")) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Use change_position");
            }
            if (options.exists("includeWatching")) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Use include_watching");
            }
            if (options.exists("lockUnspents")) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Use lock_unspents");
            }
            if (options.exists("subtractFeeFromOutputs")) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Use subtract_fee_from_outputs");
            }

            const bool psbt_opt_in = options.exists("psbt") && options["psbt"].get_bool();

            CAmount fee;
            int change_position;
            bool rbf = pwallet->m_signal_rbf;
            if (options.exists("replaceable")) {
                rbf = options["replaceable"].get_bool();
            }
            CMutableTransaction rawTx = ConstructTransaction(options["inputs"], request.params[0], options["locktime"], rbf);
            CCoinControl coin_control;
            // Automatically select coins, unless at least one is manually selected. Can
            // be overridden by options.add_inputs.
            coin_control.m_add_inputs = rawTx.vin.size() == 0;
            FundTransaction(pwallet, rawTx, fee, change_position, options, coin_control, /* override_min_fee */ false);

            bool add_to_wallet = true;
            if (options.exists("add_to_wallet")) {
                add_to_wallet = options["add_to_wallet"].get_bool();
            }

            // Make a blank psbt
            PartiallySignedTransaction psbtx(rawTx);

            // Fill transaction with our data and sign
            bool complete = true;
            const TransactionError err = pwallet->FillPSBT(psbtx, complete, SIGHASH_ALL, true, false);
            if (err != TransactionError::OK) {
                throw JSONRPCTransactionError(err);
            }

            CMutableTransaction mtx;
            complete = FinalizeAndExtractPSBT(psbtx, mtx);

            UniValue result(UniValue::VOBJ);

            if (psbt_opt_in || !complete || !add_to_wallet) {
                // Serialize the PSBT
                CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
                ssTx << psbtx;
                result.pushKV("psbt", EncodeBase64(ssTx.str()));
            }

            if (complete) {
                std::string err_string;
                std::string hex = EncodeHexTx(CTransaction(mtx));
                CTransactionRef tx(MakeTransactionRef(std::move(mtx)));
                result.pushKV("txid", tx->GetHash().GetHex());
                if (add_to_wallet && !psbt_opt_in) {
                    pwallet->CommitTransaction(tx, {}, {} /* orderForm */);
                } else {
                    result.pushKV("hex", hex);
                }
            }
            result.pushKV("complete", complete);

            return result;
        }
    };
}

static RPCHelpMan sethdseed()
{
    return RPCHelpMan{"sethdseed",
                "\nSet or generate a new HD wallet seed. Non-HD wallets will not be upgraded to being a HD wallet. Wallets that are already\n"
                "HD will have a new HD seed set so that new keys added to the keypool will be derived from this new seed.\n"
                "\nNote that you will need to MAKE A NEW BACKUP of your wallet after setting the HD wallet seed." +
        HELP_REQUIRING_PASSPHRASE,
                {
                    {"newkeypool", RPCArg::Type::BOOL, /* default */ "true", "Whether to flush old unused addresses, including change addresses, from the keypool and regenerate it.\n"
                                         "If true, the next address from getnewaddress and change address from getrawchangeaddress will be from this new seed.\n"
                                         "If false, addresses (including change addresses if the wallet already had HD Chain Split enabled) from the existing\n"
                                         "keypool will be used until it has been depleted."},
                    {"seed", RPCArg::Type::STR, /* default */ "random seed", "The WIF private key to use as the new HD seed.\n"
                                         "The seed value can be retrieved using the dumpwallet command. It is the private key marked hdseed=1"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("sethdseed", "")
            + HelpExampleCli("sethdseed", "false")
            + HelpExampleCli("sethdseed", "true \"wifkey\"")
            + HelpExampleRpc("sethdseed", "true, \"wifkey\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    LegacyScriptPubKeyMan& spk_man = EnsureLegacyScriptPubKeyMan(*pwallet, true);

    if (pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Cannot set a HD seed to a wallet with private keys disabled");
    }

    LOCK2(pwallet->cs_wallet, spk_man.cs_KeyStore);

    // Do not do anything to non-HD wallets
    if (!pwallet->CanSupportFeature(FEATURE_HD)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Cannot set an HD seed on a non-HD wallet. Use the upgradewallet RPC in order to upgrade a non-HD wallet to HD");
    }

    EnsureWalletIsUnlocked(pwallet);

    bool flush_key_pool = true;
    if (!request.params[0].isNull()) {
        flush_key_pool = request.params[0].get_bool();
    }

    CPubKey master_pub_key;
    if (request.params[1].isNull()) {
        master_pub_key = spk_man.GenerateNewSeed();
    } else {
        CKey key = DecodeSecret(request.params[1].get_str());
        if (!key.IsValid()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
        }

        if (HaveKey(spk_man, key)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Already have this key (either as an HD seed or as a loose private key)");
        }

        master_pub_key = spk_man.DeriveNewSeed(key);
    }

    spk_man.SetHDSeed(master_pub_key);
    if (flush_key_pool) spk_man.NewKeyPool();

    return NullUniValue;
},
    };
}

static RPCHelpMan walletprocesspsbt()
{
    return RPCHelpMan{"walletprocesspsbt",
                "\nUpdate a PSBT with input information from our wallet and then sign inputs\n"
                "that we can sign for." +
        HELP_REQUIRING_PASSPHRASE,
                {
                    {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "The transaction base64 string"},
                    {"sign", RPCArg::Type::BOOL, /* default */ "true", "Also sign the transaction when updating"},
                    {"sighashtype", RPCArg::Type::STR, /* default */ "ALL", "The signature hash type to sign with if not specified by the PSBT. Must be one of\n"
            "       \"ALL\"\n"
            "       \"NONE\"\n"
            "       \"SINGLE\"\n"
            "       \"ALL|ANYONECANPAY\"\n"
            "       \"NONE|ANYONECANPAY\"\n"
            "       \"SINGLE|ANYONECANPAY\""},
                    {"bip32derivs", RPCArg::Type::BOOL, /* default */ "true", "Include BIP 32 derivation paths for public keys if we know them"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "psbt", "The base64-encoded partially signed transaction"},
                        {RPCResult::Type::BOOL, "complete", "If the transaction has a complete set of signatures"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("walletprocesspsbt", "\"psbt\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    const CWallet* const pwallet = wallet.get();

    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VBOOL, UniValue::VSTR});

    // Unserialize the transaction
    PartiallySignedTransaction psbtx;
    std::string error;
    if (!DecodeBase64PSBT(psbtx, request.params[0].get_str(), error)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", error));
    }

    // Get the sighash type
    int nHashType = ParseSighashString(request.params[2]);

    // Fill transaction with our data and also sign
    bool sign = request.params[1].isNull() ? true : request.params[1].get_bool();
    bool bip32derivs = request.params[3].isNull() ? true : request.params[3].get_bool();
    bool complete = true;
    const TransactionError err = pwallet->FillPSBT(psbtx, complete, nHashType, sign, bip32derivs);
    if (err != TransactionError::OK) {
        throw JSONRPCTransactionError(err);
    }

    UniValue result(UniValue::VOBJ);
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << psbtx;
    result.pushKV("psbt", EncodeBase64(ssTx.str()));
    result.pushKV("complete", complete);

    return result;
},
    };
}

static RPCHelpMan walletcreatefundedpsbt()
{
    return RPCHelpMan{"walletcreatefundedpsbt",
                "\nCreates and funds a transaction in the Partially Signed Transaction format.\n"
                "Implements the Creator and Updater roles.\n",
                {
                    {"inputs", RPCArg::Type::ARR, RPCArg::Optional::OMITTED_NAMED_ARG, "Leave empty to add inputs automatically. See add_inputs option.",
                        {
                            {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                                {
                                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                                    {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                                    {"sequence", RPCArg::Type::NUM, /* default */ "depends on the value of the 'locktime' and 'options.replaceable' arguments", "The sequence number"},
                                },
                            },
                        },
                        },
                    {"outputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The outputs (key-value pairs), where none of the keys are duplicated.\n"
                            "That is, each address can only appear once and there can only be one 'data' object.\n"
                            "For compatibility reasons, a dictionary, which holds the key-value pairs directly, is also\n"
                            "accepted as second parameter.",
                        {
                            {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                                {
                                    {"address", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "A key-value pair. The key (string) is the litecoin address, the value (float or string) is the amount in " + CURRENCY_UNIT + ""},
                                },
                                },
                            {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                                {
                                    {"data", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "A key-value pair. The key must be \"data\", the value is hex-encoded data"},
                                },
                            },
                        },
                    },
                    {"locktime", RPCArg::Type::NUM, /* default */ "0", "Raw locktime. Non-0 value also locktime-activates inputs"},
                    {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED_NAMED_ARG, "",
                        {
                            {"add_inputs", RPCArg::Type::BOOL, /* default */ "false", "If inputs are specified, automatically include more if they are not enough."},
                            {"changeAddress", RPCArg::Type::STR_HEX, /* default */ "pool address", "The litecoin address to receive the change"},
                            {"changePosition", RPCArg::Type::NUM, /* default */ "random", "The index of the change output"},
                            {"change_type", RPCArg::Type::STR, /* default */ "set by -changetype", "The output type to use. Only valid if changeAddress is not specified. Options are \"legacy\", \"p2sh-segwit\", and \"bech32\"."},
                            {"includeWatching", RPCArg::Type::BOOL, /* default */ "true for watch-only wallets, otherwise false", "Also select inputs which are watch only"},
                            {"lockUnspents", RPCArg::Type::BOOL, /* default */ "false", "Lock selected unspent outputs"},
                            {"fee_rate", RPCArg::Type::AMOUNT, /* default */ "not set, fall back to wallet fee estimation", "Specify a fee rate in " + CURRENCY_ATOM + "/vB."},
                            {"feeRate", RPCArg::Type::AMOUNT, /* default */ "not set, fall back to wallet fee estimation", "Specify a fee rate in " + CURRENCY_UNIT + "/kvB."},
                            {"subtractFeeFromOutputs", RPCArg::Type::ARR, /* default */ "empty array", "The outputs to subtract the fee from.\n"
                                                          "The fee will be equally deducted from the amount of each specified output.\n"
                                                          "Those recipients will receive less litecoins than you enter in their corresponding amount field.\n"
                                                          "If no outputs are specified here, the sender pays the fee.",
                                {
                                    {"vout_index", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "The zero-based output index, before a change output is added."},
                                },
                            },
                            {"replaceable", RPCArg::Type::BOOL, /* default */ "wallet default", "Marks this transaction as BIP125 replaceable.\n"
                                                          "Allows this transaction to be replaced by a transaction with higher fees"},
                            {"conf_target", RPCArg::Type::NUM, /* default */ "wallet -txconfirmtarget", "Confirmation target in blocks"},
                            {"estimate_mode", RPCArg::Type::STR, /* default */ "unset", std::string() + "The fee estimate mode, must be one of (case insensitive):\n"
                            "         \"" + FeeModes("\"\n\"") + "\""},
                        },
                        "options"},
                    {"bip32derivs", RPCArg::Type::BOOL, /* default */ "true", "Include BIP 32 derivation paths for public keys if we know them"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "psbt", "The resulting raw transaction (base64-encoded string)"},
                        {RPCResult::Type::STR_AMOUNT, "fee", "Fee in " + CURRENCY_UNIT + " the resulting transaction pays"},
                        {RPCResult::Type::NUM, "changepos", "The position of the added change output, or -1"},
                    }
                                },
                                RPCExamples{
                            "\nCreate a transaction with no inputs\n"
                            + HelpExampleCli("walletcreatefundedpsbt", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"[{\\\"data\\\":\\\"00010203\\\"}]\"")
                                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    RPCTypeCheck(request.params, {
        UniValue::VARR,
        UniValueType(), // ARR or OBJ, checked later
        UniValue::VNUM,
        UniValue::VOBJ,
        UniValue::VBOOL
        }, true
    );

    CAmount fee;
    int change_position;
    bool rbf = pwallet->m_signal_rbf;
    const UniValue &replaceable_arg = request.params[3]["replaceable"];
    if (!replaceable_arg.isNull()) {
        RPCTypeCheckArgument(replaceable_arg, UniValue::VBOOL);
        rbf = replaceable_arg.isTrue();
    }
    CMutableTransaction rawTx = ConstructTransaction(request.params[0], request.params[1], request.params[2], rbf);
    CCoinControl coin_control;
    // Automatically select coins, unless at least one is manually selected. Can
    // be overridden by options.add_inputs.
    coin_control.m_add_inputs = rawTx.vin.size() == 0;
    FundTransaction(pwallet, rawTx, fee, change_position, request.params[3], coin_control, /* override_min_fee */ true);

    // Make a blank psbt
    PartiallySignedTransaction psbtx(rawTx);

    // Fill transaction with out data but don't sign
    bool bip32derivs = request.params[4].isNull() ? true : request.params[4].get_bool();
    bool complete = true;
    const TransactionError err = pwallet->FillPSBT(psbtx, complete, 1, false, bip32derivs);
    if (err != TransactionError::OK) {
        throw JSONRPCTransactionError(err);
    }

    // Serialize the PSBT
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << psbtx;

    UniValue result(UniValue::VOBJ);
    result.pushKV("psbt", EncodeBase64(ssTx.str()));
    result.pushKV("fee", ValueFromAmount(fee));
    result.pushKV("changepos", change_position);
    return result;
},
    };
}

static RPCHelpMan upgradewallet()
{
    return RPCHelpMan{"upgradewallet",
        "\nUpgrade the wallet. Upgrades to the latest version if no version number is specified.\n"
        "New keys may be generated and a new wallet backup will need to be made.",
        {
            {"version", RPCArg::Type::NUM, /* default */ strprintf("%d", FEATURE_LATEST), "The version number to upgrade to. Default is the latest wallet version."}
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "wallet_name", "Name of wallet this operation was performed on"},
                {RPCResult::Type::NUM, "previous_version", "Version of wallet before this operation"},
                {RPCResult::Type::NUM, "current_version", "Version of wallet after this operation"},
                {RPCResult::Type::STR, "result", /* optional */ true, "Description of result, if no error"},
                {RPCResult::Type::STR, "error", /* optional */ true, "Error message (if there is one)"}
            },
        },
        RPCExamples{
            HelpExampleCli("upgradewallet", "169900")
            + HelpExampleRpc("upgradewallet", "169900")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    RPCTypeCheck(request.params, {UniValue::VNUM}, true);

    EnsureWalletIsUnlocked(pwallet);

    int version = 0;
    if (!request.params[0].isNull()) {
        version = request.params[0].get_int();
    }
    bilingual_str error;
    const int previous_version{pwallet->GetVersion()};
    const bool wallet_upgraded{pwallet->UpgradeWallet(version, error)};
    const int current_version{pwallet->GetVersion()};
    std::string result;

    if (wallet_upgraded) {
        if (previous_version == current_version) {
            result = "Already at latest version. Wallet version unchanged.";
        } else {
            result = strprintf("Wallet upgraded successfully from version %i to version %i.", previous_version, current_version);
        }
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("wallet_name", pwallet->GetName());
    obj.pushKV("previous_version", previous_version);
    obj.pushKV("current_version", current_version);
    if (!result.empty()) {
        obj.pushKV("result", result);
    } else {
        CHECK_NONFATAL(!error.empty());
        obj.pushKV("error", error.original);
    }
    return obj;
},
    };
}

RPCHelpMan abortrescan();
RPCHelpMan dumpprivkey();
RPCHelpMan importprivkey();
RPCHelpMan importaddress();
RPCHelpMan importpubkey();
RPCHelpMan dumpwallet();
RPCHelpMan importwallet();
RPCHelpMan importprunedfunds();
RPCHelpMan removeprunedfunds();
RPCHelpMan importmulti();
RPCHelpMan importdescriptors();

Span<const CRPCCommand> GetWalletRPCCommands()
{
// clang-format off
static const CRPCCommand commands[] =
{ //  category              name                                actor (function)                argNames
    //  --------------------- ------------------------          -----------------------         ----------
    { "rawtransactions",    "fundrawtransaction",               &fundrawtransaction,            {"hexstring","options","iswitness"} },
    { "wallet",             "abandontransaction",               &abandontransaction,            {"txid"} },
    { "wallet",             "abortrescan",                      &abortrescan,                   {} },
    { "wallet",             "addmultisigaddress",               &addmultisigaddress,            {"nrequired","keys","label","address_type"} },
    { "wallet",             "backupwallet",                     &backupwallet,                  {"destination"} },
    { "wallet",             "bumpfee",                          &bumpfee,                       {"txid", "options"} },
    { "wallet",             "psbtbumpfee",                      &psbtbumpfee,                   {"txid", "options"} },
    { "wallet",             "createwallet",                     &createwallet,                  {"wallet_name", "disable_private_keys", "blank", "passphrase", "avoid_reuse", "descriptors", "load_on_startup"} },
    { "wallet",             "dumpprivkey",                      &dumpprivkey,                   {"address"}  },
    { "wallet",             "dumpwallet",                       &dumpwallet,                    {"filename"} },
    { "wallet",             "encryptwallet",                    &encryptwallet,                 {"passphrase"} },
    { "wallet",             "getaddressesbylabel",              &getaddressesbylabel,           {"label"} },
    { "wallet",             "getaddressinfo",                   &getaddressinfo,                {"address"} },
    { "wallet",             "getbalance",                       &getbalance,                    {"dummy","minconf","include_watchonly","avoid_reuse"} },
    { "wallet",             "getnewaddress",                    &getnewaddress,                 {"label","address_type"} },
    { "wallet",             "getrawchangeaddress",              &getrawchangeaddress,           {"address_type"} },
    { "wallet",             "getreceivedbyaddress",             &getreceivedbyaddress,          {"address","minconf"} },
    { "wallet",             "getreceivedbylabel",               &getreceivedbylabel,            {"label","minconf"} },
    { "wallet",             "gettransaction",                   &gettransaction,                {"txid","include_watchonly","verbose"} },
    { "wallet",             "getunconfirmedbalance",            &getunconfirmedbalance,         {} },
    { "wallet",             "getbalances",                      &getbalances,                   {} },
    { "wallet",             "getwalletinfo",                    &getwalletinfo,                 {} },
    { "wallet",             "importaddress",                    &importaddress,                 {"address","label","rescan","p2sh"} },
    { "wallet",             "importdescriptors",                &importdescriptors,             {"requests"} },
    { "wallet",             "importmulti",                      &importmulti,                   {"requests","options"} },
    { "wallet",             "importprivkey",                    &importprivkey,                 {"privkey","label","rescan"} },
    { "wallet",             "importprunedfunds",                &importprunedfunds,             {"rawtransaction","txoutproof"} },
    { "wallet",             "importpubkey",                     &importpubkey,                  {"pubkey","label","rescan"} },
    { "wallet",             "importwallet",                     &importwallet,                  {"filename"} },
    { "wallet",             "keypoolrefill",                    &keypoolrefill,                 {"newsize"} },
    { "wallet",             "listaddressgroupings",             &listaddressgroupings,          {} },
    { "wallet",             "listlabels",                       &listlabels,                    {"purpose"} },
    { "wallet",             "listlockunspent",                  &listlockunspent,               {} },
    { "wallet",             "listreceivedbyaddress",            &listreceivedbyaddress,         {"minconf","include_empty","include_watchonly","address_filter"} },
    { "wallet",             "listreceivedbylabel",              &listreceivedbylabel,           {"minconf","include_empty","include_watchonly"} },
    { "wallet",             "listsinceblock",                   &listsinceblock,                {"blockhash","target_confirmations","include_watchonly","include_removed"} },
    { "wallet",             "listtransactions",                 &listtransactions,              {"label|dummy","count","skip","include_watchonly"} },
    { "wallet",             "listwallettransactions",           &listwallettransactions,        {"txid"} },
    { "wallet",             "listunspent",                      &listunspent,                   {"minconf","maxconf","addresses","include_unsafe","query_options"} },
    { "wallet",             "listwalletdir",                    &listwalletdir,                 {} },
    { "wallet",             "listwallets",                      &listwallets,                   {} },
    { "wallet",             "loadwallet",                       &loadwallet,                    {"filename", "load_on_startup"} },
    { "wallet",             "lockunspent",                      &lockunspent,                   {"unlock","transactions"} },
    { "wallet",             "removeprunedfunds",                &removeprunedfunds,             {"txid"} },
    { "wallet",             "rescanblockchain",                 &rescanblockchain,              {"start_height", "stop_height"} },
    { "wallet",             "send",                             &send,                          {"outputs","conf_target","estimate_mode","fee_rate","options"} },
    { "wallet",             "sendmany",                         &sendmany,                      {"dummy","amounts","minconf","comment","subtractfeefrom","replaceable","conf_target","estimate_mode","fee_rate","verbose"} },
    { "wallet",             "sendtoaddress",                    &sendtoaddress,                 {"address","amount","comment","comment_to","subtractfeefromamount","replaceable","conf_target","estimate_mode","avoid_reuse","fee_rate","verbose"} },
    { "wallet",             "sethdseed",                        &sethdseed,                     {"newkeypool","seed"} },
    { "wallet",             "setlabel",                         &setlabel,                      {"address","label"} },
    { "wallet",             "settxfee",                         &settxfee,                      {"amount"} },
    { "wallet",             "setwalletflag",                    &setwalletflag,                 {"flag","value"} },
    { "wallet",             "signmessage",                      &signmessage,                   {"address","message"} },
    { "wallet",             "signrawtransactionwithwallet",     &signrawtransactionwithwallet,  {"hexstring","prevtxs","sighashtype"} },
    { "wallet",             "senddrivechainregister",           &senddrivechainregister,        {"owner_addresses", "sidechain_id", "amount", "subtractfeefromamount", "auth_threshold", "max_escrow_amount", "max_bundle_withdrawal"} },
    { "wallet",             "senddrivechaindeposit",            &senddrivechaindeposit,         {"sidechain_id", "payload", "amounts", "subtract_fee"} },
    { "wallet",             "senddrivechainbundle",             &senddrivechainbundle,          {"sidechain_id", "bundle_hash", "owner_addresses"} },
    { "wallet",             "senddrivechainbmmrequest",         &senddrivechainbmmrequest,      {"sidechain_id", "side_block_hash", "prev_main_block_hash", "amount", "subtractfeefromamount"} },
    { "wallet",             "senddrivechainexecute",            &senddrivechainexecute,         {"sidechain_id", "bundle_hash", "withdrawals", "allow_unbroadcast"} },
    { "wallet",             "sendvaliditysidechainregister",    &sendvaliditysidechainregister, {"sidechain_id", "config", "amount", "subtractfeefromamount"} },
    { "wallet",             "sendvaliditydeposit",              &sendvaliditydeposit,           {"sidechain_id", "destination_commitment", "refund_destination", "amount", "nonce", "deposit_id", "subtractfeefromamount"} },
    { "wallet",             "sendforceexitrequest",             &sendforceexitrequest,          {"sidechain_id", "account_id", "exit_asset_id", "max_exit_amount", "destination", "nonce"} },
    { "wallet",             "sendstaledepositreclaim",          &sendstaledepositreclaim,       {"sidechain_id", "deposit", "refund_destination", "allow_unbroadcast"} },
    { "wallet",             "sendvaliditybatch",                &sendvaliditybatch,             {"sidechain_id", "public_inputs", "proof_bytes", "data_chunks", "allow_unbroadcast"} },
    { "wallet",             "sendverifiedwithdrawals",          &sendverifiedwithdrawals,       {"sidechain_id", "batch_number", "withdrawals", "allow_unbroadcast"} },
    { "wallet",             "sendescapeexit",                   &sendescapeexit,                {"sidechain_id", "state_root_reference", "exits", "allow_unbroadcast"} },
    { "wallet",             "unloadwallet",                     &unloadwallet,                  {"wallet_name", "load_on_startup"} },
    { "wallet",             "upgradewallet",                    &upgradewallet,                 {"version"} },
    { "wallet",             "walletcreatefundedpsbt",           &walletcreatefundedpsbt,        {"inputs","outputs","locktime","options","bip32derivs"} },
    { "wallet",             "walletlock",                       &walletlock,                    {} },
    { "wallet",             "walletpassphrase",                 &walletpassphrase,              {"passphrase","timeout"} },
    { "wallet",             "walletpassphrasechange",           &walletpassphrasechange,        {"oldpassphrase","newpassphrase"} },
    { "wallet",             "walletprocesspsbt",                &walletprocesspsbt,             {"psbt","sign","sighashtype","bip32derivs"} },
};
// clang-format on
    return MakeSpan(commands);
}
