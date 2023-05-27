// Copyright (c) 2014-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key_io.h>

#include <base58.h>
#include <bech32.h>
#include <util/strencodings.h>

#include <algorithm>
#include <assert.h>
#include <string.h>

/// Maximum witness length for Bech32 addresses.
static constexpr std::size_t BECH32_WITNESS_PROG_MAX_LEN = 40;

namespace {
class DestinationEncoder
{
private:
    const CChainParams& m_params;

public:
    explicit DestinationEncoder(const CChainParams& params) : m_params(params) {}

    std::string operator()(const PKHash& id) const
    {
        std::vector<unsigned char> data = m_params.Base58Prefix(CChainParams::PUBKEY_ADDRESS);
        data.insert(data.end(), id.begin(), id.end());
        return EncodeBase58Check(data);
    }

    std::string operator()(const ScriptHash& id) const
    {
        std::vector<unsigned char> data = m_params.Base58Prefix(CChainParams::SCRIPT_ADDRESS);
        data.insert(data.end(), id.begin(), id.end());
        return EncodeBase58Check(data);
    }

    std::string operator()(const WitnessV0KeyHash& id) const
    {
        std::vector<unsigned char> data = {0};
        data.reserve(33);
        ConvertBits<8, 5, true>([&](unsigned char c) { data.push_back(c); }, id.begin(), id.end());
        return bech32::Encode(bech32::Encoding::BECH32, m_params.Bech32HRP(), data);
    }

    std::string operator()(const WitnessV0ScriptHash& id) const
    {
        std::vector<unsigned char> data = {0};
        data.reserve(53);
        ConvertBits<8, 5, true>([&](unsigned char c) { data.push_back(c); }, id.begin(), id.end());
        return bech32::Encode(bech32::Encoding::BECH32, m_params.Bech32HRP(), data);
    }

    std::string operator()(const WitnessV1Taproot& tap) const
    {
        std::vector<unsigned char> data = {1};
        data.reserve(53);
        ConvertBits<8, 5, true>([&](unsigned char c) { data.push_back(c); }, tap.begin(), tap.end());
        return bech32::Encode(bech32::Encoding::BECH32M, m_params.Bech32HRP(), data);
    }

    std::string operator()(const WitnessUnknown& id) const
    {
        if (id.version < 1 || id.version > 16 || id.length < 2 || id.length > 40) {
            return {};
        }
        std::vector<unsigned char> data = {(unsigned char)id.version};
        data.reserve(1 + (id.length * 8 + 4) / 5);
        ConvertBits<8, 5, true>([&](unsigned char c) { data.push_back(c); }, id.program, id.program + id.length);
        return bech32::Encode(bech32::Encoding::BECH32M, m_params.Bech32HRP(), data);
    }

    std::string operator()(const CNoDestination& no) const { return {}; }
};

CTxDestination DecodeDestination(const std::string& str, const CChainParams& params, std::string& error_str, std::vector<int>* error_locations)
{
    uint160 hash;
    error_str = "";

    struct decodeState {
        const bech32::DecodeResult bech32DecodeResult;
        uint8_t maxBase58CheckChars = 21;
        uint8_t maxBase58Chars = 100;
        bool is_base58 = false;
        bool is_base58Check = false;
        bool is_bech32 = false;
        bool is_validBech32Chars = false;
        std::pair<std::string, std::vector<int>> bech32DecodeErrors;
        std::vector<unsigned char> base58DataRaw, base58DataCheck, bech32Data;
        std::string networkLabel;
        // Perform base58/bech32 decoding on the input string
        decodeState(std::string str, std::string chainName) : bech32DecodeResult(bech32::Decode(str))
        {
            is_base58 = DecodeBase58(str, base58DataRaw, maxBase58Chars);
            is_base58Check = DecodeBase58Check(str, base58DataCheck, maxBase58CheckChars);
            is_bech32 = bech32DecodeResult.encoding != bech32::Encoding::INVALID;
            networkLabel = (chainName == "main" || chainName == "test") ? chainName + "net" : chainName;
            if (!is_bech32) {
                auto [bech32ErrorStr, bech32ErrorLoc] = bech32DecodeErrors;
                bech32DecodeErrors = bech32::LocateErrors(str);
                is_validBech32Chars = (bech32ErrorStr != "Invalid Base 32 character" &&
                                       bech32ErrorStr != "Invalid character or mixed case" &&
                                       bech32ErrorStr != "Invalid separator position");
            } else {
                is_validBech32Chars = true;
            }
        }
    };

    decodeState Decoded{str, params.GetChainTypeString()};
    // Direct bindings (alais) to members of Decoded
    auto& bech32Encoding = Decoded.bech32DecodeResult.encoding;
    auto& bech32Hrp = Decoded.bech32DecodeResult.hrp;
    auto& bech32Chars = Decoded.bech32DecodeResult.data;
    auto& bech32Error = Decoded.bech32DecodeErrors.first;
    auto& bech32ErrorLoc = Decoded.bech32DecodeErrors.second;
    auto& is_bech32 = Decoded.is_bech32;
    auto& is_base58 = Decoded.is_base58;
    auto& is_base58Check = Decoded.is_base58Check;
    auto& is_validBech32Chars = Decoded.is_validBech32Chars;
    auto& base58Data = Decoded.base58DataCheck;
    auto& bech32Data = Decoded.bech32Data;
    auto& networkLabel = Decoded.networkLabel;

    // If this is not 'bech32(m)' attempt to decode why for error reporting
    if (!is_bech32 && is_base58Check) {
        // base58-encoded Bitcoin addresses.
        // Public-key-hash-addresses have version 0 (or 111 testnet).
        // The base58Data vector contains RIPEMD160(SHA256(pubkey)), where pubkey is the serialized public key.
        const std::vector<unsigned char>& pubkey_prefix = params.Base58Prefix(CChainParams::PUBKEY_ADDRESS);
        if (base58Data.size() == hash.size() + pubkey_prefix.size() && std::equal(pubkey_prefix.begin(), pubkey_prefix.end(), base58Data.begin())) {
            std::copy(base58Data.begin() + pubkey_prefix.size(), base58Data.end(), hash.begin());
            return PKHash(hash);
        }
        // Script-hash-addresses have version 5 (or 196 testnet).
        // The base58Data vector contains RIPEMD160(SHA256(cscript)), where cscript is the serialized redemption script.
        const std::vector<unsigned char>& script_prefix = params.Base58Prefix(CChainParams::SCRIPT_ADDRESS);
        if (base58Data.size() == hash.size() + script_prefix.size() && std::equal(script_prefix.begin(), script_prefix.end(), base58Data.begin())) {
            std::copy(base58Data.begin() + script_prefix.size(), base58Data.end(), hash.begin());
            return ScriptHash(hash);
        }
        // If the prefix of data matches either the script or pubkey prefix, the length must have been wrong
        if ((base58Data.size() >= script_prefix.size() &&
                std::equal(script_prefix.begin(), script_prefix.end(), base58Data.begin())) ||
            (base58Data.size() >= pubkey_prefix.size() &&
                std::equal(pubkey_prefix.begin(), pubkey_prefix.end(), base58Data.begin()))) {
            error_str = "Invalid length for Base58 address (P2PKH or P2SH)";
        } else {
            std::string chainPrefixes = params.GetChainTypeString() == "main" ? "1 or 3" : "m, n, or 2";
            error_str = strprintf("Invalid or unsupported Base58 %s address. Expected prefix %s", networkLabel, chainPrefixes);
        }
        return CNoDestination();
    } else if (!is_bech32) {
        if (!is_base58) {
            error_str = is_validBech32Chars ? "Bech32(m) address decoded with error: " + bech32Error : "Address is not valid Base58 or Bech32";
            if (error_locations) *error_locations = std::move(bech32ErrorLoc);
        }
        else {
            error_str = is_validBech32Chars
                ? "Invalid address encoded as Base58 and Bech32(m) provided"
                : "Invalid checksum or length of Base58 address (P2PKH or P2SH)";
            if (is_validBech32Chars && error_locations) {
                *error_locations = std::move(bech32ErrorLoc);
            }
        }
        return CNoDestination();
    }

    if ((bech32Encoding == bech32::Encoding::BECH32 || bech32Encoding == bech32::Encoding::BECH32M) && bech32Chars.size() > 0) {
        // Bech32 decoding
        if (bech32Hrp != params.Bech32HRP()) {
            error_str = strprintf("Invalid chain prefix for %s. Expected %s got %s", networkLabel, params.Bech32HRP(), bech32Hrp);
            return CNoDestination();
        }
        int version = bech32Chars[0]; // The first 5 bit symbol is the witness version (0-16)
        if (version == 0 && bech32Encoding != bech32::Encoding::BECH32) {
            error_str = "Version 0 witness address must use Bech32 checksum";
            return CNoDestination();
        }
        if (version != 0 && bech32Encoding != bech32::Encoding::BECH32M) {
            error_str = "Version 1+ witness address must use Bech32m checksum";
            return CNoDestination();
        }
        // The rest of the symbols are converted witness program bytes.
        bech32Data.reserve(((bech32Chars.size() - 1) * 5) / 8);
        if (ConvertBits<5, 8, false>([&bech32Data](unsigned char c) {bech32Data.push_back(c); }, bech32Chars.begin() + 1, bech32Chars.end())) {
            if (version == 0) {
                {
                    WitnessV0KeyHash keyid;
                    if (bech32Data.size() == keyid.size()) {
                        std::copy(bech32Data.begin(), bech32Data.end(), keyid.begin());
                        return keyid;
                    }
                }
                {
                    WitnessV0ScriptHash scriptid;
                    if (bech32Data.size() == scriptid.size()) {
                        std::copy(bech32Data.begin(), bech32Data.end(), scriptid.begin());
                        return scriptid;
                    }
                }

                error_str = "Invalid Bech32 v0 address data size";
                return CNoDestination();
            }

            if (version == 1 && bech32Data.size() == WITNESS_V1_TAPROOT_SIZE) {
                static_assert(WITNESS_V1_TAPROOT_SIZE == WitnessV1Taproot::size());
                WitnessV1Taproot tap;
                std::copy(bech32Data.begin(), bech32Data.end(), tap.begin());
                return tap;
            }

            if (version > 16) {
                error_str = "Invalid Bech32 address witness version";
                return CNoDestination();
            }

            if (bech32Data.size() < 2 || bech32Data.size() > BECH32_WITNESS_PROG_MAX_LEN) {
                error_str = "Invalid Bech32 address data size";
                return CNoDestination();
            }

            WitnessUnknown unk;
            unk.version = version;
            std::copy(bech32Data.begin(), bech32Data.end(), unk.program);
            unk.length = bech32Data.size();
            return unk;
        }
    }

    // Return results of Bech32(m) error location
    error_str = bech32Error;
    if (error_locations) *error_locations = std::move(bech32ErrorLoc);
    return CNoDestination();
}
} // namespace

CKey DecodeSecret(const std::string& str)
{
    CKey key;
    std::vector<unsigned char> data;
    if (DecodeBase58Check(str, data, 34)) {
        const std::vector<unsigned char>& privkey_prefix = Params().Base58Prefix(CChainParams::SECRET_KEY);
        if ((data.size() == 32 + privkey_prefix.size() || (data.size() == 33 + privkey_prefix.size() && data.back() == 1)) &&
            std::equal(privkey_prefix.begin(), privkey_prefix.end(), data.begin())) {
            bool compressed = data.size() == 33 + privkey_prefix.size();
            key.Set(data.begin() + privkey_prefix.size(), data.begin() + privkey_prefix.size() + 32, compressed);
        }
    }
    if (!data.empty()) {
        memory_cleanse(data.data(), data.size());
    }
    return key;
}

std::string EncodeSecret(const CKey& key)
{
    assert(key.IsValid());
    std::vector<unsigned char> data = Params().Base58Prefix(CChainParams::SECRET_KEY);
    data.insert(data.end(), key.begin(), key.end());
    if (key.IsCompressed()) {
        data.push_back(1);
    }
    std::string ret = EncodeBase58Check(data);
    memory_cleanse(data.data(), data.size());
    return ret;
}

CExtPubKey DecodeExtPubKey(const std::string& str)
{
    CExtPubKey key;
    std::vector<unsigned char> data;
    if (DecodeBase58Check(str, data, 78)) {
        const std::vector<unsigned char>& prefix = Params().Base58Prefix(CChainParams::EXT_PUBLIC_KEY);
        if (data.size() == BIP32_EXTKEY_SIZE + prefix.size() && std::equal(prefix.begin(), prefix.end(), data.begin())) {
            key.Decode(data.data() + prefix.size());
        }
    }
    return key;
}

std::string EncodeExtPubKey(const CExtPubKey& key)
{
    std::vector<unsigned char> data = Params().Base58Prefix(CChainParams::EXT_PUBLIC_KEY);
    size_t size = data.size();
    data.resize(size + BIP32_EXTKEY_SIZE);
    key.Encode(data.data() + size);
    std::string ret = EncodeBase58Check(data);
    return ret;
}

CExtKey DecodeExtKey(const std::string& str)
{
    CExtKey key;
    std::vector<unsigned char> data;
    if (DecodeBase58Check(str, data, 78)) {
        const std::vector<unsigned char>& prefix = Params().Base58Prefix(CChainParams::EXT_SECRET_KEY);
        if (data.size() == BIP32_EXTKEY_SIZE + prefix.size() && std::equal(prefix.begin(), prefix.end(), data.begin())) {
            key.Decode(data.data() + prefix.size());
        }
    }
    return key;
}

std::string EncodeExtKey(const CExtKey& key)
{
    std::vector<unsigned char> data = Params().Base58Prefix(CChainParams::EXT_SECRET_KEY);
    size_t size = data.size();
    data.resize(size + BIP32_EXTKEY_SIZE);
    key.Encode(data.data() + size);
    std::string ret = EncodeBase58Check(data);
    memory_cleanse(data.data(), data.size());
    return ret;
}

std::string EncodeDestination(const CTxDestination& dest)
{
    return std::visit(DestinationEncoder(Params()), dest);
}

CTxDestination DecodeDestination(const std::string& str, std::string& error_msg, std::vector<int>* error_locations)
{
    return DecodeDestination(str, Params(), error_msg, error_locations);
}

CTxDestination DecodeDestination(const std::string& str)
{
    std::string error_msg;
    return DecodeDestination(str, error_msg);
}

bool IsValidDestinationString(const std::string& str, const CChainParams& params)
{
    std::string error_msg;
    return IsValidDestination(DecodeDestination(str, params, error_msg, nullptr));
}

bool IsValidDestinationString(const std::string& str)
{
    return IsValidDestinationString(str, Params());
}
