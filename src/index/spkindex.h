// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INDEX_SPKINDEX_H
#define BITCOIN_INDEX_SPKINDEX_H

#include <index/base.h>
#include <interfaces/chain.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <uint256.h>
#include <util/expected.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

struct CDiskTxPos;

inline constexpr bool DEFAULT_SPKINDEX{false};

struct SpkTxOut {
    COutPoint outpoint;
    CTxOut txout;
    uint256 block_hash;
    int height;
};

/**
 * SpkIndex is used to look up all confirmed transaction outputs paying to a given scriptPubKey,
 * in the style of the electrs "funding" rows. The index is written to a LevelDB database and,
 * for each transaction in a block, records one entry per distinct scriptPubKey among its outputs.
 */
class SpkIndex final : public BaseIndex
{
private:
    std::unique_ptr<BaseIndex::DB> m_db;
    std::pair<uint64_t, uint64_t> m_siphash_key;
    bool AllowPrune() const override { return false; }
    std::vector<std::pair<uint64_t, CDiskTxPos>> BuildEntries(const interfaces::BlockInfo& block) const;
    util::Expected<std::pair<uint256, CTransactionRef>, std::string> ReadTransaction(const CDiskTxPos& pos) const;

protected:
    interfaces::Chain::NotifyOptions CustomOptions() override;

    bool CustomAppend(const interfaces::BlockInfo& block) override;

    bool CustomRemove(const interfaces::BlockInfo& block) override;

    BaseIndex::DB& GetDB() const override;

public:
    explicit SpkIndex(std::unique_ptr<interfaces::Chain> chain, size_t n_cache_size, bool f_memory = false, bool f_wipe = false);

    /**
     * Search the index for all confirmed outputs paying to the given scriptPubKey.
     *
     * @param[in] script  The scriptPubKey to search for.
     *
     * @return  The matching outputs, ordered by block height, or
     *          util::Unexpected{error} if something unexpected happened (i.e. disk or deserialization error).
     */
    util::Expected<std::vector<SpkTxOut>, std::string> FindTxOuts(const CScript& script) const;
};

/// The global scriptPubKey index. May be null.
extern std::unique_ptr<SpkIndex> g_spkindex;

#endif // BITCOIN_INDEX_SPKINDEX_H
