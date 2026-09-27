// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <index/spkindex.h>

#include <common/args.h>
#include <crypto/siphash.h>
#include <dbwrapper.h>
#include <flatfile.h>
#include <index/base.h>
#include <index/disktxpos.h>
#include <interfaces/chain.h>
#include <logging.h>
#include <node/blockstorage.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/script.h>
#include <serialize.h>
#include <streams.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/fs.h>
#include <util/strencodings.h>
#include <validation.h>

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <exception>
#include <ios>
#include <span>
#include <string>
#include <utility>
#include <vector>

/* The database is used to find all confirmed outputs paying to a given scriptPubKey, similar to
 * the "funding" rows of electrs. For every transaction and every distinct scriptPubKey among its
 * outputs, it stores a key that is (siphash(scriptPubKey), block height, transaction location on disk)
 * and a zero-byte value. The height is stored big-endian so results come back in chain order.
 * To find the outputs of a scriptPubKey, we perform a range query on siphash(scriptPubKey), and for
 * each returned key load the transaction and return the outputs that actually match, which filters
 * out hash collisions.
 */

// LevelDB key prefix.
constexpr uint8_t DB_SPKINDEX{'o'};

std::unique_ptr<SpkIndex> g_spkindex;

namespace {
struct DBKey {
    uint64_t hash;
    uint32_t height;
    CDiskTxPos pos;

    explicit DBKey(uint64_t hash_in, uint32_t height_in, const CDiskTxPos& pos_in) : hash(hash_in), height(height_in), pos(pos_in) {}

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ser_writedata8(s, DB_SPKINDEX);
        ::Serialize(s, hash);
        ser_writedata32be(s, height);
        ::Serialize(s, pos);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        if (ser_readdata8(s) != DB_SPKINDEX) {
            throw std::ios_base::failure("Invalid format for spk index DB key");
        }
        ::Unserialize(s, hash);
        height = ser_readdata32be(s);
        ::Unserialize(s, pos);
    }
};
} // namespace

SpkIndex::SpkIndex(std::unique_ptr<interfaces::Chain> chain, size_t n_cache_size, bool f_memory, bool f_wipe)
    : BaseIndex(std::move(chain), "spkindex", "spkidx"), m_db{std::make_unique<DB>(gArgs.GetDataDirNet() / "indexes" / "spkindex" / "db", n_cache_size, f_memory, f_wipe, /*f_obfuscate=*/false, /*f_bloom=*/false)}
{
    if (!m_db->Read("siphash_key", m_siphash_key)) {
        FastRandomContext rng(false);
        m_siphash_key = {rng.rand64(), rng.rand64()};
        m_db->Write("siphash_key", m_siphash_key, /*fSync=*/true);
    }
}

interfaces::Chain::NotifyOptions SpkIndex::CustomOptions()
{
    interfaces::Chain::NotifyOptions options;
    options.disconnect_data = true;
    return options;
}

static uint64_t HashScript(std::pair<uint64_t, uint64_t> siphash_key, const CScript& script)
{
    return CSipHasher(siphash_key.first, siphash_key.second).Write(std::span<const unsigned char>{script.data(), script.size()}).Finalize();
}

std::vector<std::pair<uint64_t, CDiskTxPos>> SpkIndex::BuildEntries(const interfaces::BlockInfo& block) const
{
    std::vector<std::pair<uint64_t, CDiskTxPos>> items;
    items.reserve(block.data->vtx.size() * 2);

    std::vector<uint64_t> tx_hashes;
    CDiskTxPos pos({block.file_number, block.data_pos}, GetSizeOfCompactSize(block.data->vtx.size()));
    for (const auto& tx : block.data->vtx) {
        // One entry per distinct scriptPubKey hash per transaction; the lookup scans all outputs.
        tx_hashes.clear();
        for (const auto& txout : tx->vout) {
            tx_hashes.push_back(HashScript(m_siphash_key, txout.scriptPubKey));
        }
        std::sort(tx_hashes.begin(), tx_hashes.end());
        tx_hashes.erase(std::unique(tx_hashes.begin(), tx_hashes.end()), tx_hashes.end());
        for (const uint64_t hash : tx_hashes) {
            items.emplace_back(hash, pos);
        }
        pos.nTxOffset += ::GetSerializeSize(TX_WITH_WITNESS(*tx));
    }

    return items;
}

bool SpkIndex::CustomAppend(const interfaces::BlockInfo& block)
{
    CDBBatch batch(*m_db);
    for (const auto& [hash, pos] : BuildEntries(block)) {
        // The key encodes everything needed for lookups. The value is only a marker.
        batch.Write(DBKey(hash, block.height, pos), std::span<const std::byte>{});
    }
    m_db->WriteBatch(batch);
    return true;
}

bool SpkIndex::CustomRemove(const interfaces::BlockInfo& block)
{
    CDBBatch batch(*m_db);
    for (const auto& [hash, pos] : BuildEntries(block)) {
        batch.Erase(DBKey(hash, block.height, pos));
    }
    m_db->WriteBatch(batch);
    return true;
}

util::Expected<std::pair<uint256, CTransactionRef>, std::string> SpkIndex::ReadTransaction(const CDiskTxPos& tx_pos) const
{
    AutoFile file{m_chainstate->m_blockman.OpenBlockFile(tx_pos, /*fReadOnly=*/true)};
    if (file.IsNull()) {
        return util::Unexpected("cannot open block");
    }
    CBlockHeader header;
    CTransactionRef tx;
    try {
        file >> header;
        file.seek(tx_pos.nTxOffset, SEEK_CUR);
        file >> TX_WITH_WITNESS(tx);
        return std::pair{header.GetHash(), std::move(tx)};
    } catch (const std::exception& e) {
        return util::Unexpected(e.what());
    }
}

util::Expected<std::vector<SpkTxOut>, std::string> SpkIndex::FindTxOuts(const CScript& script) const
{
    const uint64_t prefix{HashScript(m_siphash_key, script)};
    std::unique_ptr<CDBIterator> it(m_db->NewIterator());
    DBKey key(prefix, 0, CDiskTxPos());
    std::vector<SpkTxOut> result;

    // Find all keys that start with the script hash, load the transaction at the location specified
    // in the key and return every output that pays to the provided script.
    for (it->Seek(std::pair{DB_SPKINDEX, prefix}); it->Valid() && it->GetKey(key) && key.hash == prefix; it->Next()) {
        const auto tx{ReadTransaction(key.pos)};
        if (!tx) {
            LogError("Deserialize or I/O error - %s", tx.error());
            return util::Unexpected{strprintf("IO error finding outputs for script %s.", HexStr(script))};
        }
        const auto& [block_hash, txref] = *tx;
        for (uint32_t n{0}; n < txref->vout.size(); ++n) {
            if (txref->vout[n].scriptPubKey == script) {
                result.push_back({COutPoint{txref->GetHash(), n}, txref->vout[n], block_hash, static_cast<int>(key.height)});
            }
        }
    }
    return result;
}

BaseIndex::DB& SpkIndex::GetDB() const { return *m_db; }
