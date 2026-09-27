// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <index/spkindex.h>
#include <script/script.h>
#include <test/util/common.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(spkindex_tests)

BOOST_FIXTURE_TEST_CASE(spkindex_initial_sync, TestChain100Setup)
{
    const CScript& coinbase_script = m_coinbase_txns[0]->vout[0].scriptPubKey;
    const CScript other_script = CScript() << OP_TRUE;

    // Spend a coinbase output into two outputs to other_script and one back to coinbase_script.
    CMutableTransaction tx;
    tx.version = 1;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(m_coinbase_txns[0]->GetHash(), 0);
    const CAmount value{m_coinbase_txns[0]->GetValueOut()};
    tx.vout.emplace_back(value / 4, other_script);
    tx.vout.emplace_back(value / 4, coinbase_script);
    tx.vout.emplace_back(value / 4, other_script);
    std::vector<unsigned char> sig;
    const uint256 hash = SignatureHash(coinbase_script, tx, 0, SIGHASH_ALL, 0, SigVersion::BASE);
    BOOST_REQUIRE(coinbaseKey.Sign(hash, sig));
    sig.push_back((unsigned char)SIGHASH_ALL);
    tx.vin[0].scriptSig << sig;

    const uint256 tip_hash = CreateAndProcessBlock({tx}, coinbase_script).GetHash();
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    const int tip_height{WITH_LOCK(::cs_main, return m_node.chainman->ActiveHeight())};

    SpkIndex spkindex(interfaces::MakeChain(m_node), 1 << 20, true);
    BOOST_REQUIRE(spkindex.Init());
    BOOST_CHECK(spkindex.FindTxOuts(other_script)->empty());

    spkindex.Sync();
    BOOST_CHECK_EQUAL(spkindex.GetSummary().best_block_hash, tip_hash);

    // Both outputs of the spending tx to other_script are found.
    const auto other{spkindex.FindTxOuts(other_script)};
    BOOST_REQUIRE(other.has_value());
    BOOST_REQUIRE_EQUAL(other->size(), 2U);
    for (size_t i = 0; i < 2; ++i) {
        BOOST_CHECK_EQUAL((*other)[i].outpoint.hash, tx.GetHash());
        BOOST_CHECK_EQUAL((*other)[i].outpoint.n, i * 2);
        BOOST_CHECK_EQUAL((*other)[i].txout.nValue, value / 4);
        BOOST_CHECK_EQUAL((*other)[i].block_hash, tip_hash);
        BOOST_CHECK_EQUAL((*other)[i].height, tip_height);
    }

    // Every coinbase output plus the change output of the spending tx, in height order.
    const auto cb{spkindex.FindTxOuts(coinbase_script)};
    BOOST_REQUIRE(cb.has_value());
    BOOST_CHECK_EQUAL(cb->size(), static_cast<size_t>(tip_height) + 1);
    for (size_t i = 1; i < cb->size(); ++i) {
        BOOST_CHECK_LE((*cb)[i - 1].height, (*cb)[i].height);
    }

    BOOST_CHECK(spkindex.FindTxOuts(CScript() << OP_RETURN)->empty());

    // Disconnecting the tip removes its entries right away, without waiting for a new block.
    {
        BlockValidationState state;
        CBlockIndex* tip{WITH_LOCK(::cs_main, return m_node.chainman->ActiveTip())};
        BOOST_REQUIRE(m_node.chainman->ActiveChainstate().InvalidateBlock(state, tip));
    }
    BOOST_REQUIRE(spkindex.BlockUntilSyncedToCurrentChain());
    BOOST_CHECK_EQUAL(spkindex.GetSummary().best_block_height, tip_height - 1);
    BOOST_CHECK(spkindex.FindTxOuts(other_script)->empty());
    BOOST_CHECK_EQUAL(spkindex.FindTxOuts(coinbase_script)->size(), static_cast<size_t>(tip_height) - 1);

    spkindex.Stop();
}

BOOST_AUTO_TEST_SUITE_END()
