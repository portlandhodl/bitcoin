#!/usr/bin/env python3
# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the spkindex and the getspktxouts RPC."""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)
from test_framework.wallet import (
    MiniWallet,
    getnewdestination,
)


class GetSpkTxOutsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [["-spkindex"], []]

    def run_test(self):
        node, node_noindex = self.nodes
        wallet = MiniWallet(node)

        self.log.info("Check the RPC fails without -spkindex")
        assert_raises_rpc_error(-1, "Requires spkindex", node_noindex.getspktxouts, "51")

        self.log.info("Check invalid hex is rejected")
        assert_raises_rpc_error(-8, "scriptpubkey must be hexadecimal string", node.getspktxouts, "zz")

        self.wait_until(lambda: node.getindexinfo()["spkindex"]["synced"])
        _, spk, _ = getnewdestination()
        assert_equal(node.getspktxouts(spk.hex()), [])

        self.log.info("Check confirmed outputs to a scriptPubKey are returned in height order")
        sent = []
        for amount in [10000, 20000]:
            res = wallet.send_to(from_node=node, scriptPubKey=spk, amount=amount)
            blockhash = self.generate(node, 1, sync_fun=self.no_op)[0]
            sent.append({
                "txid": res["txid"],
                "vout": res["sent_vout"],
                "amount": Decimal(amount) / 100_000_000,
                "height": node.getblockcount(),
                "blockhash": blockhash,
            })
        # Unconfirmed outputs are not indexed
        wallet.send_to(from_node=node, scriptPubKey=spk, amount=30000)
        assert_equal(node.getspktxouts(spk.hex()), sent)

        self.log.info("Check spent outputs are still returned")
        # MiniWallet outputs spent by the txs above are still listed
        wallet_txouts = node.getspktxouts(wallet.get_output_script().hex())
        assert_greater_than(len(wallet_txouts), 0)

        self.log.info("Check the index follows reorgs")
        node.invalidateblock(sent[1]["blockhash"])
        assert_equal(node.getspktxouts(spk.hex()), sent[:1])
        # The index is rewound on disconnect, not only when the next block connects
        assert_equal(node.getindexinfo("spkindex")["spkindex"]["best_block_height"], sent[0]["height"])
        node.reconsiderblock(sent[1]["blockhash"])
        assert_equal(node.getspktxouts(spk.hex()), sent)

        self.log.info("Check the index persists across restarts")
        self.restart_node(0, extra_args=["-spkindex"])
        self.wait_until(lambda: node.getindexinfo()["spkindex"]["synced"])
        assert_equal(node.getspktxouts(spk.hex()), sent)

        self.log.info("Check -spkindex is incompatible with pruning")
        self.stop_node(0)
        node.assert_start_raises_init_error(["-spkindex", "-prune=550"], "Error: Prune mode is incompatible with -spkindex.")


if __name__ == '__main__':
    GetSpkTxOutsTest(__file__).main()
