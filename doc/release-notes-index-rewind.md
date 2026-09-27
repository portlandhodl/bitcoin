Updated RPCs
------------

- Optional indexes (`-txindex`, `-txospenderindex`, `-coinstatsindex`,
  `-blockfilterindex`) are now rewound as soon as a block is
  disconnected, instead of when the next block is connected. In particular,
  `gettxspendingprevout` no longer reports spends from a block that was
  disconnected (e.g. via `invalidateblock`) while no replacement block has
  been connected yet.
