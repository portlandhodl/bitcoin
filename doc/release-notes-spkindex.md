New settings
------------

- `-spkindex` enables a new index of all confirmed transaction outputs keyed by
  scriptPubKey, similar to the "funding" rows kept by electrs. It is incompatible
  with pruning.

New RPCs
--------

- `getspktxouts "scriptpubkey"` returns every confirmed output paying to the
  given hex scriptPubKey (txid, vout, amount, height, blockhash), ordered by
  block height. Spent outputs are included. Requires `-spkindex`.
