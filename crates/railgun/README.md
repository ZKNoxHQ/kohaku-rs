# kohaku-railgun

Rust Railgun client library for Railgun's on-chain and off-chain components. It provides support for:

- UTXO and TXID syncing
- State querying
- Transaction construction
- Proof generation
- POI proof generation
- POI proof submission
- Transaction submission via broadcasters

## Examples

See the [integration tests](./tests/integration/).

## Controlling POI proof submission

With POI enabled, `sync()` and `sync_to()` retain the automatic workflow:
synchronize state, then generate and submit pending POI proofs. A wallet that
needs a separate disclosure decision can call `sync_without_poi_submission()`
or `sync_to_without_poi_submission(block)`, then explicitly call
`process_pending_poi()` when appropriate.

The submission-free sync still queries the indexer, roots and owned POI status;
it is not a no-disclosure scan. Explicit processing handles the entire pending
queue with the existing best-effort behavior: individual failures are logged
and retained. `Ok` does not establish acceptance, and a response failure does
not establish that nothing was submitted. Observe owned POI status separately
before spending. Dropping processing mid-POST leaves an unknown outcome;
cancelling after delivery but before the final save can leave persisted work
that is processed again after reopening. These methods do not add per-proof review or a durable
submission-attempt journal.

`notes()`, `balance()` and transaction construction also query owned POI status
when POI is enabled. The submission-free methods do not gate those reads.

The loopback control test uses only public dummy state. When running behind a
system HTTP proxy, include `127.0.0.1,localhost` in `NO_PROXY` so the fixture
traffic stays local.
