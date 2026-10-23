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

## POI availability

With POI enabled, status comes from a local copy of each POI list. Sync copies
leaves by index range, so a read does not name the wallet's commitments.
`Unavailable` means that copy is not caught up: it was never synced, or the last
sync did not reach the end of the list. It is a local observation state, not a
POI node status, and never means `Missing`. Only a sync that reached the zero
leaf can establish `Missing` for a commitment that is absent. A commitment
already in the tree is `Valid` even before the tail is confirmed. Only `Valid`
notes are selected for spending. If the valid set is insufficient and the
requested account/asset has unavailable notes, build returns
`RailgunProviderError::PoiStatusUnavailable` before proving. An unrelated
account/asset does not replace a genuine insufficient-balance error, and
sufficient `Valid` notes remain usable. `None` means POI is disabled. Callers
should display `Unavailable` as unknown and must not use it to authorize proof
resubmission. A blocked shield is not queried on its own; once the list is
caught up it is `Missing`.

A copied page becomes visible only after root validation and its batch save
complete. Cancelling sync during either step preserves the published in-memory
prefix. If a backend committed before its save acknowledgement was lost, a
reopen may load that validated page; the existing instance can safely reacquire
and replay it. This does not add stronger atomicity or crash guarantees to the
selected storage backend.

## Controlling POI proof submission

With POI enabled, `sync()` and `sync_to()` retain the automatic workflow:
synchronize state, then generate and submit pending POI proofs. A wallet that
needs a separate disclosure decision can call `sync_without_poi_submission()`
or `sync_to_without_poi_submission(block)`, then explicitly call
`process_pending_poi()` when appropriate.

The submission-free sync still copies POI lists and checks txid roots. List
reads name leaf ranges, not owned commitments. It is not a no-disclosure scan
of the chain indexer. Explicit processing handles the entire pending queue with
the existing best-effort behavior: individual failures are logged and retained.
`Ok` does not establish acceptance, and a response failure does not establish
that nothing was submitted. Observe the local list copy separately before
spending. Dropping processing mid-POST leaves an unknown outcome; cancelling
after delivery but before the final save can leave persisted work that is
processed again after reopening. These methods do not add per-proof review or a
durable submission-attempt journal.

`notes()`, `balance()` and transaction construction read that local copy when
POI is enabled. They do not query the node. Until a sync has caught the list
up, a commitment that is not already in the tree is `Unavailable`.

The loopback control test uses only public dummy state. When running behind a
system HTTP proxy, include `127.0.0.1,localhost` in `NO_PROXY` so the fixture
traffic stays local.
