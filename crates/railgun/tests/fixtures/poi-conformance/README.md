# Offline POI conformance fixtures

These are public synthetic proofs, never funded wallet data. The native test
service verifies Groth16 proofs with arkworks and exposes only a bounded
loopback endpoint. No circuit downloads, RPC credentials or real POI service
are needed; the normal debug test suite runs these checks.

## Source and reproduction

The proof data and current verification keys come from the MIT-licensed
[railgun-rust revision f1810f0](https://github.com/triamazikamno/railgun-rust/tree/f1810f016e0a329a1b2d07da97668049351aa60d).
Its `crates/core/tests/fixtures/ppoi.md` records generation and independent
snarkjs verification. The retained MIT notice is `LICENSE.railgun-rust`.
The retired key comes from its
[b770ba7 revision](https://github.com/triamazikamno/railgun-rust/tree/b770ba7c05a5d33d904f518fd29dd05badd36008).

`generate.py` uses Python's standard library and reads committed bytes with
`git show` from an explicitly supplied checkout. It checks the source revision
and proof hashes, trims snarkjs projective coordinates to kohaku's `Proof` shape,
retains the decimal coordinate/public-signal strings, and adds a synthetic
`txidMerklerootIndex: 0`. It performs no networking or proof generation.

```sh
python3 crates/railgun/tests/fixtures/poi-conformance/generate.py \
  /path/to/pinned/railgun-rust /path/to/disposable/output
diff -r -x README.md -x generate.py \
  crates/railgun/tests/fixtures/poi-conformance /path/to/disposable/output
```

Compare the seven generated data/license files; the output does not include
this README or the generator. All six cryptographic data files are SHA-256
pinned by `retained_keys_and_public_fixtures_are_pinned`.

The current bundle is `QmZ2MyM6TKxffkv6stuo2hFwmUfs3q4xgMYN164Sje8new`,
selected by Railgun wallet 11.2.0. The retired bundle is `poi-nov-2-23`.
The 3x3 key formatting differs from the official CID files but its coefficients
match independently derived current/retired keys. The 13x13 key's provenance is
the pinned railgun-rust source. The fixtures cover 1 input / 1 output (3x3), the
retired version of that shape, and 1 input / 3 private outputs plus an unshield
(13x13). The full fixture's rejection under the mini key establishes the
mathematical boundary; a separate `poi_inputs.rs` test exercises kohaku's
production `circuit_size(1, 4)` selection (three private outputs plus unshield).

## What is exercised

- Current/retired keys accept their own proofs and reject the other generation.
- Submission fields reconstruct the fixture's public signals with the node's
  zero padding and order. Changed roots, commitments, unshield marker,
  malformed curve points and swapped G2 coordinates fail verification.
- The actual `PoiClient` serializes and submits proof data to the local
  verifier. Retired proofs receive HTTP 400 / -32602 `Invalid proof`; current
  proofs get a void success and their synthetic owned status becomes `Valid`.
  These normal-suite proofs are precomputed. Fresh generation is covered only
  by the opt-in native tests described below. Raw JSON shape/encoding assertions run before kohaku's deserializer:
  roots are bare 64-hex, blinded commitments are prefixed 64-hex and proof
  coordinates are decimal strings in 2 / 2x2 / 2 shape. The fixture source
  uses prefixed roots; kohaku normalizes those on serialization. Its full-width
  zero marker also differs from the SDK's `0x00`; the public node
  [tests that marker numerically](https://github.com/Railgun-Community/private-proof-of-innocence/blob/4b1eaf6ef19099dbfd6b43b1ca78d2ce0132a752/packages/node/src/list-provider/list-provider-poi-event-queue.ts#L176).
  This is not a deployed-node schema or forwarding acceptance test.
  Bare-root encoding is kohaku's current format; deployed acceptance is not
  established by this loopback fixture.
- A POST accepted before its reply is dropped is reconciled by a status read
  with a recreated client, without another POST. This is a test procedure,
  not a new production retry or recovery API. Today's `submit_pending` retains
  failed submissions and can re-prove and POST again on later processing.
  The fixture's immediate `Valid` is synthetic; a real service may report
  `ProofSubmitted` while aggregation is pending.
- The actual TXID indexer retains its persisted checkpoint/tree on a root-read
  outage, then restores from a closed/reopened redb store and resumes without
  losing positions or duplicating leaves.
- Dropping a sync future while acquisition is pending leaves the persisted
  checkpoint intact; a reopened indexer can complete the same range.

## Limits

The service's list, root acceptance and status transitions are synthetic. It
does not authenticate list signatures, index-root membership, finality,
ownership, or the relation between fixture roots and a live chain. It verifies
retained public proofs in the normal suite; the opt-in tests below additionally
exercise `Groth16Prover`. Disk reopen
is within one test process, and cancellation is before writes, not SIGKILL or
an interrupted multi-key commit. Scratch redb files contain public data and
are deliberately retained. The suite grants no durable send/retry authority
and is not an Alice-to-Bob or mainnet qualification.

Run from `crates/`:

```sh
NO_PROXY=localhost,127.0.0.1 cargo test --locked -p kohaku-railgun --lib conformance_tests
```

## Fresh native proof generation (opt-in)

`poi::provider::fresh_proof_tests` exercises the production
`PoiProvider::create_proof` path: local list membership, `PoiCircuitInputs`,
Wasmer witness calculation, `Groth16Prover`, and `TransactProofData` construction.
It builds two fresh 3x3 proofs, one for a foreign private output and one for a
private output plus unshield. Both POI and TXID membership paths have nonzero
indices. Keys, notes, roots and the unshield address are public dummy values.

The separate fixture verifier reconstructs public inputs from the resulting
payload and uses the independently pinned current key, not the key returned
by the artifact loader. This fixture key is byte-identical to the pinned
artifact release's `vkey.json`; its coefficients were also checked against
the separately derived official key recorded in the fixture provenance.
Both proofs must verify with that key and fail with
the retired key. Changing a public root must fail locally and receive
`Invalid proof` through the real `PoiClient`; the original must pass the same
loopback POST. The production provider is not connected to a real POI service.

Provision only these three compressed files from the immutable commit used
by the production loader, **before** running the test:

```sh
mkdir -p /absolute/provisioned/03x03
base=https://raw.githubusercontent.com/kassandraoftroy/kohaku-artifacts/98e6a5255ae4a12bcc1fdaa8ba3bfcf2e805166d/artifacts/railgun/poi/03x03
for file in proving_key.bin.br matrices.bin.br wasm.br; do
  curl --fail --location "$base/$file" --output "/absolute/provisioned/03x03/$file"
done
cd crates
NO_PROXY=localhost,127.0.0.1 \
KOHAKU_POI_3X3_ARTIFACTS=/absolute/provisioned/03x03 \
cargo test --locked --release -p kohaku-railgun --lib fresh_native_poi -- --ignored
```

The test authenticates all three SHA-256 digests against the pinned artifact
[provenance](https://github.com/kassandraoftroy/kohaku-artifacts/blob/98e6a5255ae4a12bcc1fdaa8ba3bfcf2e805166d/artifacts/railgun/poi/PROVENANCE.md)
before opening its loopback artifact server. Missing or changed files refuse;
there is no download fallback. The server permits exactly the three expected
paths and records their order. The test-only prover constructor supplies that
endpoint without adding a runtime configuration API or changing the default
loader. Artifact bytes and generated proofs are not committed. Normal tests
remain free of artifact provisioning and expensive proving.

This establishes fresh 3x3 proving and wire compatibility with a local
cryptographic verifier. It does not establish fresh 13x13 generation, a
transaction proof, pending-entry construction/recovery, authentic list signatures
or root acceptance, encrypted
wallet storage, a deployed service's acceptance, or an Alice-to-Bob lifecycle.
