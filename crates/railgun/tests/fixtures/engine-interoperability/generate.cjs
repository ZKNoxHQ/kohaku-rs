"use strict";

// Offline development helper. Only the well-known public test mnemonic below is used.
// Expected values come from the published engine, never from kohaku-railgun.
const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const { readFileSync } = require("node:fs");
const { resolve, join } = require("node:path");

const engine = resolve(process.argv[2] || "");
assert(process.argv[2], "Pass the installed @railgun-community/engine package directory");
assert.equal(JSON.parse(readFileSync(join(engine, "package.json"))).version, "9.6.0");

// An accidental network request must fail rather than turn fixture generation into a scan.
const denyNetwork = () => { throw new Error("Fixture generation is offline"); };
globalThis.fetch = denyNetwork;
for (const name of ["node:http", "node:https"]) {
  const transport = require(name);
  transport.request = denyNetwork;
  transport.get = denyNetwork;
}
require("node:net").connect = denyNetwork;
require("node:net").createConnection = denyNetwork;

const sources = [
  "dist/key-derivation/wallet-node.js",
  "dist/key-derivation/bech32.js",
  "dist/utils/keys-utils.js",
  "dist/transaction/railgun-txid.js",
];
const [{ deriveNodes, WalletNode }, { encodeAddress, decodeAddress }, keys, txid] =
  sources.map((name) => require(join(engine, name)));

const mnemonic = "test test test test test test test test test test test junk";
const field = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const hex32 = (value) => value.toString(16).padStart(64, "0");

async function main() {
  const accounts = [];
  for (const index of [0, 1, 65535]) {
    const nodes = deriveNodes(mnemonic, index);
    const spending = nodes.spending.getSpendingKeyPair();
    const viewing = await nodes.viewing.getViewingKeyPair();
    const master = WalletNode.getMasterPublicKey(spending.pubkey, await nodes.viewing.getNullifyingKey());
    const addressKeys = { masterPublicKey: master, viewingPublicKey: viewing.pubkey };
    const addresses = [undefined, { type: 0, id: 1 }, { type: 0, id: 11155111 }].map((chain) => {
      const address = encodeAddress({ ...addressKeys, chain });
      assert.equal(decodeAddress(address).masterPublicKey, master);
      return { chain_id: chain?.id ?? null, address };
    });
    const signatures = [0n, 1n, 42n, (1n << 64n) + 1n, field - 1n].map((message) => {
      const signature = keys.signEDDSA(spending.privateKey, message);
      assert(keys.verifyEDDSA(message, signature, spending.pubkey));
      assert(!keys.verifyEDDSA((message + 1n) % field, signature, spending.pubkey));
      return { message: message.toString(), r8_x: signature.R8[0].toString(), r8_y: signature.R8[1].toString(), s: signature.S.toString() };
    });
    accounts.push({
      index,
      spending_key: Buffer.from(spending.privateKey).toString("hex"),
      viewing_key: Buffer.from(viewing.privateKey).toString("hex"),
      spending_public_key: spending.pubkey.map(String),
      viewing_public_key: Buffer.from(viewing.pubkey).toString("hex"),
      master_public_key: hex32(master),
      addresses,
      signatures,
    });
  }
  const operations = [
    { name: "one-input-one-output", nullifiers: [1n], commitments: [2n], bound_params_hash: 3n },
    { name: "one-input-two-outputs", nullifiers: [42n], commitments: [5n, 6n], bound_params_hash: 7n },
    { name: "ordered-two-inputs-three-outputs", nullifiers: [8n, 9n], commitments: [10n, 11n, 12n], bound_params_hash: 13n },
    { name: "thirteen-inputs-and-outputs", nullifiers: Array.from({ length: 13 }, (_, i) => BigInt(i + 1)), commitments: Array.from({ length: 13 }, (_, i) => field - BigInt(i + 1)), bound_params_hash: field - 1n },
  ].map((op) => ({
    name: op.name,
    nullifiers: op.nullifiers.map(String),
    commitments: op.commitments.map(String),
    bound_params_hash: op.bound_params_hash.toString(),
    txid: "0x" + hex32(txid.getRailgunTransactionIDFromBigInts(op.nullifiers, op.commitments, op.bound_params_hash)),
  }));
  const fixture = {
    warning: "Public test mnemonic and keys. Never fund these accounts. No wallet or service is opened.",
    source: {
      package: "@railgun-community/engine",
      version: "9.6.0",
      commit: "6e2614d53a106dd62abad91e7ce03ee4a3956138",
      files: Object.fromEntries(sources.map((name) => [name, createHash("sha256").update(readFileSync(join(engine, name))).digest("hex")])),
    },
    mnemonic,
    accounts,
    operations,
  };
  process.stdout.write(JSON.stringify(fixture, null, 2) + "\n");
}

main().catch((error) => { process.stderr.write(error.stack + "\n"); process.exitCode = 1; });
