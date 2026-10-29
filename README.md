# kohaku-rs

<p align="center">
<a href="https://ethereum.github.io/kohaku/">
<picture>
<source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/ethereum/kohaku/refs/heads/master/docs/public/kohaku_logo.svg">
<img alt="Kohaku logo" src="https://raw.githubusercontent.com/ethereum/kohaku/refs/heads/master/docs/public/kohaku_logo.svg" width="auto" height="60">
</picture>
</a>
</p>

Rusty privacy-first tooling for the Ethereum ecosystem.

Kohaku-rs is a collection of rust crates for working with Ethereum privacy protocols. See the [js kohaku repo](https://github.com/ethereum/kohaku) for more information.

> [!IMPORTANT]
> This project is a work in progress and is NOT READY FOR PRODUCTION USE. Packages contain UNAUDITED CODE. Consult underlying package READMEs for more information.

## Overview

- [`kohaku-tornadocash`](./crates/tornadocash/) - [tornadocash](https://tornadocash.eth.limo/) client library.
- [`kohaku-tornadocash-circuit`](./crates/tornadocash-circuit/) - Tornadocash circuit artifacts & proving wrapper.
- [`kohaku-tornadocash-keyring`](./crates/tornadocash-keyring/) - Deterministic note derivation & keyring management for tornadocash.
- [`kohaku-tornadocash-wasm`](./crates/tornadocash-wasm/) - Typescript WASM bindings for kohaku-tornadocash.
- [`kohaku-userop-kit`](./crates/userop-kit/) - 4337 user operation builder, signer, and paymaster library.
- [`kohaku-merkle-tree`](./crates/merkle-tree/) - Generic merkle tree implementation.
- [`kohaku-fork-kit`](./crates/fork-kit/) - Forking kit for testing and development of kohaku-rs crates.
- [`kohaku-tor-rpc`](./crates/tor-rpc/) - Alloy JSON-RPC over Arti, with shared or session-isolated circuits.
- [`kohaku-railgun`](./crates/railgun/) - [Railgun](https://railgun.org/) shielded pool client library.
- [`kohaku-crypto`](./crates/crypto/) - Shared crypto primitives (Poseidon, BabyJubJub, merkle helpers).
- [`poseidon-rust`](./crates/poseidon-rust/) - Circom-compatible Poseidon hash (vendored).

### Experiments

Experiments are incomplete and unstable features that are not ready for production use. See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for more information.

- [`kohaku-privacy-rpc`](https://github.com/ethereum/kohaku-rs/tree/experiments/pir-v1/crates/privacy-rpc) -  dual-endpoint Ethereum provider: PIR for private account reads, fallback JSON-RPC for everything else. Can also enable Tor for network level anonymity.

## Development

kohaku-rs primarily uses [nix flakes](https://wiki.nixos.org/wiki/Flakes) for development. See the [flake.nix](./flake.nix) file for details on required dependencies. To enter the dev shell, run:

```bash
nix develop --extra-experimental-features "nix-command flakes"
```
