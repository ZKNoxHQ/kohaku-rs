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

Kohaku-rs is a collection of rust crates for working with Ethereum privacy protocols. See [ethereum.github.io/kohaku](https://ethereum.github.io/kohaku/) for more information on the Kohaku project.

> [!IMPORTANT]
> This project is a work in progress and is NOT READY FOR PRODUCTION USE. Packages contain UNAUDITED CODE. Consult underlying package READMEs for more information.

## Overview

- [`kohaku-tornadocash`](./crates/tornadocash/) - [tornadocash](https://tornadocash.eth.limo/) client library.
- [`kohaku-tornadocash-circuit`](./crates/tornadocash-circuit/) - Tornadocash circuit artifacts & proving wrapper.
- [`kohaku-userop-kit`](./crates/userop-kit/) - 4337 user operation builder, signer, and paymaster library.
- [`kohaku-kv-store`](./crates/kv-store/) - Key-value store implementation for kohaku-rs. Used by other kohaku-rs crates for data persistence.
- [`kohaku-merkle-tree`](./crates/merkle-tree/) - Merkle tree implementation backed by `kohaku-kv-store`.
- [`kohaku-fork-kit`](./crates/fork-kit/) - Forking kit for testing and development of kohaku-rs crates.
- [`kohaku-pir-rpc`](./crates/pir-rpc/) - dual-endpoint Ethereum provider: PIR for private account reads, fallback JSON-RPC for everything else.
- [`kohaku-tor-rpc`](./crates/tor-rpc/) - Alloy JSON-RPC over Arti with shared or session-isolated circuits.
- [`kohaku-privacy-rpc`](./crates/privacy-rpc/) - batch-aware Tor + PIR privacy orchestrator (account + ERC-20 token PIR, Multicall3 packing, selective Tor isolation).

### Experiments

Experiments are incomplete and unstable features that are not ready for production use. See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for more information.

- [`kohaku-pir-rpc`](https://github.com/ethereum/kohaku-rs/tree/experiments/pir-v1/crates/pir-rpc) - dual-endpoint Ethereum provider: PIR for private account reads, fallback JSON-RPC for everything else.

## Development

kohaku-rs primarily uses [nix flakes](https://wiki.nixos.org/wiki/Flakes) for development. See the [flake.nix](./flake.nix) file for details on required dependencies. To enter the dev shell, run:

```bash
nix develop --extra-experimental-features "nix-command flakes"
```
