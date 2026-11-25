# Quantum-proof-bitcoin

A quantum-resistant fork of Bitcoin. This is early development work: there is
no coin, no network and no launch date yet.

This project is not Bitcoin and is not affiliated with the Bitcoin Core
project. It will get its own name before any launch.

## Design goals

- **Continue Bitcoin's ledger.** At a chosen block height the chain splits from
  Bitcoin. Every balance that exists on Bitcoin at that block exists on this
  chain too, controlled by the same keys.
- **Keep Bitcoin's money rules.** The 21 million cap, the halving schedule and
  proof-of-work mining stay as they are.
- **Make ownership quantum-resistant.** Coins can be moved to a new output type
  secured by SLH-DSA (NIST FIPS 205), a hash-based signature scheme, instead of
  the elliptic-curve signatures that a large quantum computer could break.
- **Launch in the open.** The code, the split height and the launch date are
  published in advance. There is no premine, no presale and no hidden
  allocation.

## What "quantum-resistant" means here

Hash-based signatures rest on one assumption: that the hash function (SHA-256)
stays hard to invert. Bitcoin's mining and block chain already depend on that
assumption, so this fork does not add a new one.

It does not mean any of the following:

- **It is not secure if P = NP.** A fast solver for NP problems would break
  signatures, hashes and proof of work in every system that works like Bitcoin,
  including this one.
- **Old coins are not protected automatically.** A coin stays under its
  original Bitcoin key, and stays exposed to a quantum attacker, until its
  owner moves it to a quantum-resistant output.
- **The code has not been audited.** Nothing here should be used to hold real
  value yet.

## Status

Working so far, on a private test network (regtest) only:

- SLH-DSA-SHA2-128s signatures, checked against NIST's official test vectors.
- A quantum-resistant output type: Pay-to-Merkle-Root outputs (BIP 360) whose
  scripts accept SLH-DSA public keys. The rules are specified in
  [doc/quantum-resistant-outputs.md](doc/quantum-resistant-outputs.md).

Not done yet:

- Wallet support for creating quantum-resistant addresses and signing for them.
- The split from Bitcoin: the split height, protection against replaying
  transactions between the two chains, difficulty adjustment after the split,
  and the network's own name and identifiers.
- Rules for coins that are never moved to a quantum-resistant output.

Until the split is implemented, a node built from this code follows Bitcoin's
rules on Bitcoin's networks.

## Based on Bitcoin Core

The code is a fork of [Bitcoin Core](https://github.com/bitcoin/bitcoin)
release v32.1, with its full history. Build instructions are in the `doc`
folder (`doc/build-unix.md`, `doc/build-osx.md`, `doc/build-windows.md`).

## Licence

MIT, the same as Bitcoin Core. See [COPYING](COPYING).
