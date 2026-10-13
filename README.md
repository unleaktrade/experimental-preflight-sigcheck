# Solana Off-Chain Signature Verification PoC

This repository contains **exploratory and experimental** material. It may be modified or deleted at any time.

The project demonstrates a **Proof of Concept (PoC)** showing how a Solana program can verify a message that was **hashed and signed off-chain** before instruction execution.  
It serves as a **preflight verification** mechanism to ensure message authenticity prior to on-chain processing.

> **Status: historical.** The pattern proven here now lives in production form in
> [settlement-engine](https://github.com/unleaktrade/settlement-engine) (`commit_quote`) with
> [liquidity-guard](https://github.com/unleaktrade/liquidity-guard) as the off-chain signer. This PoC
> only checks a signature over an arbitrary 32-byte hash against one hardcoded signer; it does not
> implement the UnleakTrade commit-hash pre-image.

## What is in the repo

| Path | What it is |
|---|---|
| `programs/experimental-preflight-sigcheck/` | Anchor program with a single instruction, `verify_signature(message_hash: [u8; 32])` |
| `sigcore/` | Standalone Rust binary (outside the Anchor workspace) that hashes a message with SHA-256, signs the hash with Ed25519 and prints both |
| `tests/experimental-preflight-sigcheck.ts` | Two tests: a valid signature is accepted, a tampered one is rejected |

Program ID: `9regB6ad87mGXsskBEhkP9eXNPR1CGMmkFaGynLr3t8S` (localnet only, see `Anchor.toml`).

## How it works

The client sends two instructions in one transaction: a native **Ed25519 verify** instruction, then `verify_signature`. The runtime checks the signature itself; the program reads the previous instruction through the instructions sysvar and enforces that:

1. the previous instruction targets the native `Ed25519SigVerify111111111111111111111111111` program;
2. it carries exactly one signature;
3. signature, public key and message are all read from that same instruction (the three instruction-index fields equal `0xFFFF`), which prevents cross-instruction substitution;
4. the signed message is exactly 32 bytes;
5. the public key is the hardcoded `AUTHORIZED_SIGNER` (`x4EJH892FzJt7wmLaiD26dh1kkkwqqzggNcKMp2uXJQ`);
6. the signed message equals the `message_hash` argument.

Each check has its own error code (see `ErrorCode` in `programs/experimental-preflight-sigcheck/src/lib.rs`).

## Running it

Requirements: Rust 1.89.0 (`rust-toolchain.toml`), the Solana CLI, Anchor 0.32.1 and yarn.

```bash
yarn install
anchor build
anchor test          # starts a local validator and runs both tests
```

The off-chain signer:

```bash
cd sigcore && cargo run
```

`sigcore` generates a **new random keypair on every run**, so its output does not verify against the hardcoded `AUTHORIZED_SIGNER`. The tests use a fixed hash and signature for the message `mynameisjulien`; to use your own key, replace the constant in the program and the values in the test.

Contact: [julien@unleak.trade](mailto:julien@unleak.trade)
