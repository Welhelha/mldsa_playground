# ML-DSA Playground

A small Rust project for testing and exploring **ML-DSA** integration in a targeted fork of `askar-crypto`. The integration tests cover ML-DSA-44, ML-DSA-65, and ML-DSA-87, including key generation and import, signatures, JWK conversion, thumbprints, key and signature sizes, and error cases.

> This is an experimental project for testing the integration; it is not, by itself, a recommendation for production use.

## Requirements

- Rust and Cargo
- Node.js and npm
- Access to the Git repository used as a dependency in `Cargo.toml`

## Tests

Run the full test suite:

```sh
cargo test
```

The ML-DSA integration test is enabled by default through the `mldsa` feature. To run it explicitly:

```sh
cargo test --features mldsa --test mldsa
```

To cross-check seed-derived public keys and signatures against `@noble/post-quantum` for ML-DSA-44, ML-DSA-65, and ML-DSA-87:

```sh
npm install
npm run test:noble
```

The cross-check verifies public-key byte equality and signature verification in both directions; it does not require Rust and noble signatures to be byte-identical because Rust uses hedged signing.

## Project structure

- `Cargo.toml`: `askar-crypto` dependency and ML-DSA feature configuration.
- `tests/mldsa.rs`: integration tests covering all three ML-DSA variants.
