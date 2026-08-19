# Poseidon2

[![CI](https://img.shields.io/github/actions/workflow/status/libernet-xyz/poseidon2/ci.yml?label=CI)](https://github.com/libernet-xyz/poseidon2/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/starkom-poseidon2)](https://crates.io/crates/starkom-poseidon2)
[![license](https://img.shields.io/crates/l/starkom-poseidon2)](https://github.com/libernet-xyz/poseidon2/blob/main/LICENSE)

## Overview

This is Starkom's implementation of the
[Poseidon2 algebraic hash](https://eprint.iacr.org/2023/323).

This crate uses version 2 of the permutation. For version 1 see the
[`starkom-poseidon`](https://crates.io/crates/starkom-poseidon) crate.

The implementation is generic and works on any prime field.

Configurations for the BLS12-381, Goldilocks, and BlueSky prime fields are provided; the BLS12-381
and BlueSky configurations support T=3 and T=4, while the Goldilocks configurations support T=12 and
T=16.

> [!NOTE]
> All predefined configurations are gated behind feature flags to avoid including all constants in
> all builds. The currently defined feature flags are `bls12_381`, `goldilocks`, and `bluesky`, all
> disabled by default.

## Usage

The following example functions instantiate Poseidon2 with T=3 and T=4 respectively, squeezing a
single element from the output. Both use a single element for capacity.

```rs
use starkom_bluesky::Scalar;
use starkom_poseidon2;

fn hash_t3(inputs: impl IntoIterator<Item = Scalar>) -> Scalar {
    starkom_poseidon2::hash::<starkom_poseidon2::bluesky::BlueSkyConfig3, Scalar, 3, 2, 1>(inputs)[0]
}

fn hash_t4(inputs: impl IntoIterator<Item = Scalar>) -> Scalar {
    starkom_poseidon2::hash::<starkom_poseidon2::bluesky::BlueSkyConfig4, Scalar, 4, 3, 1>(inputs)[0]
}
```
