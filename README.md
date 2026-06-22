# Poseidon2

[![CI](https://img.shields.io/github/actions/workflow/status/libernet-xyz/poseidon2/ci.yml?label=CI)](https://github.com/libernet-xyz/poseidon2/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/starkom-poseidon2)](https://crates.io/crates/starkom-poseidon2)
[![license](https://img.shields.io/crates/l/starkom-poseidon2)](https://github.com/libernet-xyz/poseidon2/blob/main/LICENSE)

## Overview

This is Starkom's implementation of the
[Poseidon2 algebraic hash](https://eprint.iacr.org/2023/323).

The implementation is generic and works on any prime field, but we always allocate exactly 1 state
element for capacity, resulting in 128-bit security.

We also provide configurations for the BLS12-381 and BlueSky prime fields, for T=3 and T=4.

> [!NOTE]
> The BLS12-381 configurations are controlled by the `bls12_381` feature flag, which is disabled by
> default.

## Usage

The following example functions instantiate Poseidon2 with T=3 and T=4 respectively, squeezing a
single element from the output.

```rs
use starkom_bluesky::Scalar;
use starkom_poseidon2;

fn hash_t3(inputs: &[Scalar]) -> Scalar {
    starkom_poseidon2::hash::<starkom_poseidon2::bluesky::BlueSkyConfig3, Scalar, 3>(inputs)[0]
}

fn hash_t4(inputs: &[Scalar]) -> Scalar {
    starkom_poseidon2::hash::<starkom_poseidon2::bluesky::BlueSkyConfig4, Scalar, 4>(inputs)[0]
}
```
