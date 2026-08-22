use crate::params::decode_constants;
use crate::poseidon;
use starkom_ff::Field;
use starkom_goldilocks::GL as Scalar;
use std::sync::LazyLock;

/// Poseidon2 configuration for the Goldilocks field.
pub struct GoldilocksConfig<const T: usize> {}

impl poseidon::Config<Scalar, 12> for GoldilocksConfig<12> {
    fn num_full_rounds() -> usize {
        4
    }

    fn num_partial_rounds() -> usize {
        22
    }

    fn sbox(x: Scalar) -> Scalar {
        x.cube().square() * x
    }

    fn get_round_constants() -> &'static [Scalar] {
        static ROUND_CONSTANTS: LazyLock<[Scalar; 360]> = LazyLock::new(|| {
            let bytes = include_bytes!("../params/goldilocks/arc_t12.bin");
            decode_constants::<Scalar, 360>(bytes)
        });
        &*ROUND_CONSTANTS
    }

    fn get_external_matrix() -> &'static [Scalar] {
        static MATRIX: LazyLock<[Scalar; 144]> = LazyLock::new(|| {
            let bytes = include_bytes!("../params/goldilocks/fl_t12.bin");
            decode_constants::<Scalar, 144>(bytes)
        });
        &*MATRIX
    }

    fn get_internal_matrix() -> &'static [Scalar] {
        static MATRIX: LazyLock<[Scalar; 144]> = LazyLock::new(|| {
            let bytes = include_bytes!("../params/goldilocks/pl_t12.bin");
            decode_constants::<Scalar, 144>(bytes)
        });
        &*MATRIX
    }
}

impl poseidon::Config<Scalar, 16> for GoldilocksConfig<16> {
    fn num_full_rounds() -> usize {
        4
    }

    fn num_partial_rounds() -> usize {
        22
    }

    fn sbox(x: Scalar) -> Scalar {
        x.cube().square() * x
    }

    fn get_round_constants() -> &'static [Scalar] {
        static ROUND_CONSTANTS: LazyLock<[Scalar; 480]> = LazyLock::new(|| {
            let bytes = include_bytes!("../params/goldilocks/arc_t16.bin");
            decode_constants::<Scalar, 480>(bytes)
        });
        &*ROUND_CONSTANTS
    }

    fn get_external_matrix() -> &'static [Scalar] {
        static MATRIX: LazyLock<[Scalar; 256]> = LazyLock::new(|| {
            let bytes = include_bytes!("../params/goldilocks/fl_t16.bin");
            decode_constants::<Scalar, 256>(bytes)
        });
        &*MATRIX
    }

    fn get_internal_matrix() -> &'static [Scalar] {
        static MATRIX: LazyLock<[Scalar; 256]> = LazyLock::new(|| {
            let bytes = include_bytes!("../params/goldilocks/pl_t16.bin");
            decode_constants::<Scalar, 256>(bytes)
        });
        &*MATRIX
    }
}

/// Poseidon2 configuration for Goldilocks with T=12.
pub type GoldilocksConfig12 = GoldilocksConfig<12>;

/// Poseidon2 configuration for Goldilocks with T=16.
pub type GoldilocksConfig16 = GoldilocksConfig<16>;

#[cfg(test)]
mod tests {
    use super::*;
    use starkom_goldilocks::from_const;

    fn hash_t12(inputs: impl IntoIterator<Item = Scalar>) -> [Scalar; 8] {
        poseidon::hash::<GoldilocksConfig12, Scalar, 12, 8, 4>(inputs)
    }

    fn hash_t12_0(inputs: impl IntoIterator<Item = Scalar>) -> Scalar {
        poseidon::hash0::<GoldilocksConfig12, Scalar, 12, 8, 4>(inputs)
    }

    fn hash_t16(inputs: impl IntoIterator<Item = Scalar>) -> [Scalar; 12] {
        poseidon::hash::<GoldilocksConfig16, Scalar, 16, 12, 4>(inputs)
    }

    fn hash_t16_0(inputs: impl IntoIterator<Item = Scalar>) -> Scalar {
        poseidon::hash0::<GoldilocksConfig16, Scalar, 16, 12, 4>(inputs)
    }

    fn parse_scalar(s: &'static str) -> Scalar {
        s.parse().unwrap()
    }

    fn range(n: u64) -> Vec<Scalar> {
        (0..n).map(from_const).collect()
    }

    #[test]
    fn test_permutation_t12() {
        assert_eq!(
            poseidon::permutation::<GoldilocksConfig12, Scalar, 12>(range(12).try_into().unwrap()),
            [
                parse_scalar("0x01eaef96bdf1c0c1"),
                parse_scalar("0x1f0d2cc525b2540c"),
                parse_scalar("0x6282c1dfe1e0358d"),
                parse_scalar("0xe780d721f698e1e6"),
                parse_scalar("0x280c0b6f753d833b"),
                parse_scalar("0x1b942dd5023156ab"),
                parse_scalar("0x43f0df3fcccb8398"),
                parse_scalar("0xe8e8190585489025"),
                parse_scalar("0x56bdbf72f77ada22"),
                parse_scalar("0x7911c32bf9dcd705"),
                parse_scalar("0xec467926508fbe67"),
                parse_scalar("0x6a50450ddf85a6ed"),
            ]
        );
    }

    #[test]
    fn test_permutation_t16() {
        assert_eq!(
            poseidon::permutation::<GoldilocksConfig16, Scalar, 16>(range(16).try_into().unwrap()),
            [
                parse_scalar("0x85c54702470d9756"),
                parse_scalar("0xaa53c7a7d52d9898"),
                parse_scalar("0x285128096efb0dd7"),
                parse_scalar("0xf3fde5edd3050ac8"),
                parse_scalar("0xc7b65efd040df908"),
                parse_scalar("0x4be3f6c467f57ae9"),
                parse_scalar("0x274e9a67b41754fb"),
                parse_scalar("0x0f7d39cd5de94dac"),
                parse_scalar("0xd0224b9794d0b78c"),
                parse_scalar("0x372f6139570042e1"),
                parse_scalar("0xce6e8a93dc4ec26c"),
                parse_scalar("0xace65e30a4daf7af"),
                parse_scalar("0x016f2824cc1ba3db"),
                parse_scalar("0x2e8f3af37c434dec"),
                parse_scalar("0xc80831bb6e09da01"),
                parse_scalar("0x3a7d670bf1a86ee8"),
            ]
        );
    }

    #[test]
    fn test_hash_t12_1() {
        assert_eq!(
            hash_t12(range(1)),
            [
                parse_scalar("0xef311849263abcb4"),
                parse_scalar("0x8bf04d36f9a01799"),
                parse_scalar("0x9e570c4df0f2699f"),
                parse_scalar("0x6927c3a96db0b2ad"),
                parse_scalar("0x760d22fbb5fc5de0"),
                parse_scalar("0xafd1fedcdef654f4"),
                parse_scalar("0xbb8c81621d5d5aed"),
                parse_scalar("0x298915feb162422c"),
            ]
        );
        assert_eq!(hash_t12_0(range(1)), parse_scalar("0xef311849263abcb4"));
    }

    #[test]
    fn test_hash_t12_2() {
        assert_eq!(
            hash_t12(range(2)),
            [
                parse_scalar("0x868352e949a41bce"),
                parse_scalar("0x09bc14bd401a370a"),
                parse_scalar("0x95d895ea09268383"),
                parse_scalar("0x813447f570e8c33f"),
                parse_scalar("0x4b8570484aa9eeae"),
                parse_scalar("0x52e1842ee5595711"),
                parse_scalar("0xc5b1f55643b615a8"),
                parse_scalar("0x64bc5f3129a38bc0"),
            ]
        );
        assert_eq!(hash_t12_0(range(2)), parse_scalar("0x868352e949a41bce"));
    }

    #[test]
    fn test_hash_t12_8() {
        assert_eq!(
            hash_t12(range(8)),
            [
                parse_scalar("0xfd2ed0da41a63e0b"),
                parse_scalar("0x94252156cb2374ba"),
                parse_scalar("0xc5585182a3092abf"),
                parse_scalar("0x653c8aaa741bf05b"),
                parse_scalar("0x9ab1dd68e3dd2ab0"),
                parse_scalar("0xbd3bd7b198977827"),
                parse_scalar("0x63b408e2eb16e145"),
                parse_scalar("0xce70ffe4e269654a"),
            ]
        );
        assert_eq!(hash_t12_0(range(8)), parse_scalar("0xfd2ed0da41a63e0b"));
    }

    #[test]
    fn test_hash_t12_9() {
        assert_eq!(
            hash_t12(range(9)),
            [
                parse_scalar("0x79528f6968b8fc8e"),
                parse_scalar("0xa9b0059cfeb3fdc1"),
                parse_scalar("0xf9d474a3916eb700"),
                parse_scalar("0xda90951bf86349e3"),
                parse_scalar("0xb1b0995f9b02dfeb"),
                parse_scalar("0x6b340b48657922c1"),
                parse_scalar("0x09678d12d7f7d633"),
                parse_scalar("0x3145c3da2f367338"),
            ]
        );
        assert_eq!(hash_t12_0(range(9)), parse_scalar("0x79528f6968b8fc8e"));
    }

    #[test]
    fn test_hash_t12_11() {
        assert_eq!(
            hash_t12(range(11)),
            [
                parse_scalar("0x43d0036caf8454a1"),
                parse_scalar("0xa2bcbd4ed5a14100"),
                parse_scalar("0xc33aad6222932517"),
                parse_scalar("0x5d80fcd5fecd0fff"),
                parse_scalar("0xc2d23dba4ff23013"),
                parse_scalar("0x99d084657f2b29ac"),
                parse_scalar("0x8f5ead63db53853e"),
                parse_scalar("0x4fdb7d5ca4f1da21"),
            ]
        );
        assert_eq!(hash_t12_0(range(11)), parse_scalar("0x43d0036caf8454a1"));
    }

    #[test]
    fn test_hash_t12_12() {
        assert_eq!(
            hash_t12(range(12)),
            [
                parse_scalar("0x2f038ce6adcd4ff9"),
                parse_scalar("0x9ff2232c123e6b81"),
                parse_scalar("0xa1d3b8af23e412d2"),
                parse_scalar("0x12e26c6feee38c37"),
                parse_scalar("0x4d09e9c136f6a9ba"),
                parse_scalar("0xd352b7dcb8c7938d"),
                parse_scalar("0xcba921b2ad73a196"),
                parse_scalar("0x92b6d7029dc57e29"),
            ]
        );
        assert_eq!(hash_t12_0(range(12)), parse_scalar("0x2f038ce6adcd4ff9"));
    }

    #[test]
    fn test_hash_t12_13() {
        assert_eq!(
            hash_t12(range(13)),
            [
                parse_scalar("0x5735a7e6ab16f177"),
                parse_scalar("0xec6edec1bbe88257"),
                parse_scalar("0x24c78f7980b765fa"),
                parse_scalar("0x701a85024e1820c1"),
                parse_scalar("0x1fcce822178839ba"),
                parse_scalar("0x88b02af516657820"),
                parse_scalar("0x7abe4fa3b862db08"),
                parse_scalar("0xf8295c4e6eb96919"),
            ]
        );
        assert_eq!(hash_t12_0(range(13)), parse_scalar("0x5735a7e6ab16f177"));
    }

    #[test]
    fn test_hash_t16_1() {
        assert_eq!(
            hash_t16(range(1)),
            [
                parse_scalar("0xf2b2442ea4d72b98"),
                parse_scalar("0x08367625af002a12"),
                parse_scalar("0x41d794a3d56b9451"),
                parse_scalar("0x533967a2f0a214c8"),
                parse_scalar("0x9b10cb9aecef64c2"),
                parse_scalar("0x3af18efb76e71cc4"),
                parse_scalar("0x20d42b106f3cd4d6"),
                parse_scalar("0x537149275a93e1b9"),
                parse_scalar("0xe48c755b2541ac33"),
                parse_scalar("0xd88485c5e6be8ad5"),
                parse_scalar("0xf864699c52b2d651"),
                parse_scalar("0x3bb13e057d4f33c6"),
            ]
        );
        assert_eq!(hash_t16_0(range(1)), parse_scalar("0xf2b2442ea4d72b98"));
    }

    #[test]
    fn test_hash_t16_2() {
        assert_eq!(
            hash_t16(range(2)),
            [
                parse_scalar("0xc15fbf2803ac65dd"),
                parse_scalar("0x08074b5aebc022de"),
                parse_scalar("0xea229fdd8a70c2d6"),
                parse_scalar("0x07b7e9ee134e5a87"),
                parse_scalar("0x2e78869e72d189a4"),
                parse_scalar("0xce7ad0cb08fe6d75"),
                parse_scalar("0x193513be5e03294f"),
                parse_scalar("0xb4d66fa29d946e1a"),
                parse_scalar("0x9c1ea0488a8a7e0f"),
                parse_scalar("0x15944a5b7d1bfb16"),
                parse_scalar("0xa971b2c914158460"),
                parse_scalar("0x1abcdd88deac4f10"),
            ]
        );
        assert_eq!(hash_t16_0(range(2)), parse_scalar("0xc15fbf2803ac65dd"));
    }

    #[test]
    fn test_hash_t16_12() {
        assert_eq!(
            hash_t16(range(12)),
            [
                parse_scalar("0xd66460d8c09a912b"),
                parse_scalar("0xbdcd36a3acf806d2"),
                parse_scalar("0x5113907be722f501"),
                parse_scalar("0x4ca4eee19c3c5a2d"),
                parse_scalar("0x54915e981eb28092"),
                parse_scalar("0x73e8488fdea9ae75"),
                parse_scalar("0xed5b7865c043656b"),
                parse_scalar("0xb82ca7c9c07f0f0b"),
                parse_scalar("0xe4a0823061e92dbc"),
                parse_scalar("0x92a7cf669d5d9f94"),
                parse_scalar("0xf87ef9aa4d027c1e"),
                parse_scalar("0x70648b9fd05bb1cd"),
            ]
        );
        assert_eq!(hash_t16_0(range(12)), parse_scalar("0xd66460d8c09a912b"));
    }

    #[test]
    fn test_hash_t16_13() {
        assert_eq!(
            hash_t16(range(13)),
            [
                parse_scalar("0x0ccae528199e8a7f"),
                parse_scalar("0x4c0d4be6ed277199"),
                parse_scalar("0xf04b738ac688ff1f"),
                parse_scalar("0x67ba4d00d2ab90b6"),
                parse_scalar("0xddb8a9ae2c73281b"),
                parse_scalar("0xc5c9ce6ef34c1603"),
                parse_scalar("0x0607560bacd79d1f"),
                parse_scalar("0xc5ce28cb8f7f5d34"),
                parse_scalar("0x182b9e762c1c0b0d"),
                parse_scalar("0xb5d1fd5916ab218a"),
                parse_scalar("0xcc283ae14bb815e9"),
                parse_scalar("0x66bb49824442c8b3"),
            ]
        );
        assert_eq!(hash_t16_0(range(13)), parse_scalar("0x0ccae528199e8a7f"));
    }

    #[test]
    fn test_hash_t16_15() {
        assert_eq!(
            hash_t16(range(15)),
            [
                parse_scalar("0x8c1d1af9b63b88ae"),
                parse_scalar("0x2c91cc531b87b1f3"),
                parse_scalar("0xe3ded808778829df"),
                parse_scalar("0xfcbe93b8763943d7"),
                parse_scalar("0x97ef96f852742b11"),
                parse_scalar("0x53c86d06e2914d05"),
                parse_scalar("0xa9b2fd18064fceae"),
                parse_scalar("0xb7ac2caf89f3d14b"),
                parse_scalar("0x4acc25fc21ad1322"),
                parse_scalar("0xb7f73c50198965cb"),
                parse_scalar("0xa464b48a8629eb91"),
                parse_scalar("0x262ecbfa9807635d"),
            ]
        );
        assert_eq!(hash_t16_0(range(15)), parse_scalar("0x8c1d1af9b63b88ae"));
    }

    #[test]
    fn test_hash_t16_16() {
        assert_eq!(
            hash_t16(range(16)),
            [
                parse_scalar("0xdc1ab6ca78e2737d"),
                parse_scalar("0xc4aebc20584b7492"),
                parse_scalar("0x9bf1cb58e29b0e04"),
                parse_scalar("0xbb6518684cde640e"),
                parse_scalar("0x1588e01ab26aae7f"),
                parse_scalar("0xd8fdd105f80299cc"),
                parse_scalar("0xc092c03409d99d66"),
                parse_scalar("0x6ce884c450a6c8c6"),
                parse_scalar("0x0c9cdb0f9c563b18"),
                parse_scalar("0xe5c47af9667fda3f"),
                parse_scalar("0x2761c27c7450f24e"),
                parse_scalar("0xd28d5ddddde2d03b"),
            ]
        );
        assert_eq!(hash_t16_0(range(16)), parse_scalar("0xdc1ab6ca78e2737d"));
    }

    #[test]
    fn test_hash_t16_17() {
        assert_eq!(
            hash_t16(range(17)),
            [
                parse_scalar("0x42e99ebe78a2b70a"),
                parse_scalar("0x854f58289175dd33"),
                parse_scalar("0xd3708fd191094a4e"),
                parse_scalar("0x56155fdd02248a87"),
                parse_scalar("0x771d73de69773131"),
                parse_scalar("0x2664559df6fe534f"),
                parse_scalar("0x903f354576afb24f"),
                parse_scalar("0xa53d85142bc3154c"),
                parse_scalar("0xcd9f28c9a0cbc9b6"),
                parse_scalar("0x10c5f34bdb001b20"),
                parse_scalar("0x68bdeb18f0e831ba"),
                parse_scalar("0xdcd1dfa84969ce9d"),
            ]
        );
        assert_eq!(hash_t16_0(range(17)), parse_scalar("0x42e99ebe78a2b70a"));
    }
}
