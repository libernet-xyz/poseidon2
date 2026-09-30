use crate::params::decode_constants;
use crate::poseidon;
use starkom_goldilocks::GL as Scalar;
use std::sync::LazyLock;

/// Poseidon2 configuration for the Goldilocks field.
pub struct GoldilocksConfig<const T: usize> {}

impl poseidon::Config<Scalar, 12> for GoldilocksConfig<12> {
    fn num_full_rounds_per_side() -> usize {
        4
    }

    fn num_partial_rounds() -> usize {
        22
    }

    fn alpha() -> usize {
        7
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
    fn num_full_rounds_per_side() -> usize {
        4
    }

    fn num_partial_rounds() -> usize {
        22
    }

    fn alpha() -> usize {
        7
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
    use starkom_ff::Field;
    use starkom_goldilocks::from_const;

    const DST: [Scalar; 4] = [Scalar::ZERO; 4];

    fn hash_t12(dst: [Scalar; 4], inputs: impl IntoIterator<Item = Scalar>) -> [Scalar; 8] {
        poseidon::hash::<GoldilocksConfig12, Scalar, 12, 8, 4>(dst, inputs)
    }

    fn hash_t12_0(dst: [Scalar; 4], inputs: impl IntoIterator<Item = Scalar>) -> Scalar {
        poseidon::hash0::<GoldilocksConfig12, Scalar, 12, 8, 4>(dst, inputs)
    }

    fn hash_t16(dst: [Scalar; 4], inputs: impl IntoIterator<Item = Scalar>) -> [Scalar; 12] {
        poseidon::hash::<GoldilocksConfig16, Scalar, 16, 12, 4>(dst, inputs)
    }

    fn hash_t16_0(dst: [Scalar; 4], inputs: impl IntoIterator<Item = Scalar>) -> Scalar {
        poseidon::hash0::<GoldilocksConfig16, Scalar, 16, 12, 4>(dst, inputs)
    }

    fn range(n: u64) -> Vec<Scalar> {
        (0..n).map(from_const).collect()
    }

    #[test]
    fn test_permutation_t12() {
        assert_eq!(
            poseidon::permutation::<GoldilocksConfig12, Scalar, 12>(range(12).try_into().unwrap()),
            [
                from_const(0x01eaef96bdf1c0c1),
                from_const(0x1f0d2cc525b2540c),
                from_const(0x6282c1dfe1e0358d),
                from_const(0xe780d721f698e1e6),
                from_const(0x280c0b6f753d833b),
                from_const(0x1b942dd5023156ab),
                from_const(0x43f0df3fcccb8398),
                from_const(0xe8e8190585489025),
                from_const(0x56bdbf72f77ada22),
                from_const(0x7911c32bf9dcd705),
                from_const(0xec467926508fbe67),
                from_const(0x6a50450ddf85a6ed),
            ]
        );
    }

    #[test]
    fn test_permutation_t16() {
        assert_eq!(
            poseidon::permutation::<GoldilocksConfig16, Scalar, 16>(range(16).try_into().unwrap()),
            [
                from_const(0x85c54702470d9756),
                from_const(0xaa53c7a7d52d9898),
                from_const(0x285128096efb0dd7),
                from_const(0xf3fde5edd3050ac8),
                from_const(0xc7b65efd040df908),
                from_const(0x4be3f6c467f57ae9),
                from_const(0x274e9a67b41754fb),
                from_const(0x0f7d39cd5de94dac),
                from_const(0xd0224b9794d0b78c),
                from_const(0x372f6139570042e1),
                from_const(0xce6e8a93dc4ec26c),
                from_const(0xace65e30a4daf7af),
                from_const(0x016f2824cc1ba3db),
                from_const(0x2e8f3af37c434dec),
                from_const(0xc80831bb6e09da01),
                from_const(0x3a7d670bf1a86ee8),
            ]
        );
    }

    #[test]
    fn test_capacity_dst_t12() {
        assert_eq!(
            hash_t12(DST, range(8)),
            [
                from_const(0xfd2ed0da41a63e0b),
                from_const(0x94252156cb2374ba),
                from_const(0xc5585182a3092abf),
                from_const(0x653c8aaa741bf05b),
                from_const(0x9ab1dd68e3dd2ab0),
                from_const(0xbd3bd7b198977827),
                from_const(0x63b408e2eb16e145),
                from_const(0xce70ffe4e269654a),
            ]
        );
        assert_eq!(
            hash_t12(
                [from_const(8), from_const(9), from_const(10), from_const(11)],
                range(8)
            ),
            [
                from_const(0x01eaef96bdf1c0c1),
                from_const(0x1f0d2cc525b2540c),
                from_const(0x6282c1dfe1e0358d),
                from_const(0xe780d721f698e1e6),
                from_const(0x280c0b6f753d833b),
                from_const(0x1b942dd5023156ab),
                from_const(0x43f0df3fcccb8398),
                from_const(0xe8e8190585489025),
            ]
        );
    }

    #[test]
    fn test_capacity_dst_t16() {
        assert_eq!(
            hash_t16(DST, range(12)),
            [
                from_const(0xd66460d8c09a912b),
                from_const(0xbdcd36a3acf806d2),
                from_const(0x5113907be722f501),
                from_const(0x4ca4eee19c3c5a2d),
                from_const(0x54915e981eb28092),
                from_const(0x73e8488fdea9ae75),
                from_const(0xed5b7865c043656b),
                from_const(0xb82ca7c9c07f0f0b),
                from_const(0xe4a0823061e92dbc),
                from_const(0x92a7cf669d5d9f94),
                from_const(0xf87ef9aa4d027c1e),
                from_const(0x70648b9fd05bb1cd),
            ]
        );
        assert_eq!(
            hash_t16(
                [
                    from_const(12),
                    from_const(13),
                    from_const(14),
                    from_const(15)
                ],
                range(12)
            ),
            [
                from_const(0x85c54702470d9756),
                from_const(0xaa53c7a7d52d9898),
                from_const(0x285128096efb0dd7),
                from_const(0xf3fde5edd3050ac8),
                from_const(0xc7b65efd040df908),
                from_const(0x4be3f6c467f57ae9),
                from_const(0x274e9a67b41754fb),
                from_const(0x0f7d39cd5de94dac),
                from_const(0xd0224b9794d0b78c),
                from_const(0x372f6139570042e1),
                from_const(0xce6e8a93dc4ec26c),
                from_const(0xace65e30a4daf7af),
            ]
        );
    }

    #[test]
    fn test_hash_t12_1() {
        assert_eq!(
            hash_t12(DST, range(1)),
            [
                from_const(0xef311849263abcb4),
                from_const(0x8bf04d36f9a01799),
                from_const(0x9e570c4df0f2699f),
                from_const(0x6927c3a96db0b2ad),
                from_const(0x760d22fbb5fc5de0),
                from_const(0xafd1fedcdef654f4),
                from_const(0xbb8c81621d5d5aed),
                from_const(0x298915feb162422c),
            ]
        );
        assert_eq!(hash_t12_0(DST, range(1)), from_const(0xef311849263abcb4));
    }

    #[test]
    fn test_hash_t12_2() {
        assert_eq!(
            hash_t12(DST, range(2)),
            [
                from_const(0x868352e949a41bce),
                from_const(0x09bc14bd401a370a),
                from_const(0x95d895ea09268383),
                from_const(0x813447f570e8c33f),
                from_const(0x4b8570484aa9eeae),
                from_const(0x52e1842ee5595711),
                from_const(0xc5b1f55643b615a8),
                from_const(0x64bc5f3129a38bc0),
            ]
        );
        assert_eq!(hash_t12_0(DST, range(2)), from_const(0x868352e949a41bce));
    }

    #[test]
    fn test_hash_t12_8() {
        assert_eq!(
            hash_t12(DST, range(8)),
            [
                from_const(0xfd2ed0da41a63e0b),
                from_const(0x94252156cb2374ba),
                from_const(0xc5585182a3092abf),
                from_const(0x653c8aaa741bf05b),
                from_const(0x9ab1dd68e3dd2ab0),
                from_const(0xbd3bd7b198977827),
                from_const(0x63b408e2eb16e145),
                from_const(0xce70ffe4e269654a),
            ]
        );
        assert_eq!(hash_t12_0(DST, range(8)), from_const(0xfd2ed0da41a63e0b));
    }

    #[test]
    fn test_hash_t12_9() {
        assert_eq!(
            hash_t12(DST, range(9)),
            [
                from_const(0x79528f6968b8fc8e),
                from_const(0xa9b0059cfeb3fdc1),
                from_const(0xf9d474a3916eb700),
                from_const(0xda90951bf86349e3),
                from_const(0xb1b0995f9b02dfeb),
                from_const(0x6b340b48657922c1),
                from_const(0x09678d12d7f7d633),
                from_const(0x3145c3da2f367338),
            ]
        );
        assert_eq!(hash_t12_0(DST, range(9)), from_const(0x79528f6968b8fc8e));
    }

    #[test]
    fn test_hash_t12_11() {
        assert_eq!(
            hash_t12(DST, range(11)),
            [
                from_const(0x43d0036caf8454a1),
                from_const(0xa2bcbd4ed5a14100),
                from_const(0xc33aad6222932517),
                from_const(0x5d80fcd5fecd0fff),
                from_const(0xc2d23dba4ff23013),
                from_const(0x99d084657f2b29ac),
                from_const(0x8f5ead63db53853e),
                from_const(0x4fdb7d5ca4f1da21),
            ]
        );
        assert_eq!(hash_t12_0(DST, range(11)), from_const(0x43d0036caf8454a1));
    }

    #[test]
    fn test_hash_t12_12() {
        assert_eq!(
            hash_t12(DST, range(12)),
            [
                from_const(0x2f038ce6adcd4ff9),
                from_const(0x9ff2232c123e6b81),
                from_const(0xa1d3b8af23e412d2),
                from_const(0x12e26c6feee38c37),
                from_const(0x4d09e9c136f6a9ba),
                from_const(0xd352b7dcb8c7938d),
                from_const(0xcba921b2ad73a196),
                from_const(0x92b6d7029dc57e29),
            ]
        );
        assert_eq!(hash_t12_0(DST, range(12)), from_const(0x2f038ce6adcd4ff9));
    }

    #[test]
    fn test_hash_t12_13() {
        assert_eq!(
            hash_t12(DST, range(13)),
            [
                from_const(0x5735a7e6ab16f177),
                from_const(0xec6edec1bbe88257),
                from_const(0x24c78f7980b765fa),
                from_const(0x701a85024e1820c1),
                from_const(0x1fcce822178839ba),
                from_const(0x88b02af516657820),
                from_const(0x7abe4fa3b862db08),
                from_const(0xf8295c4e6eb96919),
            ]
        );
        assert_eq!(hash_t12_0(DST, range(13)), from_const(0x5735a7e6ab16f177));
    }

    #[test]
    fn test_hash_t16_1() {
        assert_eq!(
            hash_t16(DST, range(1)),
            [
                from_const(0xf2b2442ea4d72b98),
                from_const(0x08367625af002a12),
                from_const(0x41d794a3d56b9451),
                from_const(0x533967a2f0a214c8),
                from_const(0x9b10cb9aecef64c2),
                from_const(0x3af18efb76e71cc4),
                from_const(0x20d42b106f3cd4d6),
                from_const(0x537149275a93e1b9),
                from_const(0xe48c755b2541ac33),
                from_const(0xd88485c5e6be8ad5),
                from_const(0xf864699c52b2d651),
                from_const(0x3bb13e057d4f33c6),
            ]
        );
        assert_eq!(hash_t16_0(DST, range(1)), from_const(0xf2b2442ea4d72b98));
    }

    #[test]
    fn test_hash_t16_2() {
        assert_eq!(
            hash_t16(DST, range(2)),
            [
                from_const(0xc15fbf2803ac65dd),
                from_const(0x08074b5aebc022de),
                from_const(0xea229fdd8a70c2d6),
                from_const(0x07b7e9ee134e5a87),
                from_const(0x2e78869e72d189a4),
                from_const(0xce7ad0cb08fe6d75),
                from_const(0x193513be5e03294f),
                from_const(0xb4d66fa29d946e1a),
                from_const(0x9c1ea0488a8a7e0f),
                from_const(0x15944a5b7d1bfb16),
                from_const(0xa971b2c914158460),
                from_const(0x1abcdd88deac4f10),
            ]
        );
        assert_eq!(hash_t16_0(DST, range(2)), from_const(0xc15fbf2803ac65dd));
    }

    #[test]
    fn test_hash_t16_12() {
        assert_eq!(
            hash_t16(DST, range(12)),
            [
                from_const(0xd66460d8c09a912b),
                from_const(0xbdcd36a3acf806d2),
                from_const(0x5113907be722f501),
                from_const(0x4ca4eee19c3c5a2d),
                from_const(0x54915e981eb28092),
                from_const(0x73e8488fdea9ae75),
                from_const(0xed5b7865c043656b),
                from_const(0xb82ca7c9c07f0f0b),
                from_const(0xe4a0823061e92dbc),
                from_const(0x92a7cf669d5d9f94),
                from_const(0xf87ef9aa4d027c1e),
                from_const(0x70648b9fd05bb1cd),
            ]
        );
        assert_eq!(hash_t16_0(DST, range(12)), from_const(0xd66460d8c09a912b));
    }

    #[test]
    fn test_hash_t16_13() {
        assert_eq!(
            hash_t16(DST, range(13)),
            [
                from_const(0x0ccae528199e8a7f),
                from_const(0x4c0d4be6ed277199),
                from_const(0xf04b738ac688ff1f),
                from_const(0x67ba4d00d2ab90b6),
                from_const(0xddb8a9ae2c73281b),
                from_const(0xc5c9ce6ef34c1603),
                from_const(0x0607560bacd79d1f),
                from_const(0xc5ce28cb8f7f5d34),
                from_const(0x182b9e762c1c0b0d),
                from_const(0xb5d1fd5916ab218a),
                from_const(0xcc283ae14bb815e9),
                from_const(0x66bb49824442c8b3),
            ]
        );
        assert_eq!(hash_t16_0(DST, range(13)), from_const(0x0ccae528199e8a7f));
    }

    #[test]
    fn test_hash_t16_15() {
        assert_eq!(
            hash_t16(DST, range(15)),
            [
                from_const(0x8c1d1af9b63b88ae),
                from_const(0x2c91cc531b87b1f3),
                from_const(0xe3ded808778829df),
                from_const(0xfcbe93b8763943d7),
                from_const(0x97ef96f852742b11),
                from_const(0x53c86d06e2914d05),
                from_const(0xa9b2fd18064fceae),
                from_const(0xb7ac2caf89f3d14b),
                from_const(0x4acc25fc21ad1322),
                from_const(0xb7f73c50198965cb),
                from_const(0xa464b48a8629eb91),
                from_const(0x262ecbfa9807635d),
            ]
        );
        assert_eq!(hash_t16_0(DST, range(15)), from_const(0x8c1d1af9b63b88ae));
    }

    #[test]
    fn test_hash_t16_16() {
        assert_eq!(
            hash_t16(DST, range(16)),
            [
                from_const(0xdc1ab6ca78e2737d),
                from_const(0xc4aebc20584b7492),
                from_const(0x9bf1cb58e29b0e04),
                from_const(0xbb6518684cde640e),
                from_const(0x1588e01ab26aae7f),
                from_const(0xd8fdd105f80299cc),
                from_const(0xc092c03409d99d66),
                from_const(0x6ce884c450a6c8c6),
                from_const(0x0c9cdb0f9c563b18),
                from_const(0xe5c47af9667fda3f),
                from_const(0x2761c27c7450f24e),
                from_const(0xd28d5ddddde2d03b),
            ]
        );
        assert_eq!(hash_t16_0(DST, range(16)), from_const(0xdc1ab6ca78e2737d));
    }

    #[test]
    fn test_hash_t16_17() {
        assert_eq!(
            hash_t16(DST, range(17)),
            [
                from_const(0x42e99ebe78a2b70a),
                from_const(0x854f58289175dd33),
                from_const(0xd3708fd191094a4e),
                from_const(0x56155fdd02248a87),
                from_const(0x771d73de69773131),
                from_const(0x2664559df6fe534f),
                from_const(0x903f354576afb24f),
                from_const(0xa53d85142bc3154c),
                from_const(0xcd9f28c9a0cbc9b6),
                from_const(0x10c5f34bdb001b20),
                from_const(0x68bdeb18f0e831ba),
                from_const(0xdcd1dfa84969ce9d),
            ]
        );
        assert_eq!(hash_t16_0(DST, range(17)), from_const(0x42e99ebe78a2b70a));
    }
}
