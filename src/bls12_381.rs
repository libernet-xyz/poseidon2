use crate::params::decode_constants;
use crate::poseidon::{self, sbox5};
use blstrs::Scalar;
use std::sync::LazyLock;

/// Poseidon configuration for the BLS12-381 scalar field.
pub struct BlsConfig<const T: usize> {}

impl poseidon::Config<Scalar, 3> for BlsConfig<3> {
    fn num_full_rounds() -> usize {
        4
    }

    fn num_partial_rounds() -> usize {
        56
    }

    fn num_total_rounds() -> usize {
        64
    }

    fn sbox(x: Scalar) -> Scalar {
        sbox5(x)
    }

    fn get_round_constants() -> &'static [Scalar] {
        static ROUND_CONSTANTS: LazyLock<[Scalar; 192]> = LazyLock::new(|| {
            let bytes = include_bytes!("../params/bls12_381/arc_t3.bin");
            decode_constants::<Scalar, 192>(bytes)
        });
        &*ROUND_CONSTANTS
    }

    fn get_external_matrix() -> &'static [Scalar] {
        static MATRIX: LazyLock<[Scalar; 9]> = LazyLock::new(|| {
            let bytes = include_bytes!("../params/bls12_381/fl_t3.bin");
            decode_constants::<Scalar, 9>(bytes)
        });
        &*MATRIX
    }

    fn get_internal_matrix() -> &'static [Scalar] {
        static MATRIX: LazyLock<[Scalar; 9]> = LazyLock::new(|| {
            let bytes = include_bytes!("../params/bls12_381/pl_t3.bin");
            decode_constants::<Scalar, 9>(bytes)
        });
        &*MATRIX
    }
}

impl poseidon::Config<Scalar, 4> for BlsConfig<4> {
    fn num_full_rounds() -> usize {
        4
    }

    fn num_partial_rounds() -> usize {
        56
    }

    fn num_total_rounds() -> usize {
        64
    }

    fn sbox(x: Scalar) -> Scalar {
        sbox5(x)
    }

    fn get_round_constants() -> &'static [Scalar] {
        static ROUND_CONSTANTS: LazyLock<[Scalar; 256]> = LazyLock::new(|| {
            let bytes = include_bytes!("../params/bls12_381/arc_t4.bin");
            decode_constants::<Scalar, 256>(bytes)
        });
        &*ROUND_CONSTANTS
    }

    fn get_external_matrix() -> &'static [Scalar] {
        static MATRIX: LazyLock<[Scalar; 16]> = LazyLock::new(|| {
            let bytes = include_bytes!("../params/bls12_381/fl_t4.bin");
            decode_constants::<Scalar, 16>(bytes)
        });
        &*MATRIX
    }

    fn get_internal_matrix() -> &'static [Scalar] {
        static MATRIX: LazyLock<[Scalar; 16]> = LazyLock::new(|| {
            let bytes = include_bytes!("../params/bls12_381/pl_t4.bin");
            decode_constants::<Scalar, 16>(bytes)
        });
        &*MATRIX
    }
}

/// Poseidon configuration for BLS12-381 with T=3.
pub type BlsConfig3 = BlsConfig<3>;

/// Poseidon configuration for BLS12-381 with T=4.
pub type BlsConfig4 = BlsConfig<4>;

#[cfg(test)]
mod tests {
    use super::*;
    use primitive_types::U256;

    fn parse_scalar(s: &'static str) -> Scalar {
        let u256: U256 = s.parse().unwrap();
        Scalar::from_bytes_le(&u256.to_little_endian()).unwrap()
    }

    fn hash_t3(inputs: &[Scalar]) -> Scalar {
        poseidon::hash::<BlsConfig3, Scalar, 3>(inputs)
    }

    fn hash_t4(inputs: &[Scalar]) -> Scalar {
        poseidon::hash::<BlsConfig4, Scalar, 4>(inputs)
    }

    #[test]
    fn test_permutation_t3() {
        assert_eq!(
            poseidon::permutation::<BlsConfig3, Scalar, 3>([0.into(), 1.into(), 2.into()]),
            [
                parse_scalar("0x1b152349b1950b6a8ca75ee4407b6e26ca5cca5650534e56ef3fd45761fbf5f0"),
                parse_scalar("0x4c5793c87d51bdc2c08a32108437dc0000bd0275868f09ebc5f36919af5b3891"),
                parse_scalar("0x1fc8ed171e67902ca49863159fe5ba6325318843d13976143b8125f08b50dc6b"),
            ]
        );
    }

    #[test]
    fn test_permutation_t4() {
        assert_eq!(
            poseidon::permutation::<BlsConfig4, Scalar, 4>([
                0.into(),
                1.into(),
                2.into(),
                3.into()
            ]),
            [
                parse_scalar("0x28ff6c4edf9768c08ae26290487e93449cc8bc155fc2fad92a344adceb3ada6d"),
                parse_scalar("0x0e56f2b6fad25075aa93560185b70e2b180ed7e269159c507c288b6747a0db2d"),
                parse_scalar("0x6d8196f28da6006bb89b3df94600acdc03d0ba7c2b0f3f4409a54c1db6bf30d0"),
                parse_scalar("0x07cfb49540ee456cce38b8a7d1a930a57ffc6660737f6589ef184c5e15334e36"),
            ]
        );
    }

    #[test]
    fn test_hash_t3_1() {
        assert_eq!(
            hash_t3(&[42.into()]),
            parse_scalar("0x3096077a3d12ab01b506e6aceda3c0dda9fe86c329ce2996ee63e1517b729e29")
        );
    }

    #[test]
    fn test_hash_t3_2() {
        assert_eq!(
            hash_t3(&[1.into(), 2.into()]),
            parse_scalar("0x70a58720d46a84d195bc875de66ed3ddef47522a7e806ec7a98c0d656517ce74")
        );
    }

    #[test]
    fn test_hash_t3_3() {
        assert_eq!(
            hash_t3(&[3.into(), 4.into(), 5.into()]),
            parse_scalar("0x67497b788437da8141a3580f52a7ece12dbdd8ae1b9efef7dde3cf06cad18b8a")
        );
    }

    #[test]
    fn test_hash_t3_4() {
        assert_eq!(
            hash_t3(&[6.into(), 7.into(), 8.into(), 9.into()]),
            parse_scalar("0x6c1ac173b683ba0f3c743b3ae256f8ed269660e6825d2f41d52a8851bcfe689a")
        );
    }

    #[test]
    fn test_hash_t3_5() {
        assert_eq!(
            hash_t3(&[10.into(), 11.into(), 12.into(), 13.into(), 14.into()]),
            parse_scalar("0x64b7d7fafdefa8e32de1d2c5db35ff3f204c474bba09a1acc41704dafdbf0405")
        );
    }

    #[test]
    fn test_hash_t4_1() {
        assert_eq!(
            hash_t4(&[42.into()]),
            parse_scalar("0x371862e4591023f4be2dd1b86827e2ef6dac40c430beab9d12344ddeef2a5802")
        );
    }

    #[test]
    fn test_hash_t4_2() {
        assert_eq!(
            hash_t4(&[1.into(), 2.into()]),
            parse_scalar("0x588e95bbff17f8929c7775706570c315fe7db256e96fe213da4e8ffa0587cda8")
        );
    }

    #[test]
    fn test_hash_t4_3() {
        assert_eq!(
            hash_t4(&[3.into(), 4.into(), 5.into()]),
            parse_scalar("0x5f5ba9ebadb4641e56a4d98062c1b8d8f6e5dcf0a3e740844f06d5f9237b5eb2")
        );
    }

    #[test]
    fn test_hash_t4_4() {
        assert_eq!(
            hash_t4(&[6.into(), 7.into(), 8.into(), 9.into()]),
            parse_scalar("0x3e2c69046948fc299380c2b83b1b785c36d9d36df9da6395d03b77927039ba05")
        );
    }

    #[test]
    fn test_hash_t4_5() {
        assert_eq!(
            hash_t4(&[10.into(), 11.into(), 12.into(), 13.into(), 14.into()]),
            parse_scalar("0x414a70dcfe4bfeb447008058a293fa5e64e31e3c78ca8441d6fe8886fb0892dc")
        );
    }
}
