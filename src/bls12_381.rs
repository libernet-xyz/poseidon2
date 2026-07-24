use crate::params::decode_constants;
use crate::poseidon::{self, sbox5};
use starkom_ff::bls12_381::Scalar;
use std::sync::LazyLock;

/// Poseidon configuration for the BLS12-381 scalar field.
pub struct BlsConfig<const T: usize, const R: usize, const C: usize> {}

impl poseidon::Config<Scalar, 3, 2, 1> for BlsConfig<3, 2, 1> {
    fn num_full_rounds() -> usize {
        4
    }

    fn num_partial_rounds() -> usize {
        56
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

impl poseidon::Config<Scalar, 4, 3, 1> for BlsConfig<4, 3, 1> {
    fn num_full_rounds() -> usize {
        4
    }

    fn num_partial_rounds() -> usize {
        56
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
pub type BlsConfig3 = BlsConfig<3, 2, 1>;

/// Poseidon configuration for BLS12-381 with T=4.
pub type BlsConfig4 = BlsConfig<4, 3, 1>;

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_scalar(s: &'static str) -> Scalar {
        s.parse().unwrap()
    }

    fn hash_t3(inputs: impl IntoIterator<Item = Scalar>) -> [Scalar; 2] {
        poseidon::hash::<BlsConfig3, Scalar, 3, 2, 1>(inputs)
    }

    fn hash_t3_0(inputs: impl IntoIterator<Item = Scalar>) -> Scalar {
        poseidon::hash0::<BlsConfig3, Scalar, 3, 2, 1>(inputs)
    }

    fn hash_t4(inputs: impl IntoIterator<Item = Scalar>) -> [Scalar; 3] {
        poseidon::hash::<BlsConfig4, Scalar, 4, 3, 1>(inputs)
    }

    fn hash_t4_0(inputs: impl IntoIterator<Item = Scalar>) -> Scalar {
        poseidon::hash0::<BlsConfig4, Scalar, 4, 3, 1>(inputs)
    }

    #[test]
    fn test_permutation_t3() {
        assert_eq!(
            poseidon::permutation::<BlsConfig3, Scalar, 3, 2, 1>([
                Scalar::from_const(0),
                Scalar::from_const(1),
                Scalar::from_const(2)
            ]),
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
            poseidon::permutation::<BlsConfig4, Scalar, 4, 3, 1>([
                Scalar::from_const(0),
                Scalar::from_const(1),
                Scalar::from_const(2),
                Scalar::from_const(3)
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
            hash_t3([Scalar::from_const(42)]),
            [
                parse_scalar("0x3096077a3d12ab01b506e6aceda3c0dda9fe86c329ce2996ee63e1517b729e29"),
                parse_scalar("0x05ff85d9259ee241559209ddf779631f05b51cc77901cb69c79c5ae65f3db9e6"),
            ]
        );
        assert_eq!(
            hash_t3_0([Scalar::from_const(42)]),
            parse_scalar("0x3096077a3d12ab01b506e6aceda3c0dda9fe86c329ce2996ee63e1517b729e29")
        );
    }

    #[test]
    fn test_hash_t3_2() {
        assert_eq!(
            hash_t3([Scalar::from_const(1), Scalar::from_const(2)]),
            [
                parse_scalar("0x70a58720d46a84d195bc875de66ed3ddef47522a7e806ec7a98c0d656517ce74"),
                parse_scalar("0x2629af1f361baa023b59f3c38fcb07a15b934c5e6be76c2e6be4f82155f8712d"),
            ]
        );
        assert_eq!(
            hash_t3_0([Scalar::from_const(1), Scalar::from_const(2)]),
            parse_scalar("0x70a58720d46a84d195bc875de66ed3ddef47522a7e806ec7a98c0d656517ce74")
        );
    }

    #[test]
    fn test_hash_t3_3() {
        assert_eq!(
            hash_t3([
                Scalar::from_const(3),
                Scalar::from_const(4),
                Scalar::from_const(5)
            ]),
            [
                parse_scalar("0x67497b788437da8141a3580f52a7ece12dbdd8ae1b9efef7dde3cf06cad18b8a"),
                parse_scalar("0x285c6bf6b09296651149961d9f0bec926ab0d6fe002df059e319026af4780efb"),
            ]
        );
        assert_eq!(
            hash_t3_0([
                Scalar::from_const(3),
                Scalar::from_const(4),
                Scalar::from_const(5)
            ]),
            parse_scalar("0x67497b788437da8141a3580f52a7ece12dbdd8ae1b9efef7dde3cf06cad18b8a")
        );
    }

    #[test]
    fn test_hash_t3_4() {
        assert_eq!(
            hash_t3([
                Scalar::from_const(6),
                Scalar::from_const(7),
                Scalar::from_const(8),
                Scalar::from_const(9)
            ]),
            [
                parse_scalar("0x6c1ac173b683ba0f3c743b3ae256f8ed269660e6825d2f41d52a8851bcfe689a"),
                parse_scalar("0x1d630b92554bc071812616fee04bf0a57ea9a1a982cca23167795092eb40ac06"),
            ]
        );
        assert_eq!(
            hash_t3_0([
                Scalar::from_const(6),
                Scalar::from_const(7),
                Scalar::from_const(8),
                Scalar::from_const(9)
            ]),
            parse_scalar("0x6c1ac173b683ba0f3c743b3ae256f8ed269660e6825d2f41d52a8851bcfe689a")
        );
    }

    #[test]
    fn test_hash_t3_5() {
        assert_eq!(
            hash_t3([
                Scalar::from_const(10),
                Scalar::from_const(11),
                Scalar::from_const(12),
                Scalar::from_const(13),
                Scalar::from_const(14)
            ]),
            [
                parse_scalar("0x64b7d7fafdefa8e32de1d2c5db35ff3f204c474bba09a1acc41704dafdbf0405"),
                parse_scalar("0x6d61b19cbea4f57294898ead7cd689b2621ecb0920b636ba6b08e90e6877b6fb"),
            ]
        );
        assert_eq!(
            hash_t3_0([
                Scalar::from_const(10),
                Scalar::from_const(11),
                Scalar::from_const(12),
                Scalar::from_const(13),
                Scalar::from_const(14)
            ]),
            parse_scalar("0x64b7d7fafdefa8e32de1d2c5db35ff3f204c474bba09a1acc41704dafdbf0405")
        );
    }

    #[test]
    fn test_hash_t4_1() {
        assert_eq!(
            hash_t4([Scalar::from_const(42)]),
            [
                parse_scalar("0x371862e4591023f4be2dd1b86827e2ef6dac40c430beab9d12344ddeef2a5802"),
                parse_scalar("0x6404da3d59a23d7b6f9f9c6ac505ec041a7096d1b1829f4768d83cf678686df1"),
                parse_scalar("0x247cddb15312a48b4ac4b725b4b167ef9eda9c603a704eeef709846cb72cbd98"),
            ]
        );
        assert_eq!(
            hash_t4_0([Scalar::from_const(42)]),
            parse_scalar("0x371862e4591023f4be2dd1b86827e2ef6dac40c430beab9d12344ddeef2a5802")
        );
    }

    #[test]
    fn test_hash_t4_2() {
        assert_eq!(
            hash_t4([Scalar::from_const(1), Scalar::from_const(2)]),
            [
                parse_scalar("0x588e95bbff17f8929c7775706570c315fe7db256e96fe213da4e8ffa0587cda8"),
                parse_scalar("0x683d43f52dfc5ad4c195772f2367a274f7d4de5dc8d6c4923d1203613be36a55"),
                parse_scalar("0x5a78daf14674b170598d9aeab87d51ce246892e177cb40c93299380982403c41"),
            ]
        );
        assert_eq!(
            hash_t4_0([Scalar::from_const(1), Scalar::from_const(2)]),
            parse_scalar("0x588e95bbff17f8929c7775706570c315fe7db256e96fe213da4e8ffa0587cda8")
        );
    }

    #[test]
    fn test_hash_t4_3() {
        assert_eq!(
            hash_t4([
                Scalar::from_const(3),
                Scalar::from_const(4),
                Scalar::from_const(5)
            ]),
            [
                parse_scalar("0x5f5ba9ebadb4641e56a4d98062c1b8d8f6e5dcf0a3e740844f06d5f9237b5eb2"),
                parse_scalar("0x54d28c892ecb83c35f0918e09f7e19d66279571f94b99a46216bfc36f89f8cae"),
                parse_scalar("0x3fe18f2eae5be09983d5293beb57a05f29a07e502fc0e0f487fc9a446f24a791"),
            ]
        );
        assert_eq!(
            hash_t4_0([
                Scalar::from_const(3),
                Scalar::from_const(4),
                Scalar::from_const(5)
            ]),
            parse_scalar("0x5f5ba9ebadb4641e56a4d98062c1b8d8f6e5dcf0a3e740844f06d5f9237b5eb2")
        );
    }

    #[test]
    fn test_hash_t4_4() {
        assert_eq!(
            hash_t4([
                Scalar::from_const(6),
                Scalar::from_const(7),
                Scalar::from_const(8),
                Scalar::from_const(9)
            ]),
            [
                parse_scalar("0x3e2c69046948fc299380c2b83b1b785c36d9d36df9da6395d03b77927039ba05"),
                parse_scalar("0x61c16e752c0aae1dbd75ab3562a9c937055f67d158a0c234dcf3a71f934d1443"),
                parse_scalar("0x2c83ce003c5ac171951607d4c65eb61118fb54ef78e908d190a9beb49e6b29da"),
            ]
        );
        assert_eq!(
            hash_t4_0([
                Scalar::from_const(6),
                Scalar::from_const(7),
                Scalar::from_const(8),
                Scalar::from_const(9)
            ]),
            parse_scalar("0x3e2c69046948fc299380c2b83b1b785c36d9d36df9da6395d03b77927039ba05")
        );
    }

    #[test]
    fn test_hash_t4_5() {
        assert_eq!(
            hash_t4([
                Scalar::from_const(10),
                Scalar::from_const(11),
                Scalar::from_const(12),
                Scalar::from_const(13),
                Scalar::from_const(14)
            ]),
            [
                parse_scalar("0x414a70dcfe4bfeb447008058a293fa5e64e31e3c78ca8441d6fe8886fb0892dc"),
                parse_scalar("0x3cd56078f9c97e3cbbdf6e07b4610ba4709836acdc972b5467b92676107f7dc8"),
                parse_scalar("0x3a3ce52a3eba367e6301d5f93f4d9cb7215c8815946e11fbe87e086011da3520"),
            ]
        );
        assert_eq!(
            hash_t4_0([
                Scalar::from_const(10),
                Scalar::from_const(11),
                Scalar::from_const(12),
                Scalar::from_const(13),
                Scalar::from_const(14)
            ]),
            parse_scalar("0x414a70dcfe4bfeb447008058a293fa5e64e31e3c78ca8441d6fe8886fb0892dc")
        );
    }
}
