use crate::params::decode_constants;
use crate::poseidon::{self, sbox5};
use starkom_bluesky::Scalar;
use std::sync::LazyLock;

/// Poseidon configuration for the BlueSky field.
pub struct BlueSkyConfig<const T: usize> {}

impl poseidon::Config<Scalar, 3> for BlueSkyConfig<3> {
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
            let bytes = include_bytes!("../params/bluesky/arc_t3.bin");
            decode_constants::<Scalar, 192>(bytes)
        });
        &*ROUND_CONSTANTS
    }

    fn get_external_matrix() -> &'static [Scalar] {
        static MATRIX: LazyLock<[Scalar; 9]> = LazyLock::new(|| {
            let bytes = include_bytes!("../params/bluesky/fl_t3.bin");
            decode_constants::<Scalar, 9>(bytes)
        });
        &*MATRIX
    }

    fn get_internal_matrix() -> &'static [Scalar] {
        static MATRIX: LazyLock<[Scalar; 9]> = LazyLock::new(|| {
            let bytes = include_bytes!("../params/bluesky/pl_t3.bin");
            decode_constants::<Scalar, 9>(bytes)
        });
        &*MATRIX
    }
}

impl poseidon::Config<Scalar, 4> for BlueSkyConfig<4> {
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
            let bytes = include_bytes!("../params/bluesky/arc_t4.bin");
            decode_constants::<Scalar, 256>(bytes)
        });
        &*ROUND_CONSTANTS
    }

    fn get_external_matrix() -> &'static [Scalar] {
        static MATRIX: LazyLock<[Scalar; 16]> = LazyLock::new(|| {
            let bytes = include_bytes!("../params/bluesky/fl_t4.bin");
            decode_constants::<Scalar, 16>(bytes)
        });
        &*MATRIX
    }

    fn get_internal_matrix() -> &'static [Scalar] {
        static MATRIX: LazyLock<[Scalar; 16]> = LazyLock::new(|| {
            let bytes = include_bytes!("../params/bluesky/pl_t4.bin");
            decode_constants::<Scalar, 16>(bytes)
        });
        &*MATRIX
    }
}

/// Poseidon configuration for BlueSky with T=3.
pub type BlueSkyConfig3 = BlueSkyConfig<3>;

/// Poseidon configuration for BlueSky with T=4.
pub type BlueSkyConfig4 = BlueSkyConfig<4>;

#[cfg(test)]
mod tests {
    use super::*;
    use primitive_types::U256;

    fn parse_scalar(s: &'static str) -> Scalar {
        let u256: U256 = s.parse().unwrap();
        Scalar::from_little_endian(&u256.to_little_endian()).unwrap()
    }

    fn hash_t3(inputs: &[Scalar]) -> Scalar {
        poseidon::hash::<BlueSkyConfig3, Scalar, 3>(inputs)
    }

    fn hash_t4(inputs: &[Scalar]) -> Scalar {
        poseidon::hash::<BlueSkyConfig4, Scalar, 4>(inputs)
    }

    #[test]
    fn test_permutation_t3() {
        assert_eq!(
            poseidon::permutation::<BlueSkyConfig3, Scalar, 3>([0.into(), 1.into(), 2.into()]),
            [
                parse_scalar("0x6f30582cde48a25b26015b7f718ba2fb359e93029caf04d8d0b3e66b1d46b941"),
                parse_scalar("0x5de8159372063ce76403529bb1a9725461b96467035d906400ff48d0937f9db6"),
                parse_scalar("0x3c88b37dc6d14d08960b6fe58344e09194d11a930ce9f60cc90294683fac4b9f"),
            ]
        );
    }

    #[test]
    fn test_permutation_t4() {
        assert_eq!(
            poseidon::permutation::<BlueSkyConfig4, Scalar, 4>([
                0.into(),
                1.into(),
                2.into(),
                3.into()
            ]),
            [
                parse_scalar("0x775049834d9decb40ec5a109116a27527fa9105a3521cee8a42777788fda1501"),
                parse_scalar("0x630ded08b39ceac4859c9ab6d14b548f48d01164ce1efada3a7a868f7d9248cb"),
                parse_scalar("0x14b47f414dececb9936dcbb89e2fdd8511c44acb30439d1d23e48119b1c03b4f"),
                parse_scalar("0x72de70292ce1ac7f30b859d04bbb6de5377288c1192a08863c34e11bc9269c4c"),
            ]
        );
    }

    #[test]
    fn test_hash_t3_1() {
        assert_eq!(
            hash_t3(&[42.into()]),
            parse_scalar("0x302e6d6d782c1367974698e051d9b55e18060b19393a4f0ac4b66f992bd5a5eb")
        );
    }

    #[test]
    fn test_hash_t3_2() {
        assert_eq!(
            hash_t3(&[1.into(), 2.into()]),
            parse_scalar("0x2a24882111b586a835203bdeb7a97d8489e410eadf12a495624f49b729528873")
        );
    }

    #[test]
    fn test_hash_t3_3() {
        assert_eq!(
            hash_t3(&[3.into(), 4.into(), 5.into()]),
            parse_scalar("0x160be03feff499f1256ce2404ff9ee026fc378b6a91d434746bab98aafaecb63")
        );
    }

    #[test]
    fn test_hash_t3_4() {
        assert_eq!(
            hash_t3(&[6.into(), 7.into(), 8.into(), 9.into()]),
            parse_scalar("0x63d491b523ae737f62f117ef5affb8353996b67034ddaeb8586b574678ab440a")
        );
    }

    #[test]
    fn test_hash_t3_5() {
        assert_eq!(
            hash_t3(&[10.into(), 11.into(), 12.into(), 13.into(), 14.into()]),
            parse_scalar("0x329255ad3db8a69a50a2a1f63fb4046d06d5bc6de30bf79bfe4138f4c93201df")
        );
    }

    #[test]
    fn test_hash_t4_1() {
        assert_eq!(
            hash_t4(&[42.into()]),
            parse_scalar("0x109a9fd885b0047b036489dad6d0ca97749f6a9b21d9fc2c1cb7d25952e453a0")
        );
    }

    #[test]
    fn test_hash_t4_2() {
        assert_eq!(
            hash_t4(&[1.into(), 2.into()]),
            parse_scalar("0x7c4e380d8a3935c0e8073420573f5b6aaf9ed2c727afc4da64f12401ab355faf")
        );
    }

    #[test]
    fn test_hash_t4_3() {
        assert_eq!(
            hash_t4(&[3.into(), 4.into(), 5.into()]),
            parse_scalar("0x2582eca7bed4bca9d4326a9e2ca601e0b3779582bb5173318a4e19ab005e7495")
        );
    }

    #[test]
    fn test_hash_t4_4() {
        assert_eq!(
            hash_t4(&[6.into(), 7.into(), 8.into(), 9.into()]),
            parse_scalar("0x6b13720a0ebd34f13327023c0232a3a3421f88d50b627bacfd114491ae48bfaa")
        );
    }

    #[test]
    fn test_hash_t4_5() {
        assert_eq!(
            hash_t4(&[10.into(), 11.into(), 12.into(), 13.into(), 14.into()]),
            parse_scalar("0x4f07a42cf3cd73f35eeb9b42bff06b11e1c7ebe0fd8f65b7fab0dd5d551f1c6c")
        );
    }
}
