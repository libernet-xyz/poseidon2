use crate::params::decode_constants;
use crate::poseidon::{self, sbox5};
use starkom_bluesky::Scalar;
use std::sync::LazyLock;

/// Poseidon configuration for the BlueSky field.
pub struct BlueSkyConfig<const T: usize, const R: usize, const C: usize> {}

impl poseidon::Config<Scalar, 3, 2, 1> for BlueSkyConfig<3, 2, 1> {
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

impl poseidon::Config<Scalar, 4, 3, 1> for BlueSkyConfig<4, 3, 1> {
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
pub type BlueSkyConfig3 = BlueSkyConfig<3, 2, 1>;

/// Poseidon configuration for BlueSky with T=4.
pub type BlueSkyConfig4 = BlueSkyConfig<4, 3, 1>;

#[cfg(test)]
mod tests {
    use super::*;
    use starkom_bluesky::{from_const, parse_scalar};

    fn hash_t3(inputs: impl IntoIterator<Item = Scalar>) -> [Scalar; 2] {
        poseidon::hash::<BlueSkyConfig3, Scalar, 3, 2, 1>(inputs)
    }

    fn hash_t3_0(inputs: impl IntoIterator<Item = Scalar>) -> Scalar {
        poseidon::hash0::<BlueSkyConfig3, Scalar, 3, 2, 1>(inputs)
    }

    fn hash_t4(inputs: impl IntoIterator<Item = Scalar>) -> [Scalar; 3] {
        poseidon::hash::<BlueSkyConfig4, Scalar, 4, 3, 1>(inputs)
    }

    fn hash_t4_0(inputs: impl IntoIterator<Item = Scalar>) -> Scalar {
        poseidon::hash0::<BlueSkyConfig4, Scalar, 4, 3, 1>(inputs)
    }

    #[test]
    fn test_permutation_t3() {
        assert_eq!(
            poseidon::permutation::<BlueSkyConfig3, Scalar, 3, 2, 1>([
                from_const(0),
                from_const(1),
                from_const(2)
            ]),
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
            poseidon::permutation::<BlueSkyConfig4, Scalar, 4, 3, 1>([
                from_const(0),
                from_const(1),
                from_const(2),
                from_const(3)
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
            hash_t3([from_const(42)]),
            [
                parse_scalar("0x302e6d6d782c1367974698e051d9b55e18060b19393a4f0ac4b66f992bd5a5eb"),
                parse_scalar("0x26f778c0f82ffe3d4409ebb9d7e4611556ca89c6a3e1a77cf8b80528eb344777"),
            ]
        );
        assert_eq!(
            hash_t3_0([from_const(42)]),
            parse_scalar("0x302e6d6d782c1367974698e051d9b55e18060b19393a4f0ac4b66f992bd5a5eb")
        );
    }

    #[test]
    fn test_hash_t3_2() {
        assert_eq!(
            hash_t3([from_const(1), from_const(2)]),
            [
                parse_scalar("0x2a24882111b586a835203bdeb7a97d8489e410eadf12a495624f49b729528873"),
                parse_scalar("0x69233d2461effb6b25dbec14086d466f3bf668ef2a38759fa5cb433bedf25778"),
            ]
        );
        assert_eq!(
            hash_t3_0([from_const(1), from_const(2)]),
            parse_scalar("0x2a24882111b586a835203bdeb7a97d8489e410eadf12a495624f49b729528873")
        );
    }

    #[test]
    fn test_hash_t3_3() {
        assert_eq!(
            hash_t3([from_const(3), from_const(4), from_const(5)]),
            [
                parse_scalar("0x160be03feff499f1256ce2404ff9ee026fc378b6a91d434746bab98aafaecb63"),
                parse_scalar("0x14a259b91d964d8263af60fc1325c4874c68e8fd9caef509cc07622fc17718fe"),
            ]
        );
        assert_eq!(
            hash_t3_0([from_const(3), from_const(4), from_const(5)]),
            parse_scalar("0x160be03feff499f1256ce2404ff9ee026fc378b6a91d434746bab98aafaecb63")
        );
    }

    #[test]
    fn test_hash_t3_4() {
        assert_eq!(
            hash_t3([from_const(6), from_const(7), from_const(8), from_const(9)]),
            [
                parse_scalar("0x63d491b523ae737f62f117ef5affb8353996b67034ddaeb8586b574678ab440a"),
                parse_scalar("0x531109ee099551ccea55a61f6f7cab781bf0d3d0d0c4ba032476b65d1ebb9867"),
            ]
        );
        assert_eq!(
            hash_t3_0([from_const(6), from_const(7), from_const(8), from_const(9)]),
            parse_scalar("0x63d491b523ae737f62f117ef5affb8353996b67034ddaeb8586b574678ab440a")
        );
    }

    #[test]
    fn test_hash_t3_5() {
        assert_eq!(
            hash_t3([
                from_const(10),
                from_const(11),
                from_const(12),
                from_const(13),
                from_const(14)
            ]),
            [
                parse_scalar("0x329255ad3db8a69a50a2a1f63fb4046d06d5bc6de30bf79bfe4138f4c93201df"),
                parse_scalar("0x6968c301186d76def97ee0d7bcc1f426b34df8f2e04a3afdeaa1acd8f9070d76"),
            ]
        );
        assert_eq!(
            hash_t3_0([
                from_const(10),
                from_const(11),
                from_const(12),
                from_const(13),
                from_const(14)
            ]),
            parse_scalar("0x329255ad3db8a69a50a2a1f63fb4046d06d5bc6de30bf79bfe4138f4c93201df")
        );
    }

    #[test]
    fn test_hash_t4_1() {
        assert_eq!(
            hash_t4([from_const(42)]),
            [
                parse_scalar("0x109a9fd885b0047b036489dad6d0ca97749f6a9b21d9fc2c1cb7d25952e453a0"),
                parse_scalar("0x203e5346a31efe538f826a34e87c285ef6cfe0ce12a0316a25cbd4e2326abd29"),
                parse_scalar("0x4c53083849aedf3e11959d1dad010d2f1d2951adfdcce95f6a480666e63c5834"),
            ]
        );
        assert_eq!(
            hash_t4_0([from_const(42)]),
            parse_scalar("0x109a9fd885b0047b036489dad6d0ca97749f6a9b21d9fc2c1cb7d25952e453a0")
        );
    }

    #[test]
    fn test_hash_t4_2() {
        assert_eq!(
            hash_t4([from_const(1), from_const(2)]),
            [
                parse_scalar("0x7c4e380d8a3935c0e8073420573f5b6aaf9ed2c727afc4da64f12401ab355faf"),
                parse_scalar("0x14b0dda71f3fb062cc99121629f080541891b8be0e65ba858906cf0b648042ac"),
                parse_scalar("0x5218f71044490008f3713824dfa6be57a708ad295ca8df9fb4176340d61fb681"),
            ]
        );
        assert_eq!(
            hash_t4_0([from_const(1), from_const(2)]),
            parse_scalar("0x7c4e380d8a3935c0e8073420573f5b6aaf9ed2c727afc4da64f12401ab355faf")
        );
    }

    #[test]
    fn test_hash_t4_3() {
        assert_eq!(
            hash_t4([from_const(3), from_const(4), from_const(5)]),
            [
                parse_scalar("0x2582eca7bed4bca9d4326a9e2ca601e0b3779582bb5173318a4e19ab005e7495"),
                parse_scalar("0x0307db21c6063767f309fb09afcc4f250cbaed3f1d0870cd56d3276b18ced8d5"),
                parse_scalar("0x3024913685a18187c7ae50f1dcabe3ea2acb407fc3abd5d107bd79f3dbd2e90c"),
            ]
        );
        assert_eq!(
            hash_t4_0([from_const(3), from_const(4), from_const(5)]),
            parse_scalar("0x2582eca7bed4bca9d4326a9e2ca601e0b3779582bb5173318a4e19ab005e7495")
        );
    }

    #[test]
    fn test_hash_t4_4() {
        assert_eq!(
            hash_t4([from_const(6), from_const(7), from_const(8), from_const(9)]),
            [
                parse_scalar("0x6b13720a0ebd34f13327023c0232a3a3421f88d50b627bacfd114491ae48bfaa"),
                parse_scalar("0x235d36a318fbc8175bce6613d8b8812a1d8ab17c56a70565f8eb1253a248f5d0"),
                parse_scalar("0x379747ade21215413ccf1e1d91c7f367e1d5d8cd3e52b24da10e080dc8b25c43"),
            ]
        );
        assert_eq!(
            hash_t4_0([from_const(6), from_const(7), from_const(8), from_const(9)]),
            parse_scalar("0x6b13720a0ebd34f13327023c0232a3a3421f88d50b627bacfd114491ae48bfaa")
        );
    }

    #[test]
    fn test_hash_t4_5() {
        assert_eq!(
            hash_t4([
                from_const(10),
                from_const(11),
                from_const(12),
                from_const(13),
                from_const(14)
            ]),
            [
                parse_scalar("0x4f07a42cf3cd73f35eeb9b42bff06b11e1c7ebe0fd8f65b7fab0dd5d551f1c6c"),
                parse_scalar("0x2507a1f641f6bab3bb2cc40cb6d14df149aeede849a53a4590d73b0d29af2d71"),
                parse_scalar("0x79f1da2d204aa97c4256d321055eac279959efeff119a32e106220ef69699d4f"),
            ]
        );
        assert_eq!(
            hash_t4_0([
                from_const(10),
                from_const(11),
                from_const(12),
                from_const(13),
                from_const(14)
            ]),
            parse_scalar("0x4f07a42cf3cd73f35eeb9b42bff06b11e1c7ebe0fd8f65b7fab0dd5d551f1c6c")
        );
    }
}
