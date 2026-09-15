use crate::params::decode_constants;
use crate::poseidon;
use starkom_schraderbrau::Scalar;
use std::sync::LazyLock;

/// Poseidon configuration for the BLS12-381 scalar field.
pub struct SchraderbrauConfig<const T: usize> {}

impl poseidon::Config<Scalar, 3> for SchraderbrauConfig<3> {
    fn num_full_rounds() -> usize {
        4
    }

    fn num_partial_rounds() -> usize {
        83
    }

    fn get_round_constants() -> &'static [Scalar] {
        static ROUND_CONSTANTS: LazyLock<[Scalar; 273]> = LazyLock::new(|| {
            let bytes = include_bytes!("../params/schraderbrau/arc_t3.bin");
            decode_constants::<Scalar, 273>(bytes)
        });
        &*ROUND_CONSTANTS
    }

    fn get_external_matrix() -> &'static [Scalar] {
        static MATRIX: LazyLock<[Scalar; 9]> = LazyLock::new(|| {
            let bytes = include_bytes!("../params/schraderbrau/fl_t3.bin");
            decode_constants::<Scalar, 9>(bytes)
        });
        &*MATRIX
    }

    fn get_internal_matrix() -> &'static [Scalar] {
        static MATRIX: LazyLock<[Scalar; 9]> = LazyLock::new(|| {
            let bytes = include_bytes!("../params/schraderbrau/pl_t3.bin");
            decode_constants::<Scalar, 9>(bytes)
        });
        &*MATRIX
    }
}

impl poseidon::Config<Scalar, 4> for SchraderbrauConfig<4> {
    fn num_full_rounds() -> usize {
        4
    }

    fn num_partial_rounds() -> usize {
        84
    }

    fn get_round_constants() -> &'static [Scalar] {
        static ROUND_CONSTANTS: LazyLock<[Scalar; 368]> = LazyLock::new(|| {
            let bytes = include_bytes!("../params/schraderbrau/arc_t4.bin");
            decode_constants::<Scalar, 368>(bytes)
        });
        &*ROUND_CONSTANTS
    }

    fn get_external_matrix() -> &'static [Scalar] {
        static MATRIX: LazyLock<[Scalar; 16]> = LazyLock::new(|| {
            let bytes = include_bytes!("../params/schraderbrau/fl_t4.bin");
            decode_constants::<Scalar, 16>(bytes)
        });
        &*MATRIX
    }

    fn get_internal_matrix() -> &'static [Scalar] {
        static MATRIX: LazyLock<[Scalar; 16]> = LazyLock::new(|| {
            let bytes = include_bytes!("../params/schraderbrau/pl_t4.bin");
            decode_constants::<Scalar, 16>(bytes)
        });
        &*MATRIX
    }
}

/// Poseidon configuration for BLS12-381 with T=3.
pub type SchraderbrauConfig3 = SchraderbrauConfig<3>;

/// Poseidon configuration for BLS12-381 with T=4.
pub type SchraderbrauConfig4 = SchraderbrauConfig<4>;

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_scalar(s: &'static str) -> Scalar {
        s.parse().unwrap()
    }

    fn hash_t3(inputs: impl IntoIterator<Item = Scalar>) -> [Scalar; 2] {
        poseidon::hash::<SchraderbrauConfig3, Scalar, 3, 2, 1>(inputs)
    }

    fn hash_t3_0(inputs: impl IntoIterator<Item = Scalar>) -> Scalar {
        poseidon::hash0::<SchraderbrauConfig3, Scalar, 3, 2, 1>(inputs)
    }

    fn hash_t4(inputs: impl IntoIterator<Item = Scalar>) -> [Scalar; 3] {
        poseidon::hash::<SchraderbrauConfig4, Scalar, 4, 3, 1>(inputs)
    }

    fn hash_t4_0(inputs: impl IntoIterator<Item = Scalar>) -> Scalar {
        poseidon::hash0::<SchraderbrauConfig4, Scalar, 4, 3, 1>(inputs)
    }

    #[test]
    fn test_permutation_t3() {
        assert_eq!(
            poseidon::permutation::<SchraderbrauConfig3, Scalar, 3>([
                Scalar::from_const(0),
                Scalar::from_const(1),
                Scalar::from_const(2)
            ]),
            [
                parse_scalar("0x4944db4e43f190b4efd2383ca68fc624f8c8f1f3cd6396aaccdc9f964011998b"),
                parse_scalar("0x48f659c353026326543ca20d6162afc5e2dc6871444e3271c500d9fd9a203ba3"),
                parse_scalar("0x264f179e410ea3505c03b2f726e8229a16bc796f0213ca5e325324f4407e1d43"),
            ]
        );
    }

    #[test]
    fn test_permutation_t4() {
        assert_eq!(
            poseidon::permutation::<SchraderbrauConfig4, Scalar, 4>([
                Scalar::from_const(0),
                Scalar::from_const(1),
                Scalar::from_const(2),
                Scalar::from_const(3)
            ]),
            [
                parse_scalar("0x0ed3f04e32c5a56b534177f0d5080e7808eb14b0e5a00087a8d9c1b31e15caa3"),
                parse_scalar("0x41cfd908539849048aa49853ffc331f6610ac53030220809863e41d3ccbd2db0"),
                parse_scalar("0x75b114742d553230c8d4aa77788c3c3eba96af41a79c6f43f1dbd500110facac"),
                parse_scalar("0x240692e1b40ee3a80e4ec79414f815d291866e817e59abee4d23d99cd547b8c7"),
            ]
        );
    }

    #[test]
    fn test_hash_t3_1() {
        assert_eq!(
            hash_t3([Scalar::from_const(42)]),
            [
                parse_scalar("0x43cee82d1d9567e7124e1875c4fa74738c7c5f8cec8c9c5f6e9fe168a76da12b"),
                parse_scalar("0x4d953876c095b0ee8808eca1337215d61c569fb3dd30fe16068e522102d654d1"),
            ]
        );
        assert_eq!(
            hash_t3_0([Scalar::from_const(42)]),
            parse_scalar("0x43cee82d1d9567e7124e1875c4fa74738c7c5f8cec8c9c5f6e9fe168a76da12b")
        );
    }

    #[test]
    fn test_hash_t3_2() {
        assert_eq!(
            hash_t3([Scalar::from_const(1), Scalar::from_const(2)]),
            [
                parse_scalar("0x7e57592e1ac7541299aa96f51914caf5727c120411a04ebfe2996c661386a21b"),
                parse_scalar("0x6b8a433946ec7e7aa0490e0bced41e3ef878feb7667c8e9a76f49d1c4928127d"),
            ]
        );
        assert_eq!(
            hash_t3_0([Scalar::from_const(1), Scalar::from_const(2)]),
            parse_scalar("0x7e57592e1ac7541299aa96f51914caf5727c120411a04ebfe2996c661386a21b")
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
                parse_scalar("0x621890a3340e88c6cbd889417ca2b91fb96edbd2f65a10a5910284836cba656f"),
                parse_scalar("0x4905c4a352631b77f16e996a3b695c7b2c450b99521caa79a1a706d9ca5dfb98"),
            ]
        );
        assert_eq!(
            hash_t3_0([
                Scalar::from_const(3),
                Scalar::from_const(4),
                Scalar::from_const(5)
            ]),
            parse_scalar("0x621890a3340e88c6cbd889417ca2b91fb96edbd2f65a10a5910284836cba656f")
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
                parse_scalar("0x4d398a6ce6becce23101ef0b26b46b655dac61f736535f850136b292f4f74859"),
                parse_scalar("0x5a61ae517910b94f1316a37850a35a45dc3bd0fed50b71656f26c68ad047e244"),
            ]
        );
        assert_eq!(
            hash_t3_0([
                Scalar::from_const(6),
                Scalar::from_const(7),
                Scalar::from_const(8),
                Scalar::from_const(9)
            ]),
            parse_scalar("0x4d398a6ce6becce23101ef0b26b46b655dac61f736535f850136b292f4f74859")
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
                parse_scalar("0x43d55d84a2d4589584fe788c394f274b04fc4916c8d6039d95c278e36f8403ef"),
                parse_scalar("0x4192d51c36319b49ff1ebff9bcffd8143047d9d94b09ee8d78abd9dcd8e17398"),
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
            parse_scalar("0x43d55d84a2d4589584fe788c394f274b04fc4916c8d6039d95c278e36f8403ef")
        );
    }

    #[test]
    fn test_hash_t4_1() {
        assert_eq!(
            hash_t4([Scalar::from_const(42)]),
            [
                parse_scalar("0x3d5e1194154805c8ecfeaad6b518bb60d85318836d9e873b1daed9d18f5dc7c7"),
                parse_scalar("0x1ac43457c33e27c034bf7e59b1f2b5cf3ab5aa77fc1003a2e26e0dd9ef7b1de4"),
                parse_scalar("0x255288a78acdc8555b15147772df3e64e10d8ff07520e7a6c23f9a34052fe2b7"),
            ]
        );
        assert_eq!(
            hash_t4_0([Scalar::from_const(42)]),
            parse_scalar("0x3d5e1194154805c8ecfeaad6b518bb60d85318836d9e873b1daed9d18f5dc7c7")
        );
    }

    #[test]
    fn test_hash_t4_2() {
        assert_eq!(
            hash_t4([Scalar::from_const(1), Scalar::from_const(2)]),
            [
                parse_scalar("0x34a242785db476aef95ce1eb05d11f57102c9c10f27acab6011b6a85364a98ae"),
                parse_scalar("0x544420315fdc1a2a0b776a269978ad0c3c65e4582bc43e8769cc9f8c69a7cd6a"),
                parse_scalar("0x7f2cd57a389efa07421a398fd0e92801f9602f76e36378aa20f5191b9e2eccb9"),
            ]
        );
        assert_eq!(
            hash_t4_0([Scalar::from_const(1), Scalar::from_const(2)]),
            parse_scalar("0x34a242785db476aef95ce1eb05d11f57102c9c10f27acab6011b6a85364a98ae")
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
                parse_scalar("0x39cdfcc63334e8a62fc9f52340145efe1ac8b4e08f760c6b0625ccb9b8e719cf"),
                parse_scalar("0x7f7a67beadd122399eaef86831b4bf90e432ff59c0be7c3d60b74495d719180e"),
                parse_scalar("0x06b406d2b4106c4047f257fb2228db019af3d741c5d5ebfa71df4df49886b1bb"),
            ]
        );
        assert_eq!(
            hash_t4_0([
                Scalar::from_const(3),
                Scalar::from_const(4),
                Scalar::from_const(5)
            ]),
            parse_scalar("0x39cdfcc63334e8a62fc9f52340145efe1ac8b4e08f760c6b0625ccb9b8e719cf")
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
                parse_scalar("0x7c3ab769350cff61e7b8da9b96e29a429e88abd0747567dbcc5470e889be3bc5"),
                parse_scalar("0x35b939fd3095f10d56f1c5f3b0e245319029dc6699f76c76f99edfc1cbf89d02"),
                parse_scalar("0x2f2b87d7269c5776bee6731eb3702ee9c6e125786b5ba26635089e42afd59234"),
            ]
        );
        assert_eq!(
            hash_t4_0([
                Scalar::from_const(6),
                Scalar::from_const(7),
                Scalar::from_const(8),
                Scalar::from_const(9)
            ]),
            parse_scalar("0x7c3ab769350cff61e7b8da9b96e29a429e88abd0747567dbcc5470e889be3bc5")
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
                parse_scalar("0x009c475906d811f00b6666d64f3a55f615727943802376e96acc3f591fdccc58"),
                parse_scalar("0x086175f4eae6c9816ca2952d05c2b65807aafcaca4b71addf153265459f47f68"),
                parse_scalar("0x362bd077b86daddb89be4924a5ccff2be4cb59d971f55422b58dc63229e4ab52"),
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
            parse_scalar("0x009c475906d811f00b6666d64f3a55f615727943802376e96acc3f591fdccc58")
        );
    }
}
