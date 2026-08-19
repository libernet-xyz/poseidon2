use crate::params::decode_constants;
use crate::poseidon;
use starkom_ff::Field;
use starkom_goldilocks::Scalar;
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
    use starkom_goldilocks::{from_const, parse_scalar};

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

    fn range(n: u64) -> Vec<Scalar> {
        (0..n).map(from_const).collect()
    }

    #[test]
    fn test_permutation_t12() {
        assert_eq!(
            poseidon::permutation::<GoldilocksConfig12, Scalar, 12>(range(12).try_into().unwrap()),
            [
                parse_scalar("0x83afdd42ec7645d7"),
                parse_scalar("0x092cbaa0e21e1d83"),
                parse_scalar("0x6df84f1f32b4720b"),
                parse_scalar("0x98a543e21ad05c27"),
                parse_scalar("0x07298e370c4bf74e"),
                parse_scalar("0x807ed30ea66099ee"),
                parse_scalar("0xec8aadab01a62399"),
                parse_scalar("0x7dfd4c39a3b4fc98"),
                parse_scalar("0x836cdc7dd9ad04f2"),
                parse_scalar("0x3dee2d6970fe4336"),
                parse_scalar("0x857f6f6888538e7c"),
                parse_scalar("0x93d6becbbbd67b8e"),
            ]
        );
    }

    #[test]
    fn test_permutation_t16() {
        assert_eq!(
            poseidon::permutation::<GoldilocksConfig16, Scalar, 16>(range(16).try_into().unwrap()),
            [
                parse_scalar("0x10024b9eb9f64cd1"),
                parse_scalar("0xfa89f7418f9d479c"),
                parse_scalar("0x0ecb7dcb9b22c92d"),
                parse_scalar("0xffa6268a75d846a4"),
                parse_scalar("0xf9c7a65b439bcd88"),
                parse_scalar("0x27a2f3a9a5be47f6"),
                parse_scalar("0x192e5eebbbb47661"),
                parse_scalar("0x002ec9cb3950c560"),
                parse_scalar("0x8ea36442548557f8"),
                parse_scalar("0x52b5dc115287e718"),
                parse_scalar("0xc7b8b286d08fe4a4"),
                parse_scalar("0xec3d42eef2d79fda"),
                parse_scalar("0x2be14ebd711a5ce7"),
                parse_scalar("0xa335679899fbcc47"),
                parse_scalar("0xeccce7e356ebf7ef"),
                parse_scalar("0xd74bb9263dfc66a0"),
            ]
        );
    }

    #[test]
    fn test_hash_t12_1() {
        assert_eq!(
            hash_t12(range(1)),
            [
                parse_scalar("0x5fbfe728b8a1fb59"),
                parse_scalar("0xef77815bdf0b9b9f"),
                parse_scalar("0x7db2967fcf5771db"),
                parse_scalar("0x96a346384def5d20"),
                parse_scalar("0x34b984c3cea94f3b"),
                parse_scalar("0x07e084eda69444e1"),
                parse_scalar("0xd2ec36ea39529f27"),
                parse_scalar("0x965af0bded9c4fd5"),
            ]
        );
        assert_eq!(hash_t12_0(range(1)), parse_scalar("0x5fbfe728b8a1fb59"));
    }

    #[test]
    fn test_hash_t12_2() {
        assert_eq!(
            hash_t12(range(2)),
            [
                parse_scalar("0x7d12b4ddb0f85ecd"),
                parse_scalar("0xaa632cfc56eb0927"),
                parse_scalar("0x33b824c37ec2f263"),
                parse_scalar("0x36273da74d0f1d17"),
                parse_scalar("0xcc25ec737b10fbe6"),
                parse_scalar("0x284c6e36da668fe8"),
                parse_scalar("0x56b85ae4475d2622"),
                parse_scalar("0x789f9bda9efccfa0"),
            ]
        );
        assert_eq!(hash_t12_0(range(2)), parse_scalar("0x7d12b4ddb0f85ecd"));
    }

    #[test]
    fn test_hash_t12_8() {
        assert_eq!(
            hash_t12(range(8)),
            [
                parse_scalar("0x81fabe8c9821bfa1"),
                parse_scalar("0x5fa60665043fa510"),
                parse_scalar("0xec121cfcb1e1ab33"),
                parse_scalar("0x8d1a1547f160fdc8"),
                parse_scalar("0xf61eca233f73f05d"),
                parse_scalar("0x2c8ab02701147874"),
                parse_scalar("0xef2f079eb545f108"),
                parse_scalar("0x67024ab3eabdb3bd"),
            ]
        );
        assert_eq!(hash_t12_0(range(8)), parse_scalar("0x81fabe8c9821bfa1"));
    }

    #[test]
    fn test_hash_t12_9() {
        assert_eq!(
            hash_t12(range(9)),
            [
                parse_scalar("0x7b2d6c3207bdee19"),
                parse_scalar("0x38f8710a8a93e0ae"),
                parse_scalar("0xe2abd7d65627748c"),
                parse_scalar("0x6b8ee663f8807881"),
                parse_scalar("0xba2218edc14fe418"),
                parse_scalar("0x71ad72ba3d3b41bd"),
                parse_scalar("0xef5bf1af28d1ceb4"),
                parse_scalar("0xfb6d30a602e7e207"),
            ]
        );
        assert_eq!(hash_t12_0(range(9)), parse_scalar("0x7b2d6c3207bdee19"));
    }

    #[test]
    fn test_hash_t12_11() {
        assert_eq!(
            hash_t12(range(11)),
            [
                parse_scalar("0xb07467623f6bd7fc"),
                parse_scalar("0x896e7b099938993d"),
                parse_scalar("0x41b132d85477960c"),
                parse_scalar("0x39bbd81feb63b840"),
                parse_scalar("0x3ebb88384b2e1700"),
                parse_scalar("0x3ea239978df23985"),
                parse_scalar("0xd19f3dee7eff6d68"),
                parse_scalar("0xf6311ee5273cdaaa"),
            ]
        );
        assert_eq!(hash_t12_0(range(11)), parse_scalar("0xb07467623f6bd7fc"));
    }

    #[test]
    fn test_hash_t12_12() {
        assert_eq!(
            hash_t12(range(12)),
            [
                parse_scalar("0x91dc4082eb7c6883"),
                parse_scalar("0x2f999107df4f0b23"),
                parse_scalar("0xee50218d3a248b76"),
                parse_scalar("0xb6b084e51754ebc9"),
                parse_scalar("0xb3b7b553e70166d0"),
                parse_scalar("0xb1ce553a39706ed6"),
                parse_scalar("0xf012f70fdc7a86aa"),
                parse_scalar("0x9cded02ec645ad55"),
            ]
        );
        assert_eq!(hash_t12_0(range(12)), parse_scalar("0x91dc4082eb7c6883"));
    }

    #[test]
    fn test_hash_t12_13() {
        assert_eq!(
            hash_t12(range(13)),
            [
                parse_scalar("0x93d27c619322458d"),
                parse_scalar("0xdeb2172cbacb5f3f"),
                parse_scalar("0x19240fe12953063d"),
                parse_scalar("0x5838bdd2f599a0be"),
                parse_scalar("0x1b893d092634d93a"),
                parse_scalar("0xadd75164132618e2"),
                parse_scalar("0x6074caef40b99eb9"),
                parse_scalar("0xdbb78e18635d5db0"),
            ]
        );
        assert_eq!(hash_t12_0(range(13)), parse_scalar("0x93d27c619322458d"));
    }

    #[test]
    fn test_hash_t16_1() {
        assert_eq!(
            hash_t16(range(1)),
            [
                parse_scalar("0x3bfa4620b337d11c"),
                parse_scalar("0x446acd82ab22c1bc"),
                parse_scalar("0x42d27a5756d6ed8e"),
                parse_scalar("0xf252e212a45bc94d"),
                parse_scalar("0x6e83369f856f076d"),
                parse_scalar("0x565c6f03b223efd9"),
                parse_scalar("0x589a649f740ede28"),
                parse_scalar("0xe0182d130a9bbed6"),
                parse_scalar("0x2b4d212623421fa3"),
                parse_scalar("0xe44747fb2a5e51ac"),
                parse_scalar("0x7f3bc7fe80be7619"),
                parse_scalar("0x0b995138285dffcb"),
            ]
        );
        assert_eq!(hash_t16_0(range(1)), parse_scalar("0x3bfa4620b337d11c"));
    }

    #[test]
    fn test_hash_t16_2() {
        assert_eq!(
            hash_t16(range(2)),
            [
                parse_scalar("0x983a0c56ea4071fa"),
                parse_scalar("0x07bf94787e10e847"),
                parse_scalar("0x0c1d48fd9c072164"),
                parse_scalar("0xb7ee90a897b6e50e"),
                parse_scalar("0x8878f8a5177a3d9f"),
                parse_scalar("0x4490d5f67a694d0f"),
                parse_scalar("0x933c4459983e9cc4"),
                parse_scalar("0x38b43a68f04db485"),
                parse_scalar("0x18087a3affd1078c"),
                parse_scalar("0x7e9ed1d490a397d0"),
                parse_scalar("0xdc8f41e125325fb6"),
                parse_scalar("0xd3fa0f21937718e2"),
            ]
        );
        assert_eq!(hash_t16_0(range(2)), parse_scalar("0x983a0c56ea4071fa"));
    }

    #[test]
    fn test_hash_t16_12() {
        assert_eq!(
            hash_t16(range(12)),
            [
                parse_scalar("0x0ea14665a5756f15"),
                parse_scalar("0xa8c65783281f2199"),
                parse_scalar("0xa5474a96ba0f7b5a"),
                parse_scalar("0x9fe37c0110a6bffd"),
                parse_scalar("0xe7c0e2c3c51fdbfa"),
                parse_scalar("0x85562c67ff83f345"),
                parse_scalar("0x7cb716146e3d8a3b"),
                parse_scalar("0xf86dd8318940da6b"),
                parse_scalar("0xf4c68c2c08b32e22"),
                parse_scalar("0xda2c3b1e89abf8d9"),
                parse_scalar("0x8cf600ecbd4fc35b"),
                parse_scalar("0x94686ea31af4d3a9"),
            ]
        );
        assert_eq!(hash_t16_0(range(12)), parse_scalar("0x0ea14665a5756f15"));
    }

    #[test]
    fn test_hash_t16_13() {
        assert_eq!(
            hash_t16(range(13)),
            [
                parse_scalar("0xe1c3425e8f847ab5"),
                parse_scalar("0x30ec5d6da62b133a"),
                parse_scalar("0xa46e93a898776814"),
                parse_scalar("0x5992df90fa4d58c4"),
                parse_scalar("0xb5293b8e07b7939b"),
                parse_scalar("0xef77911dbf6f74f4"),
                parse_scalar("0x4e90e412d557f90e"),
                parse_scalar("0x9845d6a2fd2e2f7b"),
                parse_scalar("0x5432377fc2b0aa51"),
                parse_scalar("0x713f5077b860e8c0"),
                parse_scalar("0x8d9575c1d498be2d"),
                parse_scalar("0x82c97bc7d2a630e2"),
            ]
        );
        assert_eq!(hash_t16_0(range(13)), parse_scalar("0xe1c3425e8f847ab5"));
    }

    #[test]
    fn test_hash_t16_15() {
        assert_eq!(
            hash_t16(range(15)),
            [
                parse_scalar("0x70ed8ed4286b6443"),
                parse_scalar("0xbd899d95f78c7145"),
                parse_scalar("0x2d90d17b61bc3c42"),
                parse_scalar("0x9804f01022bed07b"),
                parse_scalar("0xacd7f440a1e33771"),
                parse_scalar("0x1b6dbcfe7d94f2e9"),
                parse_scalar("0x15c5358fe019dcdd"),
                parse_scalar("0xb2e3dee891dedc6f"),
                parse_scalar("0x311bcdef38e9ae36"),
                parse_scalar("0x2e70e09cf52c6bfa"),
                parse_scalar("0xe0faa878c243a7dd"),
                parse_scalar("0x9f6d26bdcfbb5aa6"),
            ]
        );
        assert_eq!(hash_t16_0(range(15)), parse_scalar("0x70ed8ed4286b6443"));
    }

    #[test]
    fn test_hash_t16_16() {
        assert_eq!(
            hash_t16(range(16)),
            [
                parse_scalar("0x528d190d7bd06109"),
                parse_scalar("0x4ebbe5e10533b111"),
                parse_scalar("0xeeb93f3cf2b3ebf3"),
                parse_scalar("0xa66e7dbb84d6b0d7"),
                parse_scalar("0xe3b72c2725968d02"),
                parse_scalar("0x9eb6245959cfd417"),
                parse_scalar("0x8afb9de506285cc4"),
                parse_scalar("0x936f30fca079f285"),
                parse_scalar("0xeae3efcfd7e0f4c0"),
                parse_scalar("0x9b3dc9dfd33551c0"),
                parse_scalar("0xe1d02f172d55253d"),
                parse_scalar("0x7ef9f4accf40fb83"),
            ]
        );
        assert_eq!(hash_t16_0(range(16)), parse_scalar("0x528d190d7bd06109"));
    }

    #[test]
    fn test_hash_t16_17() {
        assert_eq!(
            hash_t16(range(17)),
            [
                parse_scalar("0x47a25187f0084c09"),
                parse_scalar("0xfc11953f53b00c75"),
                parse_scalar("0x03260122113b3dae"),
                parse_scalar("0xb07d06a0db72439f"),
                parse_scalar("0x275c1a68a248f6e1"),
                parse_scalar("0x8bac8cfd21f8492e"),
                parse_scalar("0xc4763bc45f45dd40"),
                parse_scalar("0xa1eb8c58c6f47de4"),
                parse_scalar("0xe996d220a9ccac95"),
                parse_scalar("0x88a30cfac44edb06"),
                parse_scalar("0xcc5e2f0fa324cd7b"),
                parse_scalar("0x71093265e8753edb"),
            ]
        );
        assert_eq!(hash_t16_0(range(17)), parse_scalar("0x47a25187f0084c09"));
    }
}
