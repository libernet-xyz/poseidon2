use crate::poseidon::{Config, permutation};
use anyhow::{Result, anyhow};
use primitive_types::H512;
use sha3::{self, Digest};
use starkom_ff::PrimeField256;
use std::marker::PhantomData;

fn iv_element<F: PrimeField256>(index: usize) -> F {
    let mut hasher = sha3::Sha3_512::new();
    hasher.update(format!("starkom/poseidon/cipher/{}", index).as_bytes());
    F::from_h512(H512::from_slice(hasher.finalize().as_slice()))
}

fn get_initial_state<F: PrimeField256, const T: usize, const R: usize>(key: F, nonce: F) -> [F; T] {
    let mut state = [F::ZERO; T];
    for i in 0..R {
        state[i] = iv_element::<F>(i) + nonce;
    }
    state[T - 1] = key;
    state
}

/// Encrypts an arbitrary number of field elements in batches of `R` using the Poseidon permutation
/// with state size `T`.
///
/// `R` must be `T - 1` (the last element is reserved for capacity).
///
/// This symmetric cipher is implemented using the Poseidon PRP as a block cipher in duplex sponge
/// mode, which is similar to CFB. The key lives in the capacity element.
#[derive(Debug)]
pub struct Encryptor<C: Config<F, T>, F: PrimeField256, const T: usize, const R: usize> {
    nonce: F,
    state: [F; T],
    _data: PhantomData<C>,
}

impl<C: Config<F, T>, F: PrimeField256, const T: usize, const R: usize> Encryptor<C, F, T, R> {
    /// Constructs an `Encryptor` with the specified `key` and `nonce`.
    ///
    /// WARNING: NEVER reuse the same (key, nonce) pair to encrypt two or more different messages,
    /// as doing so would leak information about the plaintexts!
    pub fn with_nonce(key: F, nonce: F) -> Self {
        assert_eq!(R, T - 1);
        Self {
            nonce,
            state: get_initial_state::<F, T, R>(key, nonce),
            _data: PhantomData::default(),
        }
    }

    /// Constructs an `Encryptor` with the specified `key` and a securely generated fresh nonce.
    ///
    /// You can retrieve the nonce by calling [`Self::nonce`].
    pub fn new(key: F) -> Self {
        Self::with_nonce(key, F::random_default())
    }

    /// Returns the nonce used by the `Encryptor`.
    ///
    /// This can be transmitted publicly along with the ciphertext and will be needed to construct
    /// the [`Decryptor`].
    pub fn nonce(&self) -> F {
        self.nonce
    }

    /// Encrypts a block of `R` field elements.
    pub fn encrypt(&mut self, block: [F; R]) -> [F; R] {
        self.state = permutation::<C, F, T>(self.state);
        for i in 0..R {
            self.state[i] += block[i];
        }
        std::array::from_fn(|i| self.state[i])
    }

    /// Performs the final checksumming.
    pub fn finalize(mut self) -> F {
        self.state = permutation::<C, F, T>(self.state);
        self.state[T - 1]
    }
}

/// Decrypts an arbitrary number of field elements in batches of `R` using the Poseidon permutation
/// with state size `T`.
///
/// `R` must be `T - 1` (the last element is reserved for capacity).
///
/// This symmetric cipher is implemented using the Poseidon PRP as a block cipher in duplex sponge
/// mode, which is similar to CFB. The key lives in the capacity element.
#[derive(Debug)]
pub struct Decryptor<C: Config<F, T>, F: PrimeField256, const T: usize, const R: usize> {
    state: [F; T],
    _data: PhantomData<C>,
}

impl<C: Config<F, T>, F: PrimeField256, const T: usize, const R: usize> Decryptor<C, F, T, R> {
    /// Constructs a `Decryptor` with the specified `key` and `nonce`.
    pub fn new(key: F, nonce: F) -> Self {
        assert_eq!(R, T - 1);
        Self {
            state: get_initial_state::<F, T, R>(key, nonce),
            _data: PhantomData::default(),
        }
    }

    /// Decrypts a block of `R` field elements.
    pub fn decrypt(&mut self, mut block: [F; R]) -> [F; R] {
        self.state = permutation::<C, F, T>(self.state);
        for i in 0..R {
            let key = self.state[i];
            self.state[i] = block[i];
            block[i] -= key;
        }
        block
    }

    /// Performs the final authentication.
    pub fn finalize(mut self, checksum: F) -> Result<()> {
        self.state = permutation::<C, F, T>(self.state);
        if self.state[T - 1].ct_ne(&checksum).into() {
            return Err(anyhow!("invalid checksum {}", checksum));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bluesky::{BlueSkyConfig3, BlueSkyConfig4};
    use starkom_bluesky::{Scalar, from_const, parse_scalar};

    fn key1() -> Scalar {
        parse_scalar("0x1a06314aa2caec8bb0b56bee3c47cf459318e72181320ac9d1f3199c1704b236")
    }

    fn key2() -> Scalar {
        parse_scalar("0x02084699c3ba63bf94afa8d0830338aa8c16087f8587517d29748744a6606101")
    }

    #[test]
    fn test_encrypt_one_block_t3_key1() {
        let key = key1();
        let nonce = from_const(42);
        let mut encryptor = Encryptor::<BlueSkyConfig3, Scalar, 3, 2>::with_nonce(key, nonce);
        let block = encryptor.encrypt([from_const(12), from_const(34)]);
        let checksum = encryptor.finalize();
        assert_eq!(
            block,
            [
                parse_scalar("0x517b930ab3b2a386dc4d12d0bb7ad791fbedc97fe1efa5f1b9973da58119611a"),
                parse_scalar("0x543e4f94b8d8a4268890523ced9d826318a9d21ccb347548a97621546d8f0dc2")
            ]
        );
        assert_eq!(
            checksum,
            parse_scalar("0x5b6391b694f558e11ddaad4a677d08925cfd111ea23249cc8d1872bfc3a99994")
        );
    }

    #[test]
    fn test_encrypt_one_block_t3_key2() {
        let key = key2();
        let nonce = from_const(42);
        let mut encryptor = Encryptor::<BlueSkyConfig3, Scalar, 3, 2>::with_nonce(key, nonce);
        let block = encryptor.encrypt([from_const(12), from_const(34)]);
        let checksum = encryptor.finalize();
        assert_eq!(
            block,
            [
                parse_scalar("0x1c673a9c9d388a227b8662b85ff9b54daca3d0d9276b53e1a76ccee13ae622bf"),
                parse_scalar("0x7f299cd405489e55c46f2924202c99241eb461e4fc94ceaec16e03f969c428c0")
            ]
        );
        assert_eq!(
            checksum,
            parse_scalar("0x226a7e017bb1d16d0ae023561228fe28916c0355350b0b79e735797afe369d9d")
        );
    }

    #[test]
    fn test_encrypt_one_block_t3_different_nonces() {
        let key = key1();
        let mut encryptor1 = Encryptor::<BlueSkyConfig3, Scalar, 3, 2>::new(key);
        let block1 = encryptor1.encrypt([from_const(12), from_const(34)]);
        let checksum1 = encryptor1.finalize();
        let mut encryptor2 = Encryptor::<BlueSkyConfig3, Scalar, 3, 2>::new(key);
        let block2 = encryptor2.encrypt([from_const(12), from_const(34)]);
        let checksum2 = encryptor2.finalize();
        assert_ne!(block1, block2);
        assert_ne!(checksum1, checksum2);
    }

    #[test]
    fn test_encrypt_two_blocks_t3_key1() {
        let key = key1();
        let nonce = from_const(42);
        let mut encryptor = Encryptor::<BlueSkyConfig3, Scalar, 3, 2>::with_nonce(key, nonce);
        let block1 = encryptor.encrypt([from_const(34), from_const(56)]);
        let block2 = encryptor.encrypt([from_const(78), from_const(90)]);
        let checksum = encryptor.finalize();
        assert_eq!(
            block1,
            [
                parse_scalar("0x517b930ab3b2a386dc4d12d0bb7ad791fbedc97fe1efa5f1b9973da581196130"),
                parse_scalar("0x543e4f94b8d8a4268890523ced9d826318a9d21ccb347548a97621546d8f0dd8")
            ]
        );
        assert_eq!(
            block2,
            [
                parse_scalar("0x71277f403f436a8e360a10d242fdad26ca65caf5cc0076ff92c07b81ec9c396d"),
                parse_scalar("0x2036c558e00f301f5c355c2b8e8e2d6b932fddc8d383d3bae9a75a9dabd6f7c5")
            ]
        );
        assert_eq!(
            checksum,
            parse_scalar("0x3d5bb7eba76c1e722c80915577d8f55e5b50a5ccae43c45381779c7cdf989a60")
        );
    }

    #[test]
    fn test_encrypt_two_blocks_t3_key2() {
        let key = key2();
        let nonce = from_const(42);
        let mut encryptor = Encryptor::<BlueSkyConfig3, Scalar, 3, 2>::with_nonce(key, nonce);
        let block1 = encryptor.encrypt([from_const(34), from_const(56)]);
        let block2 = encryptor.encrypt([from_const(78), from_const(90)]);
        let checksum = encryptor.finalize();
        assert_eq!(
            block1,
            [
                parse_scalar("0x1c673a9c9d388a227b8662b85ff9b54daca3d0d9276b53e1a76ccee13ae622d5"),
                parse_scalar("0x7f299cd405489e55c46f2924202c99241eb461e4fc94ceaec16e03f969c428d6")
            ]
        );
        assert_eq!(
            block2,
            [
                parse_scalar("0x560a95e67eabeaeec74d5c178b57d2794c7b75b0d4d51a98f41f2f22da5da7bf"),
                parse_scalar("0x7f26d8b7e713a10ae871c1e8fa401c6fb5056181352dc2665389df962bc1746f")
            ]
        );
        assert_eq!(
            checksum,
            parse_scalar("0x18c0c56f25355b3af90260075a31df63af7a08903c64f74626663e27bc92b254")
        );
    }

    #[test]
    fn test_encrypt_two_blocks_t3_different_nonces() {
        let key = key1();
        let mut encryptor1 = Encryptor::<BlueSkyConfig3, Scalar, 3, 2>::new(key);
        let block11 = encryptor1.encrypt([from_const(34), from_const(56)]);
        let block12 = encryptor1.encrypt([from_const(78), from_const(90)]);
        let checksum1 = encryptor1.finalize();
        let mut encryptor2 = Encryptor::<BlueSkyConfig3, Scalar, 3, 2>::new(key);
        let block21 = encryptor2.encrypt([from_const(34), from_const(56)]);
        let block22 = encryptor2.encrypt([from_const(78), from_const(90)]);
        let checksum2 = encryptor2.finalize();
        assert_ne!(block11, block21);
        assert_ne!(block12, block22);
        assert_ne!(checksum1, checksum2);
    }

    #[test]
    fn test_encrypt_one_block_t4_key1() {
        let key = key1();
        let nonce = from_const(42);
        let mut encryptor = Encryptor::<BlueSkyConfig4, Scalar, 4, 3>::with_nonce(key, nonce);
        let block = encryptor.encrypt([from_const(12), from_const(34), from_const(56)]);
        let checksum = encryptor.finalize();
        assert_eq!(
            block,
            [
                parse_scalar("0x697acc6998455b102280a6197bf54d75cf403bfc3fde514fcb4db16d9abad8d6"),
                parse_scalar("0x20881f62c68cf86615d6da56bf25a0de6a1389e81f05747fc2cd380b4c3f79a9"),
                parse_scalar("0x5b71078ecb5a379b4024fed43d3cb4589cbead9951cd322271a80f1b42ddc338")
            ]
        );
        assert_eq!(
            checksum,
            parse_scalar("0x6f5cfb84280a92e1c21cb784b4c309fd2d5e616c9871f10562051f43c189ab9e")
        );
    }

    #[test]
    fn test_encrypt_one_block_t4_key2() {
        let key = key2();
        let nonce = from_const(42);
        let mut encryptor = Encryptor::<BlueSkyConfig4, Scalar, 4, 3>::with_nonce(key, nonce);
        let block = encryptor.encrypt([from_const(12), from_const(34), from_const(56)]);
        let checksum = encryptor.finalize();
        assert_eq!(
            block,
            [
                parse_scalar("0x63e00ef04a2b788de94cd0a9c2bf95b84c24842739cb242027d4697405271193"),
                parse_scalar("0x5affa0dfe232d32a1562f92f29c1b2b2c41634bf780a65bfde1da41e8a171e89"),
                parse_scalar("0x663685c0033b4ad98ad30accb5843d04205cefcfed2c2db31433173c6785e905")
            ]
        );
        assert_eq!(
            checksum,
            parse_scalar("0x69c5e38879841004f277b589fe7ca54fdc64ab735b7e810d583e3ff2ba13a627")
        );
    }

    #[test]
    fn test_encrypt_one_block_t4_different_nonces() {
        let key = key1();
        let mut encryptor1 = Encryptor::<BlueSkyConfig4, Scalar, 4, 3>::new(key);
        let block1 = encryptor1.encrypt([from_const(12), from_const(34), from_const(56)]);
        let checksum1 = encryptor1.finalize();
        let mut encryptor2 = Encryptor::<BlueSkyConfig4, Scalar, 4, 3>::new(key);
        let block2 = encryptor2.encrypt([from_const(12), from_const(34), from_const(56)]);
        let checksum2 = encryptor2.finalize();
        assert_ne!(block1, block2);
        assert_ne!(checksum1, checksum2);
    }

    #[test]
    fn test_encrypt_two_blocks_t4_key1() {
        let key = key1();
        let nonce = from_const(42);
        let mut encryptor = Encryptor::<BlueSkyConfig4, Scalar, 4, 3>::with_nonce(key, nonce);
        let block1 = encryptor.encrypt([from_const(34), from_const(56), from_const(78)]);
        let block2 = encryptor.encrypt([from_const(90), from_const(112), from_const(134)]);
        let checksum = encryptor.finalize();
        assert_eq!(
            block1,
            [
                parse_scalar("0x697acc6998455b102280a6197bf54d75cf403bfc3fde514fcb4db16d9abad8ec"),
                parse_scalar("0x20881f62c68cf86615d6da56bf25a0de6a1389e81f05747fc2cd380b4c3f79bf"),
                parse_scalar("0x5b71078ecb5a379b4024fed43d3cb4589cbead9951cd322271a80f1b42ddc34e")
            ]
        );
        assert_eq!(
            block2,
            [
                parse_scalar("0x21740083f8b867fe8019d70c7b747c510b2781803aabe3b2c5c97e9926e1b0a8"),
                parse_scalar("0x46c79bf95f11972dda3e0aa33cc6a44de0f1d00f593cb36693c8821b63a9eefe"),
                parse_scalar("0x1bcd1ec59363c5089ead0cda525aeb540d7f611744aa54d2540b89f112829fe9"),
            ]
        );
        assert_eq!(
            checksum,
            parse_scalar("0x4bb9448b23695d5cc8990e21bda2369e75952addb31447210386714a5833bbea")
        );
    }

    #[test]
    fn test_encrypt_two_blocks_t4_key2() {
        let key = key2();
        let nonce = from_const(42);
        let mut encryptor = Encryptor::<BlueSkyConfig4, Scalar, 4, 3>::with_nonce(key, nonce);
        let block1 = encryptor.encrypt([from_const(34), from_const(56), from_const(78)]);
        let block2 = encryptor.encrypt([from_const(90), from_const(112), from_const(134)]);
        let checksum = encryptor.finalize();
        assert_eq!(
            block1,
            [
                parse_scalar("0x63e00ef04a2b788de94cd0a9c2bf95b84c24842739cb242027d46974052711a9"),
                parse_scalar("0x5affa0dfe232d32a1562f92f29c1b2b2c41634bf780a65bfde1da41e8a171e9f"),
                parse_scalar("0x663685c0033b4ad98ad30accb5843d04205cefcfed2c2db31433173c6785e91b")
            ]
        );
        assert_eq!(
            block2,
            [
                parse_scalar("0x7e5da887f98421930029cfb9e3845ce64fb0376e72a614a71bd25a6e9aaa7615"),
                parse_scalar("0x4b7025a627765857a0a2c8143a10ff69b2cff544a1ed9939f48d9e62fc39eeea"),
                parse_scalar("0x74a366c61fe140125e7d3275b0f34489e3e1d885a25bc2e8f0f5967da99a2efd")
            ]
        );
        assert_eq!(
            checksum,
            parse_scalar("0x0f132cd0744ab5311ae1fff1b8f254fda8c203a0e9d709299ef32c6bafa5d547")
        );
    }

    #[test]
    fn test_encrypt_two_blocks_t4_different_nonces() {
        let key = key1();
        let mut encryptor1 = Encryptor::<BlueSkyConfig4, Scalar, 4, 3>::new(key);
        let block11 = encryptor1.encrypt([from_const(34), from_const(56), from_const(78)]);
        let block12 = encryptor1.encrypt([from_const(90), from_const(112), from_const(134)]);
        let checksum1 = encryptor1.finalize();
        let mut encryptor2 = Encryptor::<BlueSkyConfig4, Scalar, 4, 3>::new(key);
        let block21 = encryptor2.encrypt([from_const(34), from_const(56), from_const(78)]);
        let block22 = encryptor2.encrypt([from_const(90), from_const(112), from_const(134)]);
        let checksum2 = encryptor2.finalize();
        assert_ne!(block11, block21);
        assert_ne!(block12, block22);
        assert_ne!(checksum1, checksum2);
    }

    #[test]
    fn test_decrypt_one_block_t3_key1() {
        let key = key1();
        let nonce = from_const(42);
        let mut encryptor = Encryptor::<BlueSkyConfig3, Scalar, 3, 2>::with_nonce(key, nonce);
        let ciphertext = encryptor.encrypt([from_const(12), from_const(34)]);
        let checksum = encryptor.finalize();
        let mut decryptor = Decryptor::<BlueSkyConfig3, Scalar, 3, 2>::new(key, nonce);
        let plaintext = decryptor.decrypt(ciphertext);
        assert!(decryptor.finalize(checksum).is_ok());
        assert_eq!(plaintext, [from_const(12), from_const(34)]);
    }

    #[test]
    fn test_decrypt_one_block_t3_key2() {
        let key = key2();
        let nonce = from_const(42);
        let mut encryptor = Encryptor::<BlueSkyConfig3, Scalar, 3, 2>::with_nonce(key, nonce);
        let ciphertext = encryptor.encrypt([from_const(12), from_const(34)]);
        let checksum = encryptor.finalize();
        let mut decryptor = Decryptor::<BlueSkyConfig3, Scalar, 3, 2>::new(key, nonce);
        let plaintext = decryptor.decrypt(ciphertext);
        assert!(decryptor.finalize(checksum).is_ok());
        assert_eq!(plaintext, [from_const(12), from_const(34)]);
    }

    #[test]
    fn test_decrypt_one_block_t3_automatic_nonce() {
        let key = key1();
        let mut encryptor = Encryptor::<BlueSkyConfig3, Scalar, 3, 2>::new(key);
        let nonce = encryptor.nonce();
        let ciphertext = encryptor.encrypt([from_const(12), from_const(34)]);
        let checksum = encryptor.finalize();
        let mut decryptor = Decryptor::<BlueSkyConfig3, Scalar, 3, 2>::new(key, nonce);
        let plaintext = decryptor.decrypt(ciphertext);
        assert!(decryptor.finalize(checksum).is_ok());
        assert_eq!(plaintext, [from_const(12), from_const(34)]);
    }

    #[test]
    fn test_decrypt_two_blocks_t3_key1() {
        let key = key1();
        let nonce = from_const(42);
        let mut encryptor = Encryptor::<BlueSkyConfig3, Scalar, 3, 2>::with_nonce(key, nonce);
        let ciphertext1 = encryptor.encrypt([from_const(34), from_const(56)]);
        let ciphertext2 = encryptor.encrypt([from_const(78), from_const(90)]);
        let checksum = encryptor.finalize();
        let mut decryptor = Decryptor::<BlueSkyConfig3, Scalar, 3, 2>::new(key, nonce);
        let plaintext1 = decryptor.decrypt(ciphertext1);
        let plaintext2 = decryptor.decrypt(ciphertext2);
        assert!(decryptor.finalize(checksum).is_ok());
        assert_eq!(plaintext1, [from_const(34), from_const(56)]);
        assert_eq!(plaintext2, [from_const(78), from_const(90)]);
    }

    #[test]
    fn test_decrypt_two_blocks_t3_key2() {
        let key = key2();
        let nonce = from_const(42);
        let mut encryptor = Encryptor::<BlueSkyConfig3, Scalar, 3, 2>::with_nonce(key, nonce);
        let ciphertext1 = encryptor.encrypt([from_const(34), from_const(56)]);
        let ciphertext2 = encryptor.encrypt([from_const(78), from_const(90)]);
        let checksum = encryptor.finalize();
        let mut decryptor = Decryptor::<BlueSkyConfig3, Scalar, 3, 2>::new(key, nonce);
        let plaintext1 = decryptor.decrypt(ciphertext1);
        let plaintext2 = decryptor.decrypt(ciphertext2);
        assert!(decryptor.finalize(checksum).is_ok());
        assert_eq!(plaintext1, [from_const(34), from_const(56)]);
        assert_eq!(plaintext2, [from_const(78), from_const(90)]);
    }

    #[test]
    fn test_decrypt_two_blocks_t3_automatic_nonce() {
        let key = key1();
        let mut encryptor = Encryptor::<BlueSkyConfig3, Scalar, 3, 2>::new(key);
        let nonce = encryptor.nonce();
        let ciphertext1 = encryptor.encrypt([from_const(34), from_const(56)]);
        let ciphertext2 = encryptor.encrypt([from_const(78), from_const(90)]);
        let checksum = encryptor.finalize();
        let mut decryptor = Decryptor::<BlueSkyConfig3, Scalar, 3, 2>::new(key, nonce);
        let plaintext1 = decryptor.decrypt(ciphertext1);
        let plaintext2 = decryptor.decrypt(ciphertext2);
        assert!(decryptor.finalize(checksum).is_ok());
        assert_eq!(plaintext1, [from_const(34), from_const(56)]);
        assert_eq!(plaintext2, [from_const(78), from_const(90)]);
    }

    #[test]
    fn test_decrypt_one_block_t4_key1() {
        let key = key1();
        let nonce = from_const(42);
        let mut encryptor = Encryptor::<BlueSkyConfig4, Scalar, 4, 3>::with_nonce(key, nonce);
        let ciphertext = encryptor.encrypt([from_const(12), from_const(34), from_const(56)]);
        let checksum = encryptor.finalize();
        let mut decryptor = Decryptor::<BlueSkyConfig4, Scalar, 4, 3>::new(key, nonce);
        let plaintext = decryptor.decrypt(ciphertext);
        assert!(decryptor.finalize(checksum).is_ok());
        assert_eq!(plaintext, [from_const(12), from_const(34), from_const(56)]);
    }

    #[test]
    fn test_decrypt_one_block_t4_key2() {
        let key = key2();
        let nonce = from_const(42);
        let mut encryptor = Encryptor::<BlueSkyConfig4, Scalar, 4, 3>::with_nonce(key, nonce);
        let ciphertext = encryptor.encrypt([from_const(12), from_const(34), from_const(56)]);
        let checksum = encryptor.finalize();
        let mut decryptor = Decryptor::<BlueSkyConfig4, Scalar, 4, 3>::new(key, nonce);
        let plaintext = decryptor.decrypt(ciphertext);
        assert!(decryptor.finalize(checksum).is_ok());
        assert_eq!(plaintext, [from_const(12), from_const(34), from_const(56)]);
    }

    #[test]
    fn test_decrypt_one_block_t4_automatic_nonce() {
        let key = key1();
        let mut encryptor = Encryptor::<BlueSkyConfig4, Scalar, 4, 3>::new(key);
        let nonce = encryptor.nonce();
        let ciphertext = encryptor.encrypt([from_const(12), from_const(34), from_const(56)]);
        let checksum = encryptor.finalize();
        let mut decryptor = Decryptor::<BlueSkyConfig4, Scalar, 4, 3>::new(key, nonce);
        let plaintext = decryptor.decrypt(ciphertext);
        assert!(decryptor.finalize(checksum).is_ok());
        assert_eq!(plaintext, [from_const(12), from_const(34), from_const(56)]);
    }

    #[test]
    fn test_decrypt_two_blocks_t4_key1() {
        let key = key1();
        let nonce = from_const(42);
        let mut encryptor = Encryptor::<BlueSkyConfig4, Scalar, 4, 3>::with_nonce(key, nonce);
        let ciphertext1 = encryptor.encrypt([from_const(34), from_const(56), from_const(78)]);
        let ciphertext2 = encryptor.encrypt([from_const(90), from_const(112), from_const(134)]);
        let checksum = encryptor.finalize();
        let mut decryptor = Decryptor::<BlueSkyConfig4, Scalar, 4, 3>::new(key, nonce);
        let plaintext1 = decryptor.decrypt(ciphertext1);
        let plaintext2 = decryptor.decrypt(ciphertext2);
        assert!(decryptor.finalize(checksum).is_ok());
        assert_eq!(plaintext1, [from_const(34), from_const(56), from_const(78)]);
        assert_eq!(
            plaintext2,
            [from_const(90), from_const(112), from_const(134)]
        );
    }

    #[test]
    fn test_decrypt_two_blocks_t4_key2() {
        let key = key2();
        let nonce = from_const(42);
        let mut encryptor = Encryptor::<BlueSkyConfig4, Scalar, 4, 3>::with_nonce(key, nonce);
        let ciphertext1 = encryptor.encrypt([from_const(34), from_const(56), from_const(78)]);
        let ciphertext2 = encryptor.encrypt([from_const(90), from_const(112), from_const(134)]);
        let checksum = encryptor.finalize();
        let mut decryptor = Decryptor::<BlueSkyConfig4, Scalar, 4, 3>::new(key, nonce);
        let plaintext1 = decryptor.decrypt(ciphertext1);
        let plaintext2 = decryptor.decrypt(ciphertext2);
        assert!(decryptor.finalize(checksum).is_ok());
        assert_eq!(plaintext1, [from_const(34), from_const(56), from_const(78)]);
        assert_eq!(
            plaintext2,
            [from_const(90), from_const(112), from_const(134)]
        );
    }

    #[test]
    fn test_decrypt_two_blocks_t4_automatic_nonce() {
        let key = key1();
        let mut encryptor = Encryptor::<BlueSkyConfig4, Scalar, 4, 3>::new(key);
        let nonce = encryptor.nonce();
        let ciphertext1 = encryptor.encrypt([from_const(34), from_const(56), from_const(78)]);
        let ciphertext2 = encryptor.encrypt([from_const(90), from_const(112), from_const(134)]);
        let checksum = encryptor.finalize();
        let mut decryptor = Decryptor::<BlueSkyConfig4, Scalar, 4, 3>::new(key, nonce);
        let plaintext1 = decryptor.decrypt(ciphertext1);
        let plaintext2 = decryptor.decrypt(ciphertext2);
        assert!(decryptor.finalize(checksum).is_ok());
        assert_eq!(plaintext1, [from_const(34), from_const(56), from_const(78)]);
        assert_eq!(
            plaintext2,
            [from_const(90), from_const(112), from_const(134)]
        );
    }
}
