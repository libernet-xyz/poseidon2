use starkom_ff::PrimeField;

/// Helper function to decode a binary file of packed 256-bit constants.
pub(crate) fn decode_constants<F: PrimeField, const N: usize>(bytes: &[u8]) -> [F; N] {
    let repr_size = (F::NUM_BITS >> 3) + ((F::NUM_BITS & 7) != 0) as usize;
    assert_eq!(repr_size, 32);
    assert_eq!(bytes.len(), N * 32);
    let mut constants = [F::ZERO; N];
    for i in 0..N {
        let bytes: [u8; 32] = bytes[(i * 32)..((i + 1) * 32)].try_into().unwrap();
        constants[i] = F::try_from_le_bytes(&bytes).unwrap();
    }
    constants
}
