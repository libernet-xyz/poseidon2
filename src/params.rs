use starkom_ff::PrimeField;

/// Helper function to decode a binary file of packed field elements.
pub(crate) fn decode_constants<F: PrimeField, const N: usize>(bytes: &[u8]) -> [F; N] {
    let repr_size = (F::NUM_BITS >> 3) + ((F::NUM_BITS & 7) != 0) as usize;
    assert_eq!(bytes.len(), N * repr_size);
    let mut constants = [F::ZERO; N];
    for i in 0..N {
        let bytes = &bytes[(i * repr_size)..((i + 1) * repr_size)];
        constants[i] = F::try_from_le_bytes(bytes).unwrap();
    }
    constants
}
