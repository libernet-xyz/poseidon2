use ff::PrimeField;

/// Poseidon2 instance configuration trait.
///
/// NOTE: throughout this Poseidon2 implementation we're always assuming that the capacity is 1, so
/// the state width `T` is always equal to the absorption rate plus 1.
pub trait Config<F: PrimeField, const T: usize> {
    /// Returns the number of full rounds on each side (they're 8 in total).
    fn num_full_rounds() -> usize;

    /// Returns the number of partial rounds.
    fn num_partial_rounds() -> usize;

    /// Returns the total number of rounds.
    fn num_total_rounds() -> usize;

    /// Applies an optimal S-box for this field.
    ///
    /// For BLS12-381 and BlueSky the S-Box is x^5.
    fn sbox(x: F) -> F;

    /// Returns the constants of the ARC layer stored as a flat array, row-first.
    fn get_round_constants() -> &'static [F];

    /// Returns the constants of the external matrix stored as a flat array, row-first.
    fn get_external_matrix() -> &'static [F];

    /// Returns the constants of the internal matrix stored as a flat array, row-first.
    fn get_internal_matrix() -> &'static [F];
}

/// Standard x^5 S-box.
///
/// WARNING: this is suitable for BLS12-381 and BlueSky but may not be suitable for other fields.
/// The general requirement is that `F::MAX % 5 != 0`, otherwise this S-box is not a bijection and
/// the resulting Poseidon2 implementation is unsound.
pub fn sbox5<F: PrimeField>(x: F) -> F {
    x.square().square() * x
}

fn linear<F: PrimeField, const T: usize>(matrix: &[F], state: [F; T]) -> [F; T] {
    let mut result = [F::ZERO; T];
    for i in 0..T {
        for j in 0..T {
            result[i] += matrix[i * T + j] * state[j];
        }
    }
    result
}

fn external_linear<C: Config<F, T>, F: PrimeField, const T: usize>(state: [F; T]) -> [F; T] {
    linear::<F, T>(C::get_external_matrix(), state)
}

fn internal_linear<C: Config<F, T>, F: PrimeField, const T: usize>(state: [F; T]) -> [F; T] {
    linear::<F, T>(C::get_internal_matrix(), state)
}

pub(crate) fn permutation<C: Config<F, T>, F: PrimeField, const T: usize>(
    mut state: [F; T],
) -> [F; T] {
    let num_full_rounds = C::num_full_rounds();
    let num_partial_rounds = C::num_partial_rounds();
    let num_total_rounds = C::num_total_rounds();
    assert_eq!(num_total_rounds, 2 * num_full_rounds + num_partial_rounds);

    let c = C::get_round_constants();

    state = external_linear::<C, F, T>(state);

    for r in 0..num_full_rounds {
        for i in 0..T {
            state[i] += c[r * T + i];
        }
        for i in 0..T {
            state[i] = C::sbox(state[i]);
        }
        state = external_linear::<C, F, T>(state);
    }

    for r in num_full_rounds..(num_full_rounds + num_partial_rounds) {
        state[0] += c[r * T];
        state[0] = C::sbox(state[0]);
        state = internal_linear::<C, F, T>(state);
    }

    for r in (num_full_rounds + num_partial_rounds)..num_total_rounds {
        for i in 0..T {
            state[i] += c[r * T + i];
        }
        for i in 0..T {
            state[i] = C::sbox(state[i]);
        }
        state = external_linear::<C, F, T>(state);
    }

    state
}

/// Generic Poseidon2 implementation over the prime field `F` with state size `T`.
///
/// `inputs` must not be empty.
pub fn hash<C: Config<F, T>, F: PrimeField, const T: usize>(inputs: &[F]) -> F {
    assert!(!inputs.is_empty());
    let mut state = [F::ZERO; T];
    for chunk in inputs.chunks(T - 1) {
        for i in 0..chunk.len() {
            state[i] += chunk[i];
        }
        state = permutation::<C, F, T>(state);
    }
    state[0]
}
