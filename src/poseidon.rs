use starkom_ff::PrimeField;

/// Poseidon2 instance configuration trait.
///
/// `R` is the absorption rate and `C` is the capacity; the state size `T` must be equal to `R+C`.
pub trait Config<F: PrimeField, const T: usize> {
    /// Returns the number of full rounds on each side (they're 8 in total).
    fn num_full_rounds_per_side() -> usize;

    /// Returns the number of partial rounds.
    fn num_partial_rounds() -> usize;

    /// Returns the total number of rounds.
    fn num_total_rounds() -> usize {
        Self::num_full_rounds_per_side() * 2 + Self::num_partial_rounds()
    }

    /// Returns the S-box exponent.
    fn alpha() -> usize;

    /// Returns the constants of the ARC layer stored as a flat array, row-first.
    fn get_round_constants() -> &'static [F];

    /// Returns the constants of the external matrix stored as a flat array, row-first.
    fn get_external_matrix() -> &'static [F];

    /// Returns the constants of the internal matrix stored as a flat array, row-first.
    fn get_internal_matrix() -> &'static [F];
}

fn sbox<C: Config<F, T>, F: PrimeField, const T: usize>(x: F) -> F {
    x.pow_small_vartime(C::alpha())
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

fn external_linear<Cfg: Config<F, T>, F: PrimeField, const T: usize>(state: [F; T]) -> [F; T] {
    linear::<F, T>(Cfg::get_external_matrix(), state)
}

fn internal_linear<Cfg: Config<F, T>, F: PrimeField, const T: usize>(state: [F; T]) -> [F; T] {
    linear::<F, T>(Cfg::get_internal_matrix(), state)
}

/// Runs the Poseidon2 permutation.
pub fn permutation<Cfg: Config<F, T>, F: PrimeField, const T: usize>(mut state: [F; T]) -> [F; T] {
    let num_full_rounds_per_side = Cfg::num_full_rounds_per_side();
    let num_partial_rounds = Cfg::num_partial_rounds();
    let num_total_rounds = Cfg::num_total_rounds();
    assert_eq!(
        num_total_rounds,
        2 * num_full_rounds_per_side + num_partial_rounds
    );

    let c = Cfg::get_round_constants();

    state = external_linear::<Cfg, F, T>(state);

    for r in 0..num_full_rounds_per_side {
        for i in 0..T {
            state[i] += c[r * T + i];
        }
        for i in 0..T {
            state[i] = sbox::<Cfg, F, T>(state[i]);
        }
        state = external_linear::<Cfg, F, T>(state);
    }

    for r in num_full_rounds_per_side..(num_full_rounds_per_side + num_partial_rounds) {
        state[0] += c[r * T];
        state[0] = sbox::<Cfg, F, T>(state[0]);
        state = internal_linear::<Cfg, F, T>(state);
    }

    for r in (num_full_rounds_per_side + num_partial_rounds)..num_total_rounds {
        for i in 0..T {
            state[i] += c[r * T + i];
        }
        for i in 0..T {
            state[i] = sbox::<Cfg, F, T>(state[i]);
        }
        state = external_linear::<Cfg, F, T>(state);
    }

    state
}

/// Generic Poseidon2 implementation over the prime field `F` with state size `T`, absorption rate
/// `R`, and capacity `C`.
///
/// `T` must be equal to `R+C`.
///
/// `inputs` must not be empty.
///
/// The scalars provided in the `dst` array are used to initialize the capacity elements; you can
/// specify domain separator tags here. All domain separator tags must be fixed and predetermined by
/// the protocol.
///
/// WARNING: this function implicitly pads with zeros up to the next rate boundary, so for example
/// if the rate is 4 the input sequence [1, 2, 3] will trivially collide with [1, 2, 3, 0]. That is
/// sometimes okay for hashing messages whose length is fixed and determined by the protocol, but
/// otherwise you need to manually prepend a scalar containing the length of the sequence. Example:
///
/// ```ignore
/// const DST: [Scalar] = [from_const(42)];
/// let message = [from_const(12), from_const(34), from_const(56), from_const(78), from_const(90)];
/// let [hash, _, _, _] = poseidon::hash::<poseidon::BlueSkyConfig4, Scalar, 4, 3, 1>(
///     DST, std::iter::once(message.len().into()).chain(message));
/// ```
pub fn hash<Cfg: Config<F, T>, F: PrimeField, const T: usize, const R: usize, const C: usize>(
    dst: [F; C],
    inputs: impl IntoIterator<Item = F>,
) -> [F; R] {
    const { assert!(T == R + C) };
    let mut state = [F::ZERO; T];
    state[R..T].copy_from_slice(&dst);
    let mut inputs = inputs.into_iter().peekable();
    assert!(inputs.peek().is_some(), "cannot hash an empty sequence");
    while inputs.peek().is_some() {
        for i in 0..R {
            match inputs.next() {
                Some(value) => state[i] += value,
                None => break,
            }
        }
        state = permutation::<Cfg, F, T>(state);
    }
    std::array::from_fn(|i| state[i])
}

/// Convenience function for [hashing](`hash`) with Poseidon2 and squeezing the first element.
pub fn hash0<Cfg: Config<F, T>, F: PrimeField, const T: usize, const R: usize, const C: usize>(
    dst: [F; C],
    inputs: impl IntoIterator<Item = F>,
) -> F {
    hash::<Cfg, F, T, R, C>(dst, inputs)[0]
}
