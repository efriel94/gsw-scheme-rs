use crate::util::*;
use faer::prelude::*;
use rand::RngExt;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

/// GSW Encryption scheme parameters
#[derive(Clone)]
pub struct GswParameters {
    /// LWE lattice dimension `n`, the base secret vector has length `n + 1`.
    pub lwe_dimension: usize,

    /// Ciphertext coefficient modulus `q`, arithmetic is performed over `Z_q`.
    pub ciphertext_modulus: u64,

    /// Error bound `B`, each sampled error coefficient lies in `[-B, B]`.
    pub error_bound: i64,

    /// Number of public-key LWE samples `m`, matrix `A` has `m` rows.
    pub public_key_samples: usize,

    /// Bit-decomposition length `l = floor(log2(q)) + 1`.
    decomposition_length: usize,

    /// Ciphertext dimension `N = (n + 1) * l`.
    ciphertext_dimension: usize,
}

impl GswParameters {
    /// Constructs GSW parameters and derives the decomposition and ciphertext dimensions.
    ///
    /// # Inputs
    ///
    /// - `lwe_dimension`: LWE dimension `n`.
    /// - `ciphertext_modulus`: Ciphertext modulus `q`.
    /// - `error_bound`: Bound `B` for sampled error coefficients.
    /// - `public_key_samples`: Number of LWE samples `m` in the public key.
    ///
    /// # Output
    ///
    /// Returns initialized scheme parameters with derived values
    /// `l = floor(log2(q)) + 1` and `N = (n + 1) * l`.
    pub fn new(
        lwe_dimension: usize,
        ciphertext_modulus: u64,
        error_bound: i64,
        public_key_samples: usize,
    ) -> Self {
        let mut params = GswParameters {
            lwe_dimension,
            ciphertext_modulus,
            error_bound,
            public_key_samples,
            decomposition_length: 0,
            ciphertext_dimension: 0,
        };
        params.compute_params();
        params
    }

    /// Computes the derived decomposition length `l` and ciphertext dimension `N`.
    ///
    /// This is called during construction after the public scheme parameters
    /// have been assigned.
    fn compute_params(&mut self) {
        let decomposition_length = ((self.ciphertext_modulus as f64).log2().floor() + 1.0) as usize;
        let ciphertext_dimension = (self.lwe_dimension + 1) * decomposition_length;

        self.decomposition_length = decomposition_length;
        self.ciphertext_dimension = ciphertext_dimension;
    }

    /// Returns a copy of these parameters with derived dimensions recomputed.
    fn from(&self) -> Self {
        let mut params = GswParameters {
            lwe_dimension: self.lwe_dimension,
            ciphertext_modulus: self.ciphertext_modulus,
            error_bound: self.error_bound,
            public_key_samples: self.public_key_samples,
            decomposition_length: 0,
            ciphertext_dimension: 0,
        };
        params.compute_params();
        params
    }
}

// NxN Ciphertext with coefficents over Z_q
pub struct GswCiphertext {
    ciphertext: Vec<Vec<u64>>,
    ciphertext_modulus: u128,
}

pub struct GswPublicKey {
    matrix_a: Vec<Vec<u64>>,
}

pub struct GswSecretKey {
    powers_of_two_secret_vector: Vec<u64>,
}

pub struct GswKeyPair {
    pub public_key: GswPublicKey,
    pub secret_key: GswSecretKey,
}

impl GswKeyPair {
    /// Derives the secret-key representation from a previously sampled vector `t`.
    ///
    /// This implements the key-derivation portion of `SecretKeyGen`. The caller
    /// supplies `t in Z_q^n`, which is sampled once during keypair generation.
    ///
    /// # Inputs
    ///
    /// - `parameters`: Parameters defining `n`, `q`, and the decomposition length.
    /// - `private_random_eigenvector`: The sampled vector `t in Z_q^n`.
    ///
    /// # Output
    ///
    /// Returns `v = PowersOf2(s)`, where
    /// `s = (1, -t_1, ..., -t_n) in Z_q^(n + 1)`.
    ///
    /// # Panics
    ///
    /// Panics if `private_random_eigenvector` is empty or does not have length `n`.
    pub fn generate_secret_key(
        parameters: &GswParameters,
        private_random_eigenvector: &[u64],
    ) -> GswSecretKey {
        assert!(
            !private_random_eigenvector.is_empty()
                && private_random_eigenvector.len() == parameters.lwe_dimension,
            "Incompatible private random eigenvector for secret key generation"
        );

        // eigenvector s in Z_q of size n + 1 where the first element is 1
        // negate coefficents t_i, skipping the first coeff to be in the form: v <- (1, -t_1, .... -t_n)
        // Negation over Z_q: -x = q - x (mod q)
        let mut base_vector_s = vec![0; private_random_eigenvector.len() + 1];
        base_vector_s[0] = 1;
        for (i, &t_i) in private_random_eigenvector.iter().enumerate() {
            base_vector_s[i + 1] = if t_i == 0 {
                0
            } else {
                parameters.ciphertext_modulus - t_i
            };
        }

        // return the secret key with a Powersof2 representation
        let sk_powers_of_two = powers_of_two_decomposition(parameters, &base_vector_s);

        GswSecretKey {
            powers_of_two_secret_vector: (sk_powers_of_two),
        }
    }

    /// Generates a public key from the same sampled vector `t` used for the secret key.
    ///
    /// Samples `B` uniformly in `Z_q^(m x n)` and an error vector `e`, then
    /// constructs `A = [b | B]`, where `b = B * t + e (mod q)`.
    ///
    /// # Inputs
    ///
    /// - `rng`: Cryptographic random-number generator used for sampling `B` and `e`.
    /// - `parameters`: Parameters defining the matrix dimensions, modulus, and error bound.
    /// - `private_random_eigenvector`: The sampled vector `t in Z_q^n`.
    ///
    /// # Output
    ///
    /// Returns the GSW public-key matrix `A in Z_q^(m x (n + 1))`.
    pub fn generate_public_key(
        rng: &mut ChaCha20Rng,
        parameters: &GswParameters,
        private_random_eigenvector: &[u64],
    ) -> GswPublicKey {
        let lwe_dimension = parameters.lwe_dimension;
        let public_key_samples = parameters.public_key_samples;
        let ciphertext_modulus = parameters.ciphertext_modulus;
        let error_bound = parameters.error_bound;

        // Generate a random matrix B sampled over Z_q of size m x n
        let mut matrix_b = vec![vec![0u64; lwe_dimension]; public_key_samples];
        for i in 0..public_key_samples {
            for j in 0..lwe_dimension {
                matrix_b[i][j] = sample_uniform_distribution_random_element_mod_q(
                    rng,
                    &parameters.ciphertext_modulus,
                );
            }
        }

        // Generate a random error eignevector vector e over X^m where X^m is B-bounded between [-B, B]
        // Sampled from the distribution of Chi of size m
        // therefore e <- X^m where e_i \in [-B, B]
        let error_eigenvector = sample_error_eigenvector(rng, error_bound, public_key_samples);

        // Compute eigenvector b = (B*t + e) mod q
        let body_eigenvector = body(
            &matrix_b,
            &private_random_eigenvector,
            &error_eigenvector,
            ciphertext_modulus as u128,
        );

        // Generate matrix A = [b | B]
        // where b \in Z_q , B \in Z_q of size m x n
        // Resultant A matrix \in Z_q of size m x (n + 1)
        let public_augmented_matrix = augment_matrices(&body_eigenvector, &matrix_b);

        GswPublicKey {
            matrix_a: (public_augmented_matrix),
        }
    }

    /// Generates a matched GSW public and secret key pair.
    ///
    /// Samples one private vector `t`, derives the secret key from it, and
    /// constructs the public key using the same `t`.
    ///
    /// # Inputs
    ///
    /// - `parameters`: GSW parameters for key generation.
    ///
    /// # Output
    ///
    /// Returns a public key for encryption and its corresponding secret key
    /// for decryption.
    pub fn generate_key_pair(parameters: &GswParameters) -> Self {
        let mut rng = ChaCha20Rng::from_rng(&mut rand::rng());

        let private_random_eigenvector_t = generate_private_eigenvector(&mut rng, parameters);
        let secret_key = Self::generate_secret_key(parameters, &private_random_eigenvector_t);
        let public_key =
            Self::generate_public_key(&mut rng, &parameters, &private_random_eigenvector_t);

        GswKeyPair {
            public_key,
            secret_key,
        }
    }
}

/// Samples the private vector `t` uniformly from `Z_q^n`.
///
/// # Inputs
///
/// - `rng`: Cryptographic random-number generator used for uniform sampling.
/// - `parameters`: GSW parameters defining `n` and `q`.
///
/// # Output
///
/// Returns the private vector `t` used to derive both keys.
fn generate_private_eigenvector(rng: &mut ChaCha20Rng, parameters: &GswParameters) -> Vec<u64> {
    // Sample a private random eigenvector t <- Z_q of size n
    let mut private_random_eigenvector_t = vec![0; parameters.lwe_dimension];
    for coeff in private_random_eigenvector_t.iter_mut() {
        *coeff =
            sample_uniform_distribution_random_element_mod_q(rng, &parameters.ciphertext_modulus);
    }

    private_random_eigenvector_t
}

/// Encrypts a single bit under a GSW public key.
///
/// Samples `R in {0,1}^(N x m)` and returns:
///
/// `C = Flatten(mu * I_N + BitDecomp(R * A)) in Z_q^(N x N)`.
///
/// # Inputs
///
/// - `parameters`: GSW parameters defining `q`, `m`, and `N`.
/// - `pk`: Public-key matrix `A`.
/// - `message`: Plaintext bit `mu`, which must be either `0` or `1`.
///
/// # Output
///
/// Returns a GSW ciphertext encrypting `message`.
///
/// # Panics
///
/// Panics if `message` is not a bit.
pub fn encrypt_bit(parameters: &GswParameters, pk: &GswPublicKey, message: u8) -> GswCiphertext {
    assert!(
        message <= 1,
        "Only supports the encryption of 1-bit messages"
    );

    let ciphertext_dimension = parameters.ciphertext_dimension;
    let public_key_samples = parameters.public_key_samples;
    let ciphertext_modulus = parameters.ciphertext_modulus;
    let matrix_a = pk.matrix_a.to_owned();

    // u * I_N where u \in {0,1} and I_N is the identity matrix of size N x N
    // (u * I_N) \in {0,1} of size N x N
    let identity_matrix = identity_matrix(&parameters);
    let u_times_identity_matrix: Vec<Vec<u64>> = identity_matrix
        .iter()
        .map(|row| {
            row.iter()
                .map(|&x| x * message as u64)
                .collect::<Vec<u64>>()
        })
        .collect::<Vec<Vec<u64>>>();

    //generate a random N x m matrix R with 0/1 entries
    let mut rng = ChaCha20Rng::from_rng(&mut rand::rng());

    let mut random_binary_matrix_r = vec![vec![0u64; public_key_samples]; ciphertext_dimension];
    for i in 0..ciphertext_dimension {
        for j in 0..public_key_samples {
            random_binary_matrix_r[i][j] = rng.random_range(0..=1);
        }
    }

    // R * A where R <- {0,1} of size N x m and A
    let r_times_a_matrix = schoolbook_lwe_matrix_multiplication_mod_q(
        random_binary_matrix_r,
        matrix_a,
        ciphertext_modulus.into(),
    );

    // BitDecomp(R * A), returns a matrix of size N x (n + 1) * l since it expands each row element into \elle bits
    // By def (n + 1) * l = N, so the output matrix is of size N * N
    //R \times A is statistically uniform by the leftover hash lemma
    let bit_decomp_r_times_a_matrix = bit_decomposition(&parameters, &r_times_a_matrix);

    // Addition of (u * I_N) + BitDecomp(R * A)
    // where (u * I_N) \in Z_q of size N x N and BitDecomp(R*A) \in {0,1} of size N * N
    // Simply atddition mod q of two NxN marices
    let addition_vector_temp: Vec<Vec<u64>> = u_times_identity_matrix
        .iter()
        .zip(bit_decomp_r_times_a_matrix.chunks(ciphertext_dimension))
        .map(|(row_a, row_b)| {
            row_a
                .iter()
                .zip(row_b.iter())
                .map(|(&a, &b)| (a + b) % ciphertext_modulus)
                .collect::<Vec<u64>>()
        })
        .collect();

    // C = Flatten((u * I_N) + BitDecomp(R * A))
    let flattened_ciphertext = flatten(&parameters, &addition_vector_temp);
    assert_eq!(
        flattened_ciphertext.len(),
        ciphertext_dimension,
        "Incorrect row count: got {}, expected {}",
        flattened_ciphertext.len(),
        ciphertext_dimension
    );
    assert!(
        flattened_ciphertext
            .iter()
            .all(|row| row.len() == ciphertext_dimension),
        "Incorrect column count: expected every row to have len {}",
        ciphertext_dimension
    );

    GswCiphertext {
        ciphertext: (flattened_ciphertext),
        ciphertext_modulus: ciphertext_modulus as u128,
    }
}

/// Decrypts a GSW ciphertext containing a single bit.
///
/// Chooses a secret-key coefficient `v_i in (q/4, q/2]` and computes
/// `x_i = <C_i, v> mod q`. For bit messages, the result is decoded by
/// choosing whether `x_i` is closer modulo `q` to `0` or to `v_i`.
///
/// # Inputs
///
/// - `parameters`: GSW parameters defining `q`, `l`, and `N`.
/// - `ct`: Ciphertext matrix `C in Z_q^(N x N)`.
/// - `sk`: Secret key represented as `v = PowersOf2(s)`.
///
/// # Output
///
/// Returns the recovered plaintext bit, either `0` or `1`.
///
/// # Panics
///
/// Panics if the ciphertext or secret-key dimensions do not match the
/// parameters, or if no suitable coefficient `v_i` is found.
pub fn decrypt_bit(parameters: &GswParameters, ct: GswCiphertext, sk: &GswSecretKey) -> u8 {
    let ciphertext_dimension = parameters.ciphertext_dimension;
    let ciphertext_modulus = parameters.ciphertext_modulus;
    let decomposition_length = parameters.decomposition_length;

    assert_eq!(ct.ciphertext.len(), ciphertext_dimension);
    assert!(
        ct.ciphertext
            .iter()
            .all(|row| row.len() == ciphertext_dimension)
    );
    assert_eq!(sk.powers_of_two_secret_vector.len(), ciphertext_dimension);

    // Find vi such that vi \in (q/4, q/2])
    let decryption_index = (0..decomposition_length)
        .find(|&i| {
            let vi = sk.powers_of_two_secret_vector[i];
            vi > ciphertext_modulus / 4 && vi <= ciphertext_modulus / 2
        })
        .expect("No v_i found in (q/4, q/2]");

    let vi = sk.powers_of_two_secret_vector[decryption_index];

    // x_i = <C_i, v> mod q
    //
    let xi = ct.ciphertext[decryption_index]
        .iter()
        .zip(sk.powers_of_two_secret_vector.iter())
        .fold(0u128, |acc, (&cij, &vj)| {
            (acc + (cij as u128 * vj as u128)) % ciphertext_modulus as u128
        });

    // Essentially if <C_i, v> is closer to v_i then return 1, otherwise return 0
    let xi = xi as u64;
    let distance_to_zero = xi.min(ciphertext_modulus - xi);
    let difference_to_one = xi.abs_diff(vi);
    let distance_to_one = difference_to_one.min(ciphertext_modulus - difference_to_one);

    if distance_to_one < distance_to_zero {
        1
    } else {
        0
    }
}

/// Computes the bit decomposition of coefficients over `Z_q`.
///
/// Each input coefficient `a_i` is expanded into `l` bits ordered from
/// least-significant to most-significant bit:
///
/// `(a_(1,0), ..., a_(1,l-1), ..., a_(k,0), ..., a_(k,l-1))`.
///
/// # Inputs
///
/// - `parameters`: GSW parameters containing the decomposition length `l`.
/// - `input_eigenvector`: Rows of coefficients to decompose.
///
/// # Output
///
/// Returns a flat vector containing the concatenated `l`-bit decompositions.
fn bit_decomposition(parameters: &GswParameters, input_eigenvector: &[Vec<u64>]) -> Vec<u64> {
    // for every element in the vector we break each one into l (\elle) bits
    let output_len = input_eigenvector.iter().map(|row| row.len()).sum::<usize>()
        * parameters.decomposition_length;
    let mut output_vec = Vec::with_capacity(output_len);

    for row in input_eigenvector.iter() {
        for &ai in row.iter() {
            for j in 0..parameters.decomposition_length {
                output_vec.push((ai >> j) & 1);
            }
        }
    }

    output_vec
}

/// Recombines consecutive decomposition blocks into coefficients.
///
/// For each block of length `l`, computes `sum_j 2^j * a_(i,j)`.
///
/// # Inputs
///
/// - `parameters`: GSW parameters containing the decomposition length `l`.
/// - `input_eigenvector`: Flat decomposition coefficients grouped in blocks of `l`.
///
/// # Output
///
/// Returns one recombined coefficient for each complete input block.
fn inverse_bit_decomposition(parameters: &GswParameters, input_eigenvector: &[u64]) -> Vec<u64> {
    let k = input_eigenvector.len() / parameters.decomposition_length;
    let bit_level = parameters.decomposition_length;
    let mut output_vec: Vec<u64> = Vec::with_capacity(k);

    // loop over k elements
    for i in 0..k {
        let mut value = 0 as u128;

        // for each k-th element, reconstruct the original coefficent value from j bits
        for j in 0..bit_level {
            let coeff_value = input_eigenvector[i * bit_level + j] as u128;
            value += coeff_value << j; // coeff * 2^j
        }

        output_vec.push(value as u64);
    }

    output_vec
}

/// Applies the GSW flattening operation to a matrix.
///
/// Computes `Flatten(A) = BitDecomp(BitDecomp^(-1)(A))`, producing bounded
/// binary coefficients needed to control noise during homomorphic operations.
///
/// # Inputs
///
/// - `parameters`: GSW parameters defining the ciphertext dimension `N`.
/// - `input_matrix`: Matrix whose rows each have length `N`.
///
/// # Output
///
/// Returns the flattened matrix with bit-decomposed rows.
///
/// # Panics
///
/// Panics if any input row does not have length `N`.
fn flatten(parameters: &GswParameters, input_matrix: &[Vec<u64>]) -> Vec<Vec<u64>> {
    let expected_row_len = parameters.ciphertext_dimension;
    assert!(
        input_matrix.iter().all(|row| row.len() == expected_row_len),
        "Flatten expects each input row to have len {}",
        expected_row_len
    );

    input_matrix
        .iter()
        .map(|row| {
            let inverse_bit_decomp_row_result = inverse_bit_decomposition(parameters, row);
            bit_decomposition(parameters, &[inverse_bit_decomp_row_result])
        })
        .collect()
}

/// Computes the powers-of-two expansion of a vector over `Z_q`.
///
/// Expands each coefficient `a_i` into
/// `(a_i, 2*a_i, ..., 2^(l-1)*a_i) mod q`.
///
/// # Inputs
///
/// - `parameters`: GSW parameters defining `q` and decomposition length `l`.
/// - `input_eigenvector`: Coefficients to expand.
///
/// # Output
///
/// Returns a vector of length `input_eigenvector.len() * l`. For a base
/// secret vector of length `n + 1`, this is the GSW secret vector `v`.
fn powers_of_two_decomposition(parameters: &GswParameters, input_eigenvector: &[u64]) -> Vec<u64> {
    let decomposition_length = parameters.decomposition_length;
    let k = input_eigenvector.len();
    let ciphertext_modulus = parameters.ciphertext_modulus;

    let mut output_vec: Vec<u64> = Vec::with_capacity(k * decomposition_length);

    // so we want to loop over the current input vector
    // multiply each element by a power of two
    // reduce mod q
    // up to a level l of floor(log q) + 1
    for a_i in input_eigenvector {
        let mut current = *a_i;
        for _ in 0..decomposition_length {
            output_vec.push(current);
            current = reduce_mod_q((current as u128) * 2u128, &(ciphertext_modulus as u128)) as u64;
        }
    }

    output_vec
}

/// Constructs the `N x N` identity matrix used in GSW encryption.
///
/// # Panics
///
/// Panics if the derived ciphertext dimension `N` is zero.
fn identity_matrix(parameters: &GswParameters) -> Vec<Vec<u64>> {
    let ciphertext_dimension = parameters.ciphertext_dimension;
    assert!(ciphertext_dimension > 0);

    let mut output_vec = vec![vec![0u64; ciphertext_dimension]; ciphertext_dimension];
    for i in 0..ciphertext_dimension {
        output_vec[i][i] = 1;
    }

    output_vec
}
