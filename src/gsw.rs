use std::{process::id, vec};

use rand::{Rng, RngExt};
use crate::util::*;

// Setup 
#[derive()]
pub struct GswParameters {
    pub n: usize,        // lwe lattice dimension  
    pub q: u64,          // ciphertext modulus
    pub B: i64,          // B-bounded error distribution X^m where coefficents of X^m are e_i \in [-B, B]
    pub m: usize,        // m samples i.e A matrix is of size m x (n + 1) over Z_q
    l: usize,            // \elle  = floor(log q) + 1
    large_n: usize       // N = (n + 1) * l
}

impl GswParameters {
    fn compute_params(&mut self) {
        let l = ((self.q as f64).log2().floor() + 1.0) as usize;
        let large_n = (self.n + 1) * l;

        self.l = l as usize;
        self.large_n = large_n;
    }

    fn from(&self) -> Self {
        let mut params = GswParameters { 
            n: (self.n), 
            q: (self.q), 
            B: (self.B), 
            m: (self.m),
            l: (0),
            large_n: (0)
        };
        params.compute_params();
        params
    }
}

// NxN Ciphertext with coefficents over Z_q
struct GswCiphertext {
    ciphertext: Vec<Vec<u64>>
}

pub struct GswPublicKey {
    data: Vec<Vec<u64>>,
}

pub struct GswSecretKey {
    data: Vec<u64>,
}


#[derive()]
pub struct GswKeyPair {
    pub public_key: GswPublicKey,
    pub secret_key: GswSecretKey,
}

impl GswKeyPair {

    pub fn generate_key_pair(parameters: &GswParameters) -> Self {

        let n = parameters.n;
        let q = parameters.q;
        let m = parameters.m;
        let bounded_error_distribution = parameters.B;

        // ---------------------------------
        // Generate Secret Key
        // ---------------------------------

        // Sample a private random eigenvector t <- Z_q of size n
        let mut rng = rand::rng();
        let mut private_random_eigenvector_t = vec![0; n];
        for coeff in private_random_eigenvector_t.iter_mut() {
            *coeff = sample_uniform_distribution_random_element_mod_q(&mut rng, &q);
        }

        // eigenvector v in Z_q of size n + 1 where the first element is 1
        // negate coefficents t_i, skipping the first coeff to be in the form: v <- (1, -t_1, .... -t_n)
        // Negation over Z_q: -x = q - x (mod q)
        let mut base_vector_v = vec![0; private_random_eigenvector_t.len() + 1];
        base_vector_v[0] = 1;
        for (i, &t_i) in private_random_eigenvector_t.iter().enumerate() {
            base_vector_v[i+1] = if t_i == 0 { 0 } else { q - t_i }; 
        }

        // return the secret key with a Powersof2 representation
        let sk_powers_of_two = powers_of_two_decomposition(parameters, &base_vector_v);

        // ---------------------------------
        // Generate Public Key
        // ---------------------------------

        // Generate a random matrix B sampled over Z_q of size m x n
        let mut rng = rand::rng();
        let mut matrix_b = vec![vec![0u64; n]; m];
        for i in 0..m {
            for j in 0..n {
                matrix_b[i][j] = sample_uniform_distribution_random_element_mod_q(&mut rng, &q);
            }
        }
        
        // Generate a random error eignevector vector e over X^m where X^m is B-bounded between [-B, B] 
        // Sampled from the distribution of Chi of size m
        // therefore e <- X^m where e_i \in [-B, B]
        let error_eigenvector = sample_error_eigenvector(&mut rng, bounded_error_distribution, m);

        // Compute eigenvector b = (B*t + e) mod q 
        let mut body_eigenvector = body(
            &matrix_b, 
            &private_random_eigenvector_t, 
            &error_eigenvector, 
            q as u128,
        );

        // Generate matrix A = [b | B]
        let public_augmented_matrix = augment_matrix


        // the public augmented matrix A = [b | B]
        // where b \in Z_q of size m x 1
        // where B \in Z_q of size m x n
        // therefore output public key A \in Z_q of size m * (n + 1)
        let mut matrix_a = vec![vec![0u64; n + 1]; m];
        for i in 0..m {

            //first column of b_i
            let b_i = b_eigenvector[i];
            matrix_a[i][0] = b_i;

            for j in 0..n {

                // augmented with elements of B_i
                matrix_a[i][j + 1] = matrix_b[i][j + 1];
            }
        }
        

        GswKeyPair { 
            public_key: GswPublicKey { data: (matrix_a) }, 
            secret_key: GswSecretKey { data: (sk_powers_of_two) } 
        }


    }
}

// GSW Encryption
// Encrypt a message u \in Z_q 
// Outputs matrix C = Flatten(u * I_N + BitDecomp(R * A)) \in Zq of size N x N where N = k * l  
fn encryption(parameters: GswParameters, pk: GswPublicKey, message: u64) -> GswCiphertext {

    let N = (parameters.n + 1) * parameters.l;
    let n = parameters.n;
    let m = parameters.m;
    let q = parameters.q;
    let matrix_a = pk.data;

    // u * I_N where u \in {0,1} and I_N is the identity matrix of size N x N
    // (u * I_N) \in {0,1} of size N x N
    let identity_matrix = identity_matrix(&parameters);
    let mut u_times_identity_matrix: Vec<Vec<u64>> = identity_matrix
        .iter()
        .map(|row| {
            row.iter()
                .map(|&x| x * message)
                .collect::<Vec<u64>>()
        })
        .collect::<Vec<Vec<u64>>>();

    //BitDecomp(R * A) where R \times A is statistically uniform by the leftover hash lemma
    
    //generate a random N x m matrix R with 0/1 entries
    let mut rng = rand::rng();
    let mut random_binary_matrix_r = vec![vec![0u64; m]; N];
    for i in 0..N {
        for j in 0..m {
            random_binary_matrix_r[i][j] = rng.random_range(0..=1);
        }
    }

    let r_times_a_matrix = schoolbook_matrix_multiplication_mod_q(
        random_binary_matrix_r,
        matrix_a,
        q, 
        );


    // N x m matrix R \times public matrix A of size m * (n + 1)
    // (R * A) \in Z_q of size N x (n + 1)
    let r_times_a_matrix_len = N * (n + 1);
    let r_times_a_matrix = vec![vec![0u64; n + 1]; N];

    for i in 0..N {
        for j in 0..n {
            let mut sum = 0;

            for k in 0..m {
                // row - col mult
                let rij = random_binary_matrix_r[i * m + k] as u128;
                let aij = matrix_a[k * n + j] as u128;
                let mult_result = rij * aij;

                sum += mult_result;
            }

            //reduce mod q and assign
            r_times_a_matrix[i * N + j] = (sum % (q as u128)) as u64;
        }
    }

    // BitDecomp(R * A), returns a matrix of size N x (n + 1) * l since it expands each row element into \elle bits
    // By def (n + 1) * l = N, so the output matrix is N * N
    let bit_decomp_r_times_a_matrix = bit_decomposition(&parameters, &r_times_a_matrix);

    // Addition of (u * I_N) + BitDecomp(R * A)
    let addition_vector_temp: Vec<u64> = u_times_identity_matrix
        .iter()
        .zip(bit_decomp_r_times_a_matrix.iter())
        .map(|(a,b)| (a + b) % q)
        .collect();

    // C = Flatten((u * I_N) + BitDecomp(R * A))
    let flattened_ciphertext = flatten(&parameters, &addition_vector_temp);
    assert_eq!(
        flattened_ciphertext.len(), 
        N * N,
        "Incorrect len: got {}, expected {}", flattened_ciphertext.len(), N * N);

    GswCiphertext { ciphertext: (flattened_ciphertext) }

}

// GSW Decryption
fn decryption(parameters: GswParameters, ct: GswCiphertext, sk: GswSecretKey) -> u64 {
    todo!()
}

// BitDecomp(a)
// Input: Eigenvector a with coefficents over Z_q
// Output: Bit decomposed representation (a_{1,0}, ... , a_{1, l-1}, ... , a_{k,0} , .... , a_{k, l-1}) ,
// where l = floor(log) + 1
// Ordered from LSB to MSB
fn bit_decomposition(parameters: &GswParameters, input_eigenvector: &Vec<u64>) -> Vec<u64> {

    // for every element in the vector we break each one into l (\elle) bits
    let output_len = input_eigenvector.len() * parameters.l;
    let mut output_vec = Vec::with_capacity(output_len);

    for &ai in input_eigenvector.iter().as_ref() {
        for j in 0..parameters.l {
            output_vec.push((ai >> j) & 1);    
        }
    }

    output_vec


}

// BitDecomp^{-1}(a)
// Input: Eigenvector a with coefficents a_i over Z_q
// Output: Inverse bit decomposition representation (\sum(2^j * a_{1,j} , ... , \sum(2^j * a_{k,j}))
fn inverse_bit_decomposition(parameters: &GswParameters, input_eigenvector: &Vec<u64>) -> Vec<u64> {
    
    let k = input_eigenvector.len() / parameters.l;
    let bit_level = parameters.l;
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

// Flatten(a) = BitDecomp(InverseBitDecomp(a)) \in {0,1} of size N
// Input: Eigenvector a with coefficents over Z_q
// Output: N-dimensional Eigenvector with coefficents that are strongly bounded, a requirement to mitigate multiplicative noise
fn flatten(parameters: &GswParameters, input_eigenvector: &Vec<u64>) -> Vec<u64> {

    let inverse_bit_decomp_vector_result = inverse_bit_decomposition(parameters, input_eigenvector);
    let bit_decomp_vector_result = bit_decomposition(parameters, &inverse_bit_decomp_vector_result);

    bit_decomp_vector_result
}

// Powersof2(a)
// Input: Eigenvector a with coefficents over Z_q
// Output:  Eigenvector of the form (a_1, 2a_1, ... , 2^{l-1}a_1, ... , a_k, 2a_k, 2^{l-1}a_k) of size N = k*l,
// with coefficents a_i in Z_q
fn powers_of_two_decomposition(parameters: &GswParameters, input_eigenvector: &[u64]) -> Vec<u64> {

    let l = parameters.l;   
    let k = input_eigenvector.len(); 
    let q = parameters.q;

    let mut output_vec: Vec<u64> = Vec::with_capacity((k * l));

    // so we want to loop over the current input vector
    // multiply each element by a power of two
    // reduce mod q
    // up to a level l of floor(log q) + 1
    for a_i in input_eigenvector {
        let mut current = *a_i;
        for _ in 0..l {
            output_vec.push(current);
            current = reduce_mod_q((current as u128) * 2u128, &(q as u128)) as u64;
        }
    }

    output_vec 
    
}

// Generate an identity square matrix of size m x n
fn identity_matrix(parameters: &GswParameters) -> Vec<Vec<u64>> {

    let m = parameters.m;
    assert!(m > 0);
    
    let mut output_vec = vec![vec![0u64; m]; m];
    for i in 0..m {
        output_vec[i][i] = 1;
    }

    output_vec
}


