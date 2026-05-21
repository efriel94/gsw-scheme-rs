use std::vec;

use rand::{Rng, RngExt};
use rand_distr::{Normal,Distribution};

//  Sample an element distribution over the range (0, q-1)
pub fn sample_uniform_distribution_random_element_mod_q<R: Rng>(rng: &mut R, q: &u64) -> u64 {
    rng.random_range(0..*q)   
}

// Sample an element from the normal distribution N(0, sigma^2)
pub fn sample_normal_distribution_random_element(sigma: f64) -> f64 {

    //mean zero, std deviation sigma
    let normal = Normal::new(0.0, sigma).unwrap();
    let rand_element = normal.sample(&mut rand::rng()).round();
    rand_element
}

// reduce input element a \in Z^+ to the range Z_q = {0, q-1}
pub fn reduce_mod_q(input_element: u128, q: &u128) -> u128 {
    
    input_element % *q
}


// Sample random e_i \in [-B, B]
fn sample_bounded_error<R: Rng>(rng: &mut R, error_bound: i64) -> i64 {
    if error_bound <= 0 {
        return 0;
    }
    rng.random_range(-error_bound..=error_bound)
}

// Sample an error eigenvector of distribution X^m (chi) where X distributionm is B-bounded
// The coefficents e_i of the eigenvector e, e_i \in [-B, B]
pub fn sample_error_eigenvector<R: Rng>(rng: &mut R, error_bound: i64, size_m: usize) -> Vec<i64> {

    let mut e_vec = Vec::with_capacity(size_m);
    for _ in 0..size_m {
        e_vec.push(sample_bounded_error(rng, error_bound));
    }

    e_vec

}


pub fn matrix_vector_multiplication_mod_q(
    input_matrix_a: &[Vec<u64>],
    input_vector_b: &[u64],
    modulus: u128,
) -> Vec<u64> {

    let rows_a = input_matrix_a.len();
    let cols_a = input_matrix_a[0].len();
    let vector_b_len = input_vector_b.len();

    assert!(
        cols_a == vector_b_len, 
        "Incompatible dimensions for matrix-vector multiplication, got cols input matrix A {}, got vector len {}",
        cols_a,
        vector_b_len,
    );

    let mut output_vec = vec![0u64; rows_a];

    for i in 0..rows_a {
        let mut sum = 0;
        for j in 0..cols_a {
            let aij = input_matrix_a[i][j] as u128;
            let bi = input_vector_b[j] as u128;
            let result = (aij * bi);
            sum += result;
        }
        output_vec[i] = (sum % modulus) as u64;
    }

    output_vec

}


pub fn schoolbook_lwe_matrix_multiplication_mod_q(
    input_matrix_a: Vec<Vec<u64>>, 
    input_matrix_b: Vec<Vec<u64>>, 
    modulus: u128
) -> Vec<Vec<u64>> {

    let rows_a = input_matrix_a.len();
    let cols_a = input_matrix_a[0].len();
    let rows_b = input_matrix_b.len();
    let cols_b = input_matrix_b[0].len();

    assert!(rows_a > 0 && cols_a > 0, "input matrix a must be non empty");
    assert!(rows_b > 0 && cols_b > 0, "input matrix b must be non empty");
    assert!(cols_a == rows_b, "matrix dimensions do not align for matrix multiplication");

    let mut output_vec = vec![vec![0u64; cols_b]; rows_a];

    for i in 0..rows_a {
        for j in 0..cols_b {
            let mut sum = 0;
            for k in 0..cols_a {

                let mult_result = (input_matrix_a[i][k] * input_matrix_b[k][j]) as u128;
                sum += mult_result
            }
            output_vec[i][j] = (sum % modulus) as u64;
        }
    }

    output_vec

}

// Compute b = B*t + e (mod q) , where
// matrix B \in Z_q of size m x n
// vector t \in Z_q of size m x 1
// vector e sampled from distribution Chi of size m where cofficents e_i is sampled in the B-bounded interval [-B, B]
// Outputs a vector b \in Z_q of size m x 1 
pub fn body(
    input_matrix_b: &[Vec<u64>],
    input_vector_t: &[u64],
    input_vector_e: &[i64],
    modulus: u128,
) -> Vec<u64> {

    let total_rows_matrix_b = input_matrix_b.len();
    let total_cols_matrix_b = input_matrix_b[0].len();
    let total_len_vector_t = input_vector_t.len();

    assert!(
        total_cols_matrix_b == total_len_vector_t,
        "Incompatible dimensions for matrix-vector multiplication. Matrix columns {}, Vector length {}",
        total_cols_matrix_b,
        total_len_vector_t
    );
    
    let mut output_vector = vec![0u64; total_rows_matrix_b];
    
    // Compute B*t + e (mod q)
    // \sum_{j=0}^{n-1} B_{i,j} * t_j + e_i (mod q) 
    for i in 0..total_rows_matrix_b {
        let mut sum = 0;
        for j in 0..total_cols_matrix_b {

            let bij = input_matrix_b[i][j] as u128;
            let ti = input_vector_t[j] as u128;
            sum += (bij * ti) 
        }

        // Addition of e_i (mod q)
        let temp = (sum as i128 + input_vector_e[i] as i128).rem_euclid(modulus as i128);
        output_vector[i] = temp as u64;
    }

    output_vector

}


pub fn augment_matrices(
    input_vector_a: &[u64],
    input_matrix_b: &[Vec<u64>]
) -> Vec<Vec<u64>> {

    assert!(
        input_vector_a.len() == input_matrix_b.len(),
        "Length of input vector must have the same number of rows as input matrix"
    );

    let mut output_vec = Vec::with_capacity(input_matrix_b.len());
    
    for (&ai, row_b) in input_vector_a.iter().zip(input_matrix_b.iter())  {
        
        let mut new_row_vec = Vec::with_capacity(row_b.len() + 1);
        new_row_vec.push(ai);
        new_row_vec.extend(row_b.iter());
        output_vec.push(new_row_vec);
    }

    output_vec
}
