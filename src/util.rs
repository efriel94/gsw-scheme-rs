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


//sample random e_i \in [-B, B]
fn sample_bounded_error<R: Rng>(rng: &mut R, error_bound: i64) -> i64 {
    if error_bound <= 0 {
        return 0;
    }
    rng.random_range(-error_bound..=error_bound)
}

//sample an error eigenvector of distribution X^m (chi) where X distributionm is B-bounded
//The coefficents e_i of the eigenvector e, e_i \in [-B, B]
pub fn sample_error_eigenvector<R: Rng>(rng: &mut R, error_bound: i64, size_m: usize) -> Vec<i64> {

    let mut e_vec = Vec::with_capacity(size_m);
    for _ in 0..size_m {
        e_vec.push(sample_bounded_error(rng, error_bound));
    }

    e_vec

}