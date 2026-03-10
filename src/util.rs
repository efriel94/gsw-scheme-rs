use rand::{Rng, RngExt};

//  Sample an element distribution over the range (0, q-1)
pub fn sample_uniform_distribution_random_element_mod_q(q: &u64) -> u64 {

    let mut rng = rand::rng();
    rng.random_range(0..*q)   
}

// reduce input element a \in Z^+ to the range Z_q = {0, q-1}
pub fn reduce_mod_q(input_element: u128, q: &u128) -> u128 {
    
    input_element % *q
}