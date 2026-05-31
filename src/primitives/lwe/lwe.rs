
pub struct LweSecretKey;

#[derive(Clone, Debug)]
pub enum ErrorDistribution {
    
    UniformBounded { bound: i64 },
    DiscreteGaussian { std_dev: f64, bound: Option<i64> },  // Optionally bound on the discrete gaussian if user wishes to force an explicit cutoff
}

/// LWE encryption parameters
#[derive(Clone)]
pub struct LweParameters {
    
    /// Length of the lattice dimension `n` where the length of the LWE secret vector is `n + 1`
    pub lwe_dimension: usize,
    
    /// Ciphertext modulus, arithmetic performed modulo q
    pub ciphertext_modulus: u128,
    
    /// Error vector is sampled over a range of error distributions
    pub error_distribution: ErrorDistribution,
    
    /// Number of samples `m`,
    pub sample_size: usize,
}

impl LweParameters {
    
    pub fn new(
        input_lwe_dimension: usize,
        input_ciphertext_modulus: u128,
        input_error_distribution: ErrorDistribution,
        input_sample_size: usize
    ) -> Self {
        let params = LweParameters {
            lwe_dimension: input_lwe_dimension,
            ciphertext_modulus: input_ciphertext_modulus,
            error_distribution: input_error_distribution,
            sample_size: input_sample_size,
        };
        params
    }
}



/// Structure of a LWE sample / ciphertext
/// An LWE sample c = (a, b) where:
/// a <- Chi^m is sampled from a random distribution of size n 
/// b = As + e (mod q) where A is a randomly sampled matrix   
pub struct LweCiphertext {
    pub mask: Vec<usize>,
    pub body: u64
}