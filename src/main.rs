use gsw_scheme::util::{reduce_mod_q, sample_uniform_distribution_random_element_mod_q};


fn main() {
    println!("Hello, world!");

}

// Setup 
#[derive()]
pub struct GswParameters {
    pub n: usize,        // lwe lattice dimension  
    pub q: u64,          // ciphertext modulus
    pub chi: f64,        // error distribution
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
            chi: (self.chi), 
            m: (self.m),
            l: (0),
            large_n: (0)
        };
        params.compute_params();
        params
    }
}

// Secret key (secret eigenvector) s is a Powersof2(s) representation
// Stores a Powersof2(s) = (s, 2s_1, ... , 2^{l - 1}s_1 , ...., 2s_k , 2^{l - 1}s_{k})
struct GswSecretKey {

    sk: Vec<u64>
}

impl GswSecretKey {
    // Sample eigenvector t over Z_q of size n
    // Generate base eigenvector v the form: v <- (1, -t_1, .... -t_n)
    // Return sk = Powersof2(v)  
    fn generate(parameters: &GswParameters) -> Self {

        let n = parameters.n;
        let q = parameters.q;

        let mut base_vector_t = vec![0; n + 1];
        base_vector_t[0] = 1;
        
        //sample base elements over uniform distribution mod q
        for coeff in base_vector_t.iter_mut().skip(1) {
            *coeff = sample_uniform_distribution_random_element_mod_q(&q);
        }

        // negate elements, skipping the first coeff to be in the form: v <- (1, -t_1, .... -t_n)
        // Negation over Z_q: -x = q - x (mod q)
        for coeff in base_vector_t.iter_mut().skip(1) {
            *coeff = if *coeff == q { 0 } else { q - *coeff };
        }

        // return the Powersof2 representation
        let sk_powers_of_two = powers_of_two_decomposition(parameters, &base_vector_t);
        
        Self { sk: (
            sk_powers_of_two
        ) }

    }
}

// Public key    
struct GswPublicKey {
    // Generate a random matrix B sampled over Z_q of size m x n
    
    // Generate a random error eignevector vector e over X^m (Sampled from teh distribution of Chi of size m)

    // Sample eigenvector t over Z_q of size n

    // Calculate b eigenvector, b = (B * t) + e

    // A matrix (n + 1) column matrix, consisting of b followed by (n + 1) columns

    //return pk = A
    
}

// NxN Ciphertext with coefficents over Z_q
struct GswCiphertext {
    ciphertext: Vec<Vec<u64>>
}

// Secret Key generation
fn secret_key_gen(parameters: GswParameters) -> GswSecretKey {
    todo!()
} 

//Public Key generation
fn public_key_gen(parameters: GswParameters, sk: GswSecretKey) -> GswPublicKey {
    todo!()
}

// GSW Encryption
// Encrypt a message u \in Z_q 
// Outputs matrix with coefficents \in Zq of size N x N where N = k * l  
fn encryption(parameters: GswParameters, pk: GswPublicKey, message: u64) -> GswCiphertext {
    todo!()
}

// GSW Decryption
fn decryption(parameters: GswParameters, ct: GswCiphertext, sk: GswSecretKey) -> u64 {
    todo!()
}

// BitDecomp(a)
// Input: Eigenvector a with coefficents over Z_q
// Output: Bit decomposed representation (a_{1,0}, ... , a_{1, l-1}, ... , a_{k,0} , .... , a_{k, l-1}) ,
// where l = floor(log) + 1
fn bit_decomposition_vector(parameters: GswParameters, input_eigenvector: Vec<u64>) -> Vec<u64> {
    todo!()
}

// BitDecomp^{-1}(a)
// Input: Eigenvector a with coefficents over Z_q
// Output: Inverse bit decomposition representation (\sum(2^j * a_{1,j} , ... , \sum(2^j * a_{k,j}))
fn inverse_bit_decomposition_vector(parameters: GswParameters, input_eigenvector: Vec<u64>) -> Vec<u64> {
    todo!()
}

// Flatten(a)
// Input: Eigenvector a with coefficents over Z_q
// Output: Eigenvector with coefficents that are strongly bounded, a requirement to mitigate multiplicative noise
fn flatten(parameters: GswParameters, input_eigenvector: Vec<u64>) -> Vec<u64> {
    todo!()
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
        for i in 0..l {
            output_vec.push(current);
            current = reduce_mod_q((current as u128) * 2u128, &(q as u128)) as u64;
        }
    }

    output_vec 
    
}

// Generate a N dimension Identity matrix, I_N
fn generate_identity_matrix(parameters: GswParameters) -> Vec<Vec<u64>> {
    todo!()
}