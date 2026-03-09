
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
    fn setup(&self) -> Self {
        GswParameters { 
            n: (self.n), 
            q: (self.q), 
            chi: (self.chi), 
            m: (self.m), 
            l: (((self.q as f64).log2() + 1.0).floor() as usize), 
            large_n: ((self.n + 1) * self.l),  
        }
    }
}

// Secret key (secret eigenvector) s is a Powersof2(s) representation
// Powersof2(s) = (s, 2s_1, ... , 2^{l - 1}s_1 , ...., 2s_k , 2^{l - 1}s_{k})
struct GswSecretKey {

    // Sample eigenvector t over Z_q of size n

    // Generate secret key eigenvector sk of the form: sk <- (1, -t_1, .... -t_n)

    // Return Powersof2(sk) 
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
// Output:  Eigenvector of the form (a_1, 2a_1, ... , 2^{l-1}a_1, ... , a_k, 2a_k, 2^{l-1}a_k) of size N = k*l
fn powers_of_two_decomposition(parameters: GswParameters, input_eigenvector: Vec<u64>) -> Vec<u64> {
    todo!()
}

// Generate a N dimension Identity matrix, I_N
fn generate_identity_matrix(parameters: GswParameters) -> Vec<Vec<u64>> {
    todo!()
}