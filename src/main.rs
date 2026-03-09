fn main() {
    println!("Hello, world!");
}


// Setup 
struct GswParameters {
    
}

// Secret key 
struct GswSecretKey {

}

// Public key
struct GswPublicKey {

}

// Ciphertext
struct GswCiphertext {

}

// Plaintext
struct GswPlaintext {

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
// u \in Z_q 
// Outputs matrix \in Zq of size N x N where N = k * l  
fn encryption(parameters: GswParameters, pk: GswPublicKey, message: u64) -> GswCiphertext {
    todo!()
}

// GSW Decryption
fn decryption(parameters: GswParameters, ct: GswCiphertext, sk: GswSecretKey) -> u64 {
    todo!()
}