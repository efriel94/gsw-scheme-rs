use gsw_scheme::gsw::{decryption, encryption, GswKeyPair, GswParameters};

fn main() {
    let parameters = GswParameters::new(
        4,    // n
        1024, // q
        1,    // B
        64,   // m
    );

    let key_pair = GswKeyPair::generate_key_pair(&parameters);
    let message = 1;

    let ciphertext = encryption(parameters.clone(), key_pair.public_key, message);
    let decrypted_message = decryption(parameters, ciphertext, key_pair.secret_key);

    println!("message: {}", message);
    println!("decrypted: {}", decrypted_message);

    assert_eq!(message, decrypted_message);

}
