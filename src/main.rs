use gsw_scheme::gsw::{GswKeyPair, GswParameters, decrypt_bit, encrypt_bit};

fn main() {
    let parameters = GswParameters::new(
        4,               // lwe_dimension
        1024,       // ciphertext_modulus
        1,                 // error_bound
        64,         // public_key_samples
    );

    let key_pair = GswKeyPair::generate_key_pair(&parameters);
    let bit_message = 1;

    let ciphertext = encrypt_bit(&parameters, &key_pair.public_key, bit_message);
    let decrypted_message = decrypt_bit(&parameters, ciphertext, &key_pair.secret_key);

    println!("message: {}", bit_message);
    println!("decrypted: {}", decrypted_message);

    assert_eq!(bit_message, decrypted_message);
}
