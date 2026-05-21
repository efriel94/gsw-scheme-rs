use gsw_scheme::gsw::{decrypt_bit, encrypt_bit, GswKeyPair, GswParameters};

fn main() {
    let parameters = GswParameters::new(
        4,    // n
        1024, // q
        1,    // B
        64,   // m
    );

    let key_pair = GswKeyPair::generate_key_pair(&parameters);
    let bit_message = 1;

    let ciphertext = encrypt_bit(&parameters, &key_pair.public_key, bit_message);
    let decrypted_message = decrypt_bit(&parameters, ciphertext, &key_pair.secret_key);

    println!("message: {}", bit_message);
    println!("decrypted: {}", decrypted_message);

    assert_eq!(bit_message, decrypted_message);

}
