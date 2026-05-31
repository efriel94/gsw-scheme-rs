use gsw_scheme::constructions::gsw::{GswInstance, GswParameters, decrypt_bit, encrypt_bit};

fn main() {
    let parameters = GswParameters::new(
        4,          // lwe_dimension
        1024,  // ciphertext_modulus
        1,            // error_bound
        64,    // public_key_samples
    );

    let gsw_instance = GswInstance::generate(&parameters); // returns c = [b | B] where b is the private component augmented with the public B matrix
    let bit_message = 1;

    let ciphertext = encrypt_bit(&parameters, &gsw_instance.public_component, bit_message);
    let decrypted_message = decrypt_bit(&parameters, ciphertext, &gsw_instance.private_component);

    println!("message: {}", bit_message);
    println!("decrypted: {}", decrypted_message);

    assert_eq!(bit_message, decrypted_message);
}
