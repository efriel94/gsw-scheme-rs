# GSW Scheme in Rust

This is a rust implementation of the levelled-HE GSW (Gentry Sahai Waters) scheme. Currently the implementation only supports encrypting single-bit plaintexts in the message space `{0,1}`.


## Todo

- [ ] Extend plaintext space to Z_p to recover any \mu in Z_q
- [ ] Add LWE based bootstrapping for FHE based version.
- [ ] Add levelled RLWE based version.
- [ ] Add RLWE based bootstrapping.
- [ ] Implement homomorphic NAND, addition, and multiplication operations.
- [ ] Add correctness tests for key generation, encryption, decryption, and flattening.
- [ ] Benchmark parameter choices and core matrix operations.
- [ ] Document supported parameters and security assumptions.
- [ ] Add examples for encrypting, decrypting, and evaluating simple circuits.

## References

[Original GSW Paper, June 2013](https://eprint.iacr.org/2013/340.pdf)
