# GSW Scheme in Rust

A modular and extensible implementation of the Gentry-Sahai-Waters (GSW) somewhat homomorphic encryption scheme in Rust.

This project is in active development but will provide a generic GSW framework designed to support multiple underlying hardness assumptions: LWE, RLWE and NTRU, a range of decomposition strategies and external product constructions.

## Problem statement

Applying GSW based techniques is becoming an increasingly popular method to use for building Fully Homomorphic Encryption schemes. To allow rapid user development and experiementation of GSW based FHE schemes there is a lack of open source libraries that provide intuitive interfaces to the GSW scheme. 

The purpose of this project is to enable rapid development to extend upwards from GSW-based somewhat HE scheme to Fully Homomorphic Encryption (FHE) 


## References

[Original GSW Paper, June 2013](https://eprint.iacr.org/2013/340.pdf)