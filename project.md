# Lightweight (stream) ciphers implementation in Rust

## Student

- Grégoire FRÉMION `gregoire.fremion@telecom-sudparis.eu`

## Description

The project's aim is to implement stream ciphers and potentially block ciphers in Rust, following the styles and guidelines of the crate [RustCrypto](https://github.com/RustCrypto) which is a well known crate (in fact, rather a collection of crates) for cryptography. The final goal would be to integrate the project into the RustCrypto crate. 

I would like first to focus on lightweight ciphers, that seems missing in RustCrypto but which are interesting in my opinion because Rust is more and more present in IoT and embeded systems, that are often ressources-limited and need (good) lightweight cryptography.

The project will have several steps : 

- The first one will be to figure out how the implementation should be done in order to be potentialy integrated in the future to the RustCrypto crate,
- Secondly, implement, write the documentation and code the tests for some ciphers that are missing from the RustCrypto crate. Ciphers considered as secure are missing in RustCrypto, the two firsts ciphers that I want to implement would be Trivium \[1\] (a stream cipher) which is relatively simple, and then grain-128AEADv2 \[2\] (another stream cipher but with authenticated encryption and associated data). Then other symetric ciphers or even other cryptographic primitives might be implemented, depending on the time remaining.
- Create benchmarks to identify potential implementations and compare the performances with existing implementations of the ciphers,
-  (Integrate the crate in the RustCrypto project)

## References

\[1\] Cannière, C. D., & Preneel, B. (2008). Trivium. In New stream cipher designs (pp. 244-266). Springer, Berlin, Heidelberg.

\[2\] M. Hell, T. Johansson, A. Maximov, W. Meier, J. Sönnerup, H. Yoshida. (2021). Grain-128AEADv2 - A lightweight AEAD stream cipher
