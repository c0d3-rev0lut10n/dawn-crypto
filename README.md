# Cryptographic library for use in the Dawn messenger

*licensed under GPL version 3 or higher*

This is the repository containing the core functions used in the standard library of the **Dawn messenger**, which is going to be released soon. This code is still experimental and any use for production, especially for applications where security is critical, is **NOT** recommended as of now.

It is used by the [Dawn standard library](https://github.com/c0d3-rev0lut10n/dawn-stdlib) to provide cryptographical functionalities.

## Dependencies

This library uses post-quantum cryptography provided by [PQClean](https://github.com/PQClean/PQClean) through the rust bindings in [pqcrypto](https://github.com/rustpq/pqcrypto).

It also uses [rust-openssl](https://github.com/sfackler/rust-openssl), which provides the necessary functionality to use AES-256 and SHA-256.

[x25519-dalek](https://github.com/dalek-cryptography/x25519-dalek) is used to incorporate a classic asymmetric cryptography system.
