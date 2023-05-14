# Cryptographic library for use in the Dawn messenger

*licensed under GPL version 3 or higher*

This is the repository containing the core functions used in the standard library of the **Dawn messenger**, which is going to be released soon. This code is still experimental and any use for production, especially for applications where security is critical, is **NOT** recommended as of now.

It is used by the [Dawn standard library](https://github.com/c0d3-rev0lut10n/dawn-stdlib) to provide cryptographical functionalities.

## Dependencies

This library uses post-quantum cryptography provided by [PQClean](https://github.com/PQClean/PQClean) through the rust bindings in [pqcrypto](https://github.com/rustpq/pqcrypto).

It also uses [rust-openssl](https://github.com/sfackler/rust-openssl), which provides the necessary functionality to use AES-256 and SHA-256.

[x25519-dalek](https://github.com/dalek-cryptography/x25519-dalek) is used to incorporate a classic asymmetric cryptography system.

## Functionality

### Generating keys

The following functions all generate a tuple with a random keypair in the format (*public key*, *private key*):

* kyber_keygen() generates a kyber keypair (used for asymmetric post-quantum encryption)
* sign_keygen() generates a Sphincs-Haraka-256f-robust keypair (used for asymmetric post-quantum signing)
* curve_keygen() generates a x25519 keypair (traditional asymmetric encryption)

For convenience, there is also **init()** which will generate you both keypairs used for encryption and also an ID at once. Therefore, the separate functions are only really necessary if you want to regenerate keys for an existing chat. Those might be used in a future version of *dawn-stdlib*, whcih will implement group chats.

### ID System

Dawn takes a zero-trust approach towards the server. This even includes the information about who you are chatting with, at what time and so on. However, the server obviously needs a way to determine what message is for you. To make that possible, a temporary ID is calculated using a seed and a modifier, the latter is based on the current UTC time, which are put together and hashed. This means that a Dawn client will generate new temporary IDs for every chat at a given time (by default, this is going to be 4 hours). Since your IP address would give away some information that might make it easy to reconstruct which old ID corresponds to which new ID, the requests need to use **fresh TOR circuits** at least every time you rotate the IDs. This needs to be implemented by a Dawn client and is not a feature of this library. The following functions only provide a base to make dealing with those rotating IDs more convenient.

* id_gen() provides a new randomly generated seed
* get_temp_id() calculates a temporary ID from your seed and the current modifier. Use the result of this as the ID you send to the server.
* get_next_id() derives a new seed from your given seed. Use this every time you rotate an ID to provide forward secrecy regarding used IDs.
