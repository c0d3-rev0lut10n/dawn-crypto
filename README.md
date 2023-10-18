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

* **kyber_keygen()** generates a kyber keypair (used for asymmetric post-quantum encryption)
* **sign_keygen()** generates a Sphincs-Shake-192f-robust keypair (used for asymmetric post-quantum signing)
* **curve_keygen()** generates a x25519 keypair (traditional asymmetric encryption)

**sym_keygen()** generates a random key you can use for manual symmetric encryption. This can be used for encrypting files that get stored on a content server. In this case, you would only transmit the key in your message, reducing bandwidth and data usage on the message server and offloading it to easily scalable and self-hostable content servers.

For convenience, there is also **init()** which will generate you both keypairs used for encryption and also an ID at once. Therefore, the separate functions are only really necessary if you want to regenerate keys for an existing chat. Those might be used in a future version of *dawn-stdlib*, whcih will implement group chats.

### Encrypting/Decrypting

There are two easily usable functions for encrypting and decrypting messages. These can be used in normal messaging and as a part of the *init* process:

* **encrypt_msg(pub_key, sec_key, pfs_key, msg)** takes the kyber public key of your recipient, your secret signature key, a shared key for Perfect Forward Secrecy and the content of the message. It returns the message ciphertext and your new PFS shared key on success.
* **decrypt_msg(sec_key, pub_key, pfs_key, enc_msg)** takes your secret key for kyber decryption, an optional public key for verifying the signature, a shared key for Perfect Forward Secrecy and the ciphertext. It returns the content of the message and your new PFS shared key on success.

To encrypt data, for example bigger media files, there are also **encrypt_data(data, key)** and **decrypt_data(ciphertext, key)** which use AES-256 to symmetrically encrypt and decrypt byte arrays.

### Verifying security

To make sure that there is no MITM attack on the communication between two clients, you need a way to verify that your chat partner indeed has the public key that corresponds to your secret key and vice-versa. That functionality is provided by **derive_security_number(key_a, key_b)**. You need to provide the public key of the party that initiated the chat as *key_a* and the other public key as *key_b* (you could do it in the exact opposite way, but the point is that both clients need to do it identically). Show the returned value to the user to give them opportunity to verify the connection security by comparing the security numbers in a real-life meeting or over a verified secure connection.

### ID System

Dawn takes a zero-trust approach towards the server. This even includes the information about who you are chatting with, at what time and so on. However, the server obviously needs a way to determine what message is for you. To make that possible, a temporary ID is calculated using a seed and a modifier, the latter is based on the current UTC time, which are put together and hashed. This means that a Dawn client will generate new temporary IDs for every chat at a given time (by default, this is going to be 4 hours). Since your IP address would give away some information that might make it easy to reconstruct which old ID corresponds to which new ID, the requests need to use **fresh TOR circuits** at least every time you rotate the IDs. This needs to be implemented by a Dawn client and is not a feature of this library. The following functions only provide a base to make dealing with those rotating IDs more convenient.

* id_gen() provides a new randomly generated seed
* get_temp_id() calculates a temporary ID from your seed and the current modifier. Use the result of this as the ID you send to the server.
* get_next_id() derives a new seed from your given seed. Use this every time you rotate an ID to provide forward secrecy regarding used IDs.

### Miscellaneous

#### Getting the shared PFS key upon initialization of a chat

When you initialize a chat, you take the public key of your chat partner, generate your own elliptic-curve based keypair and derive the shared secret using a Diffie-Hellman-Handshake. The receiving party does the same with your generated public key. **get_curve_secret(secret_key, public_key)** is used to derive the shared secret.

#### Generating a Message Detail Code

In order to verify the permission to get metadata about a message or delete it, the server verifies a Message Detail Code. When sending a message, you generate one, send it in your encrypted message and also send it to the server in clear text. When you want to get details about a received message or want to delete your sent/received message, you need to provide the MDC to the server.
Essentially, a MDC is a random 8-character long hex string. You can generate one using the self-explanatory **mdc_gen()**.
