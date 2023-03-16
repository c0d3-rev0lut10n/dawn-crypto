use pqcrypto::kem::kyber1024::*;
use pqcrypto::prelude::*;
use hex::{encode, decode};
use ring::{digest, pbkdf2};
use std::num::NonZeroU32;
use openssl::symm::{encrypt, decrypt, Cipher};
use rand::Rng;
use rand_core::OsRng;
use std::array::TryFromSliceError;

pub fn keygen() -> (Vec<u8>, Vec<u8>) {
	let (pk, sk) = keypair();
	let public_key = pk.as_bytes().to_vec();
	let secret_key = sk.as_bytes().to_vec();
	(public_key, secret_key)
}

pub fn get_shared_secret(pub_key: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
	
	// import public key
	let pk = PublicKey::from_bytes(&pub_key)?;
	
	let (shared_secret, ciphertext) = encapsulate(&pk);
	let shared_secret = shared_secret
		.as_bytes()
		.to_vec();
	let ciphertext = ciphertext
		.as_bytes()
		.to_vec();
	
	Ok((shared_secret, ciphertext))
	
}

pub fn decrypt_shared_secret(ciphertext: Vec<u8>, sec_key: Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
	
	// import ciphertext
	let ciphertext = Ciphertext::from_bytes(&ciphertext)?;
	
	// import secret key
	let sk = SecretKey::from_bytes(&sec_key)?;
	
	Ok(decapsulate(&ciphertext, &sk).as_bytes().to_vec())
}
