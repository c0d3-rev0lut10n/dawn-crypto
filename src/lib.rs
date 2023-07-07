/*	Copyright (c) 2022, 2023 Laurenz Werner
	
	This file is part of Dawn.
	
	Dawn is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.
	
	Dawn is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.
	
	You should have received a copy of the GNU General Public License
	along with Dawn.  If not, see <http://www.gnu.org/licenses/>.
*/

mod hash;
mod id;
mod kyber;
mod sign;
mod symm;
pub mod warning;
mod x25519;

#[macro_use]
extern crate lazy_static;

#[cfg(test)]
mod tests;

use sign::*;
use hex::{encode, decode};
use rand::Rng;
use crate::warning::*;

// Error return macro
macro_rules! error{
	($a:expr) => {
		return Err($a.to_string())
	}
}

// This returns a tuple with the public and secret key that got generated (for encrypting)
pub fn kyber_keygen() -> (Vec<u8>, Vec<u8>) {
	kyber::keygen()
}

// This returns a tuple with the public and secret key that got generated (for signing)
pub fn sign_keygen() -> (Vec<u8>, Vec<u8>) {
	sign::keygen()
}

// This returns a tuple with the public and secret key that got generated (for init, using x25519)
pub fn curve_keygen() -> (Vec<u8>, Vec<u8>) {
	x25519::keygen()
}

// This returns the shared secret derived from x25519 keys using Diffie-Hellman
pub fn get_curve_secret(secret_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>, String> {
	match x25519::get_shared_secret(secret_key, public_key) {
		Ok(res) => Ok(res),
		Err(_) => {
			error!("failed to derive curve secret");
		}
	}
}

// This is a convenience function to generate the keypairs and an id at the same time
pub fn init() -> ((Vec<u8>, Vec<u8>), (Vec<u8>, Vec<u8>), (Vec<u8>, Vec<u8>), (Vec<u8>, Vec<u8>), String) {
	let keypair_kyber = kyber::keygen();
	let keypair_curve = x25519::keygen();
	let keypair_kyber_for_salt = kyber::keygen();
	let keypair_curve_for_salt = x25519::keygen();
	let id = id::gen_id();
	(keypair_kyber, keypair_curve, keypair_kyber_for_salt, keypair_curve_for_salt, id)
}

// generate an id
pub fn id_gen() -> String {
	id::gen_id()
}

// generate message detail code
pub fn mdc_gen() -> String {
	let id = rand::thread_rng()
		.gen::<[u8; 4]>()
		.to_vec();
	encode(id)
}

// generate a key for symmetric encryption (e.g. for sending files) using a CSPRNG
pub fn sym_key_gen() -> Vec<u8> {
	let key = rand::thread_rng()
		.gen::<[u8; 32]>()
		.to_vec();
	key
}

// get a temporary id from a seed and the default modifier
pub fn get_temp_id(id: &str) -> Result<String, String> {
	id::get_temp_id(id)
}

// get a temporary id from a seed and a modifier (e.g. time)
pub fn get_custom_temp_id(id: &str, modifier: &str) -> Result<String, String> {
	id::get_custom_temp_id(id, modifier)
}

// get next id for PFS-based id generation
pub fn get_next_id(id: &str, salt: &str) -> Result<String, String> {
	id::get_next(id, salt)
}

// encrypt (and optionally sign) message
// returns the encrypted and signed message and the new Perfect Forward Secrecy key on success
pub fn encrypt_msg(pub_key: &[u8], sec_key: Option<&[u8]>, pfs_key: &[u8], salt: &[u8], msg: &str) -> Result<(Vec<u8>, Vec<u8>), String> {

	// get shared secret and ciphertext for kyber encryption
	let (kyber_shared_secret, kyber_ciphertext) = match kyber::get_shared_secret(pub_key) {
		Ok((shared_secret, ciphertext)) => {
			(shared_secret, ciphertext)
		}
		Err(_) => {
			error!("failed to get kyber shared secret")
		}
	};
	
	// check key length
	if pfs_key.len() != 32 { error!(format!("CRITICAL: PFS key has wrong length. Expected 32 bytes, got {} bytes", pfs_key.len())); }
	
	// check salt length
	if salt.len() != 16 { error!(format!("CRITICAL: PFS key has wrong length. Expected 16 bytes, got {} bytes", salt.len())); }
	
	// derive new Perfect Forward Secrecy key
	let mut pfs_shared_secret = hash::get_pfs_key(&pfs_key, &salt);
	let new_pfs_key = pfs_shared_secret.clone();
	
	// derive secret
	let mut shared_secret = kyber_shared_secret.clone();
	shared_secret.append(&mut pfs_shared_secret);
	let secret = hash::hash(&shared_secret);
	
	// sign the message if requested
	let signature;
	if sec_key.is_some() {
		signature = match sign(sec_key.unwrap(), msg) {
			Ok(sig) => encode(sig),
			Err(_) => {
				error!("failed to sign message")
			}
		};
	}
	else {
		signature = "".to_string();
	}
	let signed_message_string = signature + "." + msg;
	let signed_message = signed_message_string.as_bytes();
	
	// symmetric encryption of the message using the shared secret
	let enc_msg = symm::encrypt(signed_message, &secret);
	if enc_msg.is_err() { error!("symmetric encryption failed"); }
	
	let mut final_message = kyber_ciphertext;
	final_message.append(&mut enc_msg.unwrap());
	
	Ok((final_message, new_pfs_key))
}

// decrypt message and optionally check signature
// returns the message content and the new Perfect Forward Secrecy key on success. Also, there is a cumulative byte indicating warnings.
pub fn decrypt_msg(sec_key: &[u8], pub_key: Option<&[u8]>, pfs_key: &[u8], salt: &[u8], enc_msg: &[u8]) -> Result<(String, Vec<u8>, u8), String> {
	
	// initialize warnings
	let mut warning = 0u8;
	
	// check message length
	if enc_msg.len() <= 1568+16 { error!("message too short"); }
	let mut enc_msg = enc_msg.to_vec();
	
	// check salt length
	if salt.len() != 16 { error!(format!("CRITICAL: PFS key has wrong length. Expected 16 bytes, got {} bytes", salt.len())); }
	
	// extract kyber ciphertext and symmetrically encrypted message
	let symm_enc_msg = enc_msg.split_off(1568);
	
	// decrypt kyber shared secret
	let kyber_shared_secret = match kyber::decrypt_shared_secret(&enc_msg, sec_key) {
		Ok(res) => res,
		Err(_) => {
			error!("could not decrypt kyber secret");
		}
	};
	
	// check key length
	if pfs_key.len() != 32 { error!(format!("CRITICAL: PFS key has wrong length. Expected 32 bytes, got {} bytes", pfs_key.len())); }
	
	// derive new Perfect Forward Secrecy key
	let mut pfs_shared_secret = hash::get_pfs_key(&pfs_key, &salt);
	let new_pfs_key = pfs_shared_secret.clone();
	
	// derive secret
	let mut shared_secret = kyber_shared_secret.clone();
	shared_secret.append(&mut pfs_shared_secret);
	let secret = hash::hash(&shared_secret);
	
	// decrypt message
	let dec_msg = symm::decrypt(&symm_enc_msg, &secret);
	if dec_msg.is_err() { error!("symmetric decryption failed"); }
	let dec_msg = dec_msg.unwrap();
	
	// split signature and message
	let signed_msg_string = String::from_utf8_lossy(&dec_msg);
	let (signature, message) = match signed_msg_string.split_once(".") {
		Some((sig, msg)) => {
			// since signatures are optional, handle a missing signature gracefully
			if sig.len() == 0 {
				warning += NO_SIGNATURE;
				return Ok((msg.to_string(), new_pfs_key, warning))
			}
			(decode(&sig), msg)
		},
		None => { error!("signature not found"); }
	};
	let signature = match signature {
		Ok(sig) => sig,
		Err(_) => { error!("signature parsing failed"); }
	};
	
	// verify signature if requested
	if pub_key.is_some() {
		if verify(&signature, &pub_key.unwrap(), message).is_err() { error!("signature verification failed"); }
	}
	
	// return the message and new PFS key
	Ok((message.to_string(), new_pfs_key, warning))
}

// encrypt data using a symmetric key
pub fn encrypt_data(data: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
	let encrypted = symm::encrypt(data, key);
	if encrypted.is_err() { error!("symmetric encryption failed"); }
	Ok(encrypted.unwrap())
}

// decrypt data using a symmetric key
pub fn decrypt_data(encrypted_data: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
	let data = symm::decrypt(encrypted_data, key);
	if data.is_err() { error!("symmetric decryption failed"); }
	Ok(data.unwrap())
}

// calculates security number for given keys
// to use it correctly, key_a needs to be the key from the party that sent the init request
pub fn derive_security_number(key_a: &[u8], key_b: &[u8]) -> Result<String, String> {
	if key_a.len() == 0 || key_b.len() == 0 {
		return Err("Both keys must be longer than zero bytes each".to_string())
	}
	let mut key_a = key_a.to_vec();
	let mut key_b = key_b.to_vec();
	key_a.append(&mut key_b);
	Ok(encode(hash::hash(&key_a)))
}
