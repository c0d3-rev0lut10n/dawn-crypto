mod hash;
mod id;
mod kyber;
mod mdc;
mod sign;
mod symm;
mod x25519;

#[cfg(test)]
mod tests;

use sign::*;
use hex::{encode, decode};

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

// This is a convenience function to generate a keypair and an id at the same time
pub fn init() -> ((Vec<u8>, Vec<u8>), Vec<u8>) {
	let keypair = kyber::keygen();
	let id = id::gen_id();
	(keypair, id)
}

// encrypt and sign message
// returns the encrypted and signed message and the new Perfect Forward Secrecy key on success
pub fn encrypt_msg(pub_key: Vec<u8>, sec_key: Vec<u8>, pfs_key: Vec<u8>, msg: &str) -> Result<(Vec<u8>, Vec<u8>), String> {

	// get shared secret and ciphertext for kyber encryption
	let (kyber_shared_secret, kyber_ciphertext) = match kyber::get_shared_secret(pub_key) {
		Ok((shared_secret, ciphertext)) => {
			(shared_secret, ciphertext)
		}
		Err(_) => {
			error!("failed to get kyber shared secret")
		}
	};
	println!("{}", kyber_ciphertext.len());
	
	// derive new Perfect Forward Secrecy key
	let mut pfs_shared_secret = hash::get_pfs_key(pfs_key);
	
	// derive secret
	let mut shared_secret = kyber_shared_secret.clone();
	shared_secret.append(&mut pfs_shared_secret);
	let secret = hash::hash(shared_secret);
	
	// sign the message
	let signature = match sign(sec_key, msg) {
		Ok(sig) => encode(sig),
		Err(_) => {
			error!("failed to sign message")
		}
	};
	let signed_message = (signature + "." + msg).as_bytes().to_vec();
	
	// symmetric encryption of the message using the shared secret
	let enc_msg = symm::encrypt(signed_message, secret);
	if enc_msg.is_err() { error!("symmetric encryption failed"); }
	
	let mut final_message = kyber_ciphertext;
	final_message.append(&mut enc_msg.unwrap());
	
	Ok((final_message, pfs_shared_secret))
}

// decrypt message and optionally check signature
// returns the message content and the new Perfect Forward Secrecy key on success
pub fn decrypt_msg(sec_key: Vec<u8>, pub_key: Option<Vec<u8>>, pfs_key: Vec<u8>, enc_msg: Vec<u8>) -> Result<(String, Vec<u8>), String> {
	
	// check message length
	if enc_msg.len() <= 1568+16 { error!("message too short"); }
	let mut enc_msg = enc_msg;
	
	// extract kyber ciphertext and symmetrically encrypted message
	let symm_enc_msg = enc_msg.split_off(1568);
	println!("{}", enc_msg.len());
	
	// decrypt kyber shared secret
	let kyber_shared_secret = match kyber::decrypt_shared_secret(enc_msg, sec_key) {
		Ok(res) => res,
		Err(_) => {
			error!("could not decrypt kyber secret");
		}
	};
	
	// derive new Perfect Forward Secrecy key
	let mut pfs_shared_secret = hash::get_pfs_key(pfs_key);
	
	// derive secret
	let mut shared_secret = kyber_shared_secret.clone();
	shared_secret.append(&mut pfs_shared_secret);
	let secret = hash::hash(shared_secret);
	
	// decrypt message
	let dec_msg = symm::decrypt(symm_enc_msg, secret);
	if dec_msg.is_err() { error!("symmetric decryption failed"); }
	let dec_msg = dec_msg.unwrap();
	
	// split signature and message
	let signed_msg_string = String::from_utf8_lossy(&dec_msg);
	let (signature, message) = match signed_msg_string.split_once(".") {
		Some((sig, msg)) => (decode(&sig), msg),
		None => { error!("signature not found"); }
	};
	let signature = match signature {
		Ok(sig) => sig,
		Err(_) => { error!("signature parsing failed"); }
	};
	
	// verify signature if requested
	if pub_key.is_some() {
		if verify(signature, pub_key.unwrap(), message).is_err() { error!("signature verification failed"); }
	}
	
	// return the message and new PFS key
	Ok((message.to_string(), pfs_shared_secret))
}
