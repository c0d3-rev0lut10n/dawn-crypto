use x25519_dalek::{StaticSecret, PublicKey};
use rand_core::OsRng;

pub fn keygen() -> (Vec<u8>, Vec<u8>) {
	let secret = StaticSecret::new(OsRng);
	let public_key = PublicKey::from(&secret);
	let secret = secret.to_bytes().to_vec();
	let public_key = public_key.as_bytes().to_vec();
	(public_key, secret)
}

pub fn get_shared_secret(secret: Vec<u8>, public_key: Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
	let secret_byte_array : [u8;32] = secret.as_slice().try_into()?;
	let secret = StaticSecret::from(secret_byte_array);
	let pubkey_byte_array : [u8;32] = public_key.as_slice().try_into()?;
	let pk = PublicKey::from(pubkey_byte_array);
	let shared_secret = secret.diffie_hellman(&pk).as_bytes().to_vec();
	Ok(shared_secret)
}
