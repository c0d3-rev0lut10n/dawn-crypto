use pqcrypto::prelude::*;
use pqcrypto::sign::sphincsharaka256frobust::{
	detached_sign,
	verify_detached_signature,
	keypair,
	PublicKey,
	SecretKey,
	DetachedSignature
};

// generate a keypair
pub fn keygen() -> (Vec<u8>, Vec<u8>) {
	
	let (pk, sk) = keypair();
	let public_key = pk.as_bytes().to_vec();
	let secret_key = sk.as_bytes().to_vec();
	(public_key, secret_key)
}

// sign a message
pub fn sign(sec_key: Vec<u8>, msg: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {

	let key = SecretKey::from_bytes(&sec_key)?;
	let signature = detached_sign(msg.as_bytes(), &key)
		.as_bytes()
		.to_vec();
	
	Ok(signature)
}

// verify a signature
pub fn verify(signature: Vec<u8>, pub_key: Vec<u8>, msg: &str) -> Result<(), Box<dyn std::error::Error>> {
	
	let key = PublicKey::from_bytes(&pub_key)?;
	let signature = DetachedSignature::from_bytes(&signature)?;
	verify_detached_signature(&signature, &msg.as_bytes(), &key)?;
	Ok(())
}
