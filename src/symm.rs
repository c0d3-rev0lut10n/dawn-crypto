use openssl::symm::{encrypt as openssl_encrypt, decrypt as openssl_decrypt, Cipher};
use rand::Rng;

// encrypt message using aes-256-cbc
pub fn encrypt(data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
	let iv = rand::thread_rng().gen::<[u8; 16]>();
	let aes_cipher = Cipher::aes_256_cbc();
	let mut enc_msg = openssl_encrypt(aes_cipher, &key, Some(&iv), &data)?;
	let mut ciphertext = iv.to_vec();
	ciphertext.append(&mut enc_msg);
	Ok(ciphertext)
}

// decrypt message using aes-256-cbc
pub fn decrypt(mut ciphertext: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
	// check the length of the ciphertext
	if ciphertext.len() <= 16 { return Err("ciphertext too short".into()) }
	let enc_data = ciphertext.split_off(16);
	let aes_cipher = Cipher::aes_256_cbc();
	let dec_msg = openssl_decrypt(aes_cipher, &key, Some(&ciphertext), &enc_data)?;
	Ok(dec_msg)
}
