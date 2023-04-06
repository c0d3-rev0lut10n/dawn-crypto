use crate::*;
use rand::Rng;
use regex::Regex;

// tests for the main module

#[test]
fn test_message_encryption() {
	let (pk, sk) = kyber_keygen();
	let (sign_pk, sign_sk) = sign_keygen();
	let pfs_key = rand::thread_rng().gen::<[u8; 32]>().to_vec();
	let (enc_msg, new_key) = encrypt_msg(pk, sign_sk, pfs_key.clone(), "testing message encryption").unwrap();
	assert_ne!(pfs_key, new_key);
	let (dec_msg, other_new_key) = decrypt_msg(sk, Some(sign_pk), pfs_key, enc_msg).unwrap();
	assert_eq!(new_key, other_new_key);
	assert_eq!(dec_msg, "testing message encryption".to_string());
	
}

#[test]
fn test_curve_crypto() {
	let (pk1, sk1) = curve_keygen();
	let (pk2, sk2) = curve_keygen();
	assert_eq!(get_curve_secret(sk2, pk1).unwrap(), get_curve_secret(sk1, pk2).unwrap())
}

#[test]
fn test_mdc_gen() {
	let mdc = mdc_gen();
	let mdc_regex = Regex::new("^[0-9a-f]{8}$").unwrap();
	assert!(mdc_regex.is_match(&mdc))
}
