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

use openssl::symm::{encrypt as openssl_encrypt, decrypt as openssl_decrypt, Cipher};
use rand::Rng;

// encrypt message using aes-256-cbc
pub fn encrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
	if key.len() != 32 {
		return Err("key length invalid".into())
	}
	let iv = rand::thread_rng().gen::<[u8; 16]>();
	let aes_cipher = Cipher::aes_256_cbc();
	let mut enc_msg = openssl_encrypt(aes_cipher, key, Some(&iv), data)?;
	let mut ciphertext = iv.to_vec();
	ciphertext.append(&mut enc_msg);
	Ok(ciphertext)
}

// decrypt message using aes-256-cbc
pub fn decrypt(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
	if key.len() != 32 {
		return Err("key length invalid".into())
	}
	let mut ciphertext = ciphertext.to_vec();
	// check the length of the ciphertext
	if ciphertext.len() <= 16 { return Err("ciphertext too short".into()) }
	let enc_data = ciphertext.split_off(16);
	let aes_cipher = Cipher::aes_256_cbc();
	let dec_msg = openssl_decrypt(aes_cipher, key, Some(&ciphertext), &enc_data)?;
	Ok(dec_msg)
}
