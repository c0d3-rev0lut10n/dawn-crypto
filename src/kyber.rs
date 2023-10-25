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

use pqcrypto::kem::kyber1024::*;
use pqcrypto::prelude::*;

pub fn keygen() -> (Vec<u8>, Vec<u8>) {
	let (pk, sk) = keypair();
	let public_key = pk.as_bytes().to_vec();
	let secret_key = sk.as_bytes().to_vec();
	(public_key, secret_key)
}

pub fn get_shared_secret(pub_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
	
	// import public key
	let pk = PublicKey::from_bytes(pub_key)?;
	
	let (shared_secret, ciphertext) = encapsulate(&pk);
	let shared_secret = shared_secret
		.as_bytes()
		.to_vec();
	let ciphertext = ciphertext
		.as_bytes()
		.to_vec();
	
	Ok((shared_secret, ciphertext))
	
}

pub fn decrypt_shared_secret(ciphertext: &[u8], sec_key: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
	
	// import ciphertext
	let ciphertext = Ciphertext::from_bytes(ciphertext)?;
	
	// import secret key
	let sk = SecretKey::from_bytes(sec_key)?;
	
	Ok(decapsulate(&ciphertext, &sk).as_bytes().to_vec())
}
