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

use pqcrypto::prelude::*;
use pqcrypto::sign::sphincsshake192fsimple::{
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
pub fn sign(sec_key: &[u8], msg: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {

	let key = SecretKey::from_bytes(sec_key)?;
	let signature = detached_sign(msg.as_bytes(), &key)
		.as_bytes()
		.to_vec();
	
	Ok(signature)
}

// verify a signature
pub fn verify(signature: &[u8], pub_key: &[u8], msg: &str) -> Result<(), Box<dyn std::error::Error>> {
	
	let key = PublicKey::from_bytes(pub_key)?;
	let signature = DetachedSignature::from_bytes(signature)?;
	verify_detached_signature(&signature, msg.as_bytes(), &key)?;
	Ok(())
}
