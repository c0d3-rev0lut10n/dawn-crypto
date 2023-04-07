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
