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

use hex::encode;
use rand::Rng;
use regex::Regex;
use crate::hash;

lazy_static! {
	static ref IS_ID_SEED: Regex = Regex::new("^[0-9a-f]{64}$").unwrap();
}

// generate id seed
pub fn gen_id() -> String {
	let id = rand::thread_rng()
		.gen::<[u8; 32]>();
	encode(id)
}

// generate temporary id using seed and modifier (i.e. time)
pub fn get_temp_id(id: &str, modifier: &str) -> Result<String, String> {
	if !IS_ID_SEED.is_match(id) {
		return Err("invalid id".to_string())
	}
	if modifier.is_empty() {
		return Err("modifier was empty".to_string())
	}
	let input = String::from(id) + modifier;
	let hash = encode(&hash::hash(input.as_bytes()));
	Ok(hash)
}

// hash with sha256 to get next id-seed or aes-key-seed, used for Perfect Forward Secrecy
pub fn get_next(current: &str) -> Result<String, String> {
	if !IS_ID_SEED.is_match(current) {
		return Err("invalid id".to_string())
	}
	let hash = encode(&hash::hash(current.as_bytes()));
	Ok(hash)
}
