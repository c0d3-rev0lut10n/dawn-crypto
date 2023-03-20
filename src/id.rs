use hex::encode;
use rand::Rng;
use crate::hash;

// generate id seed
pub fn gen_id() -> String {
	let id = rand::thread_rng()
		.gen::<[u8; 16]>()
		.to_vec();
	encode(id)
}

// generate temporary id using seed and modifier (i.e. time)
pub fn get_temp_id(id: &str, modifier: &str) -> String {
	let input = String::from(id) + modifier;
	let hash = encode(&hash::hash(input.as_bytes()));
	hash
}

// hash with sha256 to get next id-seed or aes-key-seed, used for Perfect Forward Secrecy
pub fn get_next(current: &str) -> String {
	let hash = encode(&hash::hash(current.as_bytes()));
	hash
}
