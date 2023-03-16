use hex::encode;
use rand::Rng;

// generate id seed
pub fn gen_id() -> Vec<u8> {
	let id = rand::thread_rng()
		.gen::<[u8; 16]>()
		.to_vec();
	id
}

// generate temporary id using seed and modifier (i.e. time)
pub fn get_temp_id(idstring: &str, modifier: &str) -> String {
	let input = "".to_owned() + idstring + modifier;
	let hash = encode(&openssl::sha::sha256(input.as_bytes()));
	hash
}

// hash with sha256 to get next id-seed or aes-key-seed, used for Perfect Forward Secrecy
pub fn get_next(current: &str) -> String {
	let hash = encode(&openssl::sha::sha256(current.as_bytes()));
	hash
}
