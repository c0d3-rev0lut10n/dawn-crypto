use openssl::sha::sha256 as hash_function;
use hex::encode;

pub fn hash(input: Vec<u8>) -> Vec<u8> {
	return hash_function(&input).to_vec();
}

pub fn get_pfs_key(key: Vec<u8>) -> Vec<u8> {
	return hash_function(&key).to_vec();
}
