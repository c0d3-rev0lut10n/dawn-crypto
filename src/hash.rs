use openssl::sha::sha256 as hash_function;

pub fn hash(input: &[u8]) -> Vec<u8> {
	return hash_function(&input).to_vec();
}

pub fn get_pfs_key(key: Vec<u8>) -> Vec<u8> {
	return hash_function(&key).to_vec();
}
