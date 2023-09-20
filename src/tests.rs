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

#![allow(unused_variables)]

use crate::*;
use rand::Rng;
use regex::Regex;
use chrono::prelude::*;

// tests for the main module

#[test]
fn test_message_encryption() {
	// init test environment
	let (pk, sk) = kyber_keygen();
	let (sign_pk, sign_sk) = sign_keygen();
	let (other_sign_pk, other_sign_sk) = sign_keygen();
	let pfs_key = rand::thread_rng().gen::<[u8; 32]>();
	let salt = rand::thread_rng().gen::<[u8;32]>();
	
	// test encrypted and signed message
	let (enc_msg, new_key) = encrypt_msg(&pk, Some(&sign_sk), &pfs_key, &salt, "testing message encryption").unwrap();
	assert_ne!(pfs_key.to_vec(), new_key);
	assert_eq!(new_key.len(), 32);
	let (dec_msg, other_new_key, warning) = decrypt_msg(&sk, Some(&sign_pk), &pfs_key, &salt, &enc_msg).unwrap();
	assert_eq!(new_key, other_new_key);
	assert_eq!(dec_msg, "testing message encryption".to_string());
	assert_eq!(warning, warning::NONE);
	
	// test ignoring a present signature
	let (dec_msg, other_new_key, warning) = decrypt_msg(&sk, None, &pfs_key, &salt, &enc_msg).unwrap();
	assert_eq!(new_key, other_new_key);
	assert_eq!(dec_msg, "testing message encryption".to_string());
	assert_eq!(warning, warning::NONE);
	
	// test encrypted and unsigned message
	let (enc_msg, new_key) = encrypt_msg(&pk, None, &pfs_key, &salt, "testing message encryption").unwrap();
	assert_ne!(pfs_key.to_vec(), new_key);
	assert_eq!(new_key.len(), 32);
	let (dec_msg, other_new_key, warning) = decrypt_msg(&sk, Some(&sign_pk), &pfs_key, &salt, &enc_msg).unwrap();
	assert_eq!(new_key, other_new_key);
	assert_eq!(dec_msg, "testing message encryption".to_string());
	assert_eq!(warning, warning::NO_SIGNATURE);
	
	// test encrypted and wrongly signed message
	let (enc_msg, new_key) = encrypt_msg(&pk, Some(&other_sign_sk), &pfs_key, &salt, "testing message encryption").unwrap();
	assert_ne!(pfs_key.to_vec(), new_key);
	assert_eq!(new_key.len(), 32);
	assert_eq!(decrypt_msg(&sk, Some(&sign_pk), &pfs_key, &salt, &enc_msg), Err("signature verification failed".to_string()));
}

#[test]
fn test_curve_crypto() {
	let (pk1, sk1) = curve_keygen();
	let (pk2, sk2) = curve_keygen();
	assert_eq!(get_curve_secret(&sk2, &pk1).unwrap(), get_curve_secret(&sk1, &pk2).unwrap())
}

#[test]
fn test_mdc_gen() {
	let mdc = mdc_gen();
	let mdc_regex = Regex::new("^[0-9a-f]{8}$").unwrap();
	assert!(mdc_regex.is_match(&mdc))
}

#[test]
fn test_data_encryption() {
	let key = sym_key_gen();
	let data = vec![0,0,42,42];
	let ciphertext = encrypt_data(&data, &key).unwrap();
	assert_ne!(ciphertext, data);
	let dec_data = decrypt_data(&ciphertext, &key).unwrap();
	assert_eq!(data, dec_data);
}

#[test]
fn test_get_temp_id() {
	let id = id_gen();
	
	let c_time = Utc::now();
	let date_modifier = c_time.date_naive().format("%Y%m%d").to_string();
	let time_modifier = c_time.time().format("%H").to_string().parse::<u8>();
	
	// round to 4-hour resolution
	let time_modifier = time_modifier.unwrap() / 4;
	
	let modifier = date_modifier + &time_modifier.to_string();
	let human_readable_utc = c_time.date_naive().format("%d.%m.%Y").to_string() + " " + &c_time.time().format("%H:%M:%S").to_string();
	println!("\n[test_get_temp_id] UTC: {}\n[test_get_temp_id] modifier string: {}\n", human_readable_utc, modifier);
	assert_eq!(get_temp_id(&id), get_custom_temp_id(&id, &modifier));
}

#[test]
fn test_get_custom_temp_id() {
	let id = id_gen();
	assert!(get_custom_temp_id(&id, "").is_err());
	assert!(get_custom_temp_id("wrong id", "42").is_err());
	assert!(get_custom_temp_id(&id, "42").is_ok());
}

#[test]
fn test_get_next_id() {
	let id = id_gen();
	assert!(get_next_id("", "").is_err());
	assert!(get_next_id("a23e", "abcdabdcabdcabdc").is_err());
	assert!(get_next_id("wrong", "hi").is_err());
	assert!(get_next_id(&id, "invalid").is_err());
	assert!(get_next_id(&id, "42abdc42abdceffe42abdc42abdceffe42abdc42abdceffe42abdc42abdceffe").is_ok())
}

#[test]
fn test_get_curve_secret() {
	let (curve_pk, curve_sk) = curve_keygen();
	assert!(get_curve_secret(&curve_sk, &vec![]).is_err());
}

#[test]
fn test_get_all_timestamps_since() {
	println!("{:?}", get_all_timestamps_since("202308212"));
}
