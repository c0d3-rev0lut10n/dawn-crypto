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
use chrono::{Duration, prelude::*};

lazy_static! {
	static ref IS_ID_SEED: Regex = Regex::new("^[0-9a-f]{64}$").unwrap();
	static ref IS_SALT: Regex = Regex::new("^[0-9a-f]{64}$").unwrap();
}

// generate id seed
pub fn gen_id() -> String {
	let id = rand::thread_rng()
		.gen::<[u8; 32]>();
	encode(id)
}

// generate temporary id using seed and default modifier
pub fn get_temp_id(id: &str) -> Result<String, String> {
	if !IS_ID_SEED.is_match(id) {
		return Err("invalid id".to_string())
	}
	
	// get current time
	let c_time = Utc::now();
	let date_modifier = c_time.date_naive().format("%Y%m%d").to_string();
	let time_modifier = c_time.time().format("%H").to_string().parse::<u8>();
	if time_modifier.is_err() {
		return Err("failed to format time".to_string());
	}
	
	// round to 4-hour resolution
	let time_modifier = time_modifier.unwrap() / 4;
	
	let modifier = date_modifier + &time_modifier.to_string();
	let input = String::from(id) + &modifier;
	let hash = encode(&hash::hash(input.as_bytes()));
	Ok(hash)
}

// generate temporary id using seed and modifier (i.e. time)
pub fn get_custom_temp_id(id: &str, modifier: &str) -> Result<String, String> {
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
pub fn get_next(current: &str, salt: &str) -> Result<String, String> {
	if !IS_ID_SEED.is_match(current) {
		return Err("invalid id".to_string())
	}
	if !IS_SALT.is_match(salt) {
		return Err("invalid salt".to_string())
	}
	let mut hash_input = current.as_bytes().to_vec();
	hash_input.append(&mut salt.as_bytes().to_vec());
	let hash = encode(&hash::hash(&hash_input));
	Ok(hash)
}


// this returns the current timestamp
pub fn get_current_timestamp() -> Result<String, String> {
	// get current time
	let c_time = Utc::now();
	let date_modifier = c_time.date_naive().format("%Y%m%d").to_string();
	let time_modifier = c_time.time().format("%H").to_string().parse::<u8>();
	if time_modifier.is_err() {
		return Err("failed to format time".to_string());
	}
	
	// round to 4-hour resolution
	let time_modifier = time_modifier.unwrap() / 4;
	
	let modifier = date_modifier + &time_modifier.to_string();
	Ok(modifier)
}

// this returns a list of all timestamps from the given input timestamp until the current timestamp
pub fn get_all_timestamps_since(timestamp: &str) -> Result<Vec<String>, String> {
	let time = match parse_timestamp(timestamp) {
		Ok(res) => res,
		Err(err) => return Err(err)
	};
	
	let current_time = Utc::now().naive_utc();
	
	if time > current_time { return Err("timestamp is in the future".to_string()); }
	
	let mut timestamps = Vec::<String>::new();
	let mut time_to_check = time;
	let interval = Duration::hours(4);
	timestamps.push(timestamp.to_string());
	loop {
		time_to_check = time_to_check.checked_add_signed(interval).unwrap();
		if time_to_check > current_time { break; }
		timestamps.push(get_timestamp(time_to_check))
	}
	
	return Ok(timestamps)
}

fn parse_timestamp(timestamp: &str) -> Result<NaiveDateTime, String> {
	if timestamp.len() != 9 {
		return Err("invalid timestamp length".to_string());
	}
	
	let timestamp_date = match NaiveDate::parse_from_str(&timestamp[0..8], "%Y%m%d") {
		Ok(res) => res,
		Err(_) => return Err("failed to parse the date".to_string())
	};
	let timestamp_hour = match &timestamp[8..9].parse::<u32>() { // parsing as u32 because chrono's and_hms_opt requires this as input. Otherwise, u8 would be fine obviously
		Ok(res) => 4 * res,
		Err(_) => return Err("failed to parse the time modifier".to_string())
	};
	let time = match timestamp_date.and_hms_opt(timestamp_hour, 0, 0) {
		Some(res) => res,
		None => return Err("failed to add the time modifier".to_string())
	};
	Ok(time)
}

fn get_timestamp(time: NaiveDateTime) -> String {
	let date_modifier = time.format("%Y%m%d").to_string();
	let time_modifier = time.format("%H").to_string().parse::<u8>().unwrap();
	
	// round to 4-hour resolution
	let time_modifier = time_modifier / 4;
	
	let modifier = date_modifier + &time_modifier.to_string();
	modifier
}
