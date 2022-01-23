#[cfg(test)]
mod tests;

use aes::Aes128;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use hmac::{Hmac, Mac};
use rand;
use sha2::Sha256;
use std::{net, time::SystemTime};

pub enum Error {
    DataLen,
    IdWidth,
}

pub enum FecLoss {
    L80p = 0,
    L60p = 1,
    L40p = 2,
    L20p = 3,
}

impl FecLoss {
    pub fn as_float(&self) -> f32 {
        match self {
            Self::L80p => 0.8,
            Self::L60p => 0.6,
            Self::L40p => 0.4,
            Self::L20p => 0.2,
        }
    }
}

const TOTAL_DATA: usize = 7;

type Aes128Cbc = Cbc<Aes128, Pkcs7>;
type HmacSha256 = Hmac<Sha256>;

pub fn send(
    data: Vec<u8>,
    encryption_key: [u8; 16],
    integrity_key: Vec<u8>,
    send_flag: bool,
    id: u8,
    possible_loss: FecLoss,
) -> Result<(), Error> {
    // length of data must be divisible by 16
    if data.len() % 16 != 0 {
        return Err(Error::DataLen);
    }
    // id can only be 6 bits long
    if id >= 64 {
        return Err(Error::IdWidth);
    }
    // generate random "initialization vector"
    let mut iv_data = generate_iv();
    // generate global sequence
    let global_sequence_number: u32 = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Could not get epoch")
        .as_secs() as u32;
    let mut global_sequence_data: Vec<u8> = global_sequence_number.to_ne_bytes().to_vec();

    // encrypt data
    let mut encrypted_data = encrypt_message(encryption_key, &iv_data, data);

    let mut message = vec![];
    message.append(&mut global_sequence_data);
    message.append(&mut encrypted_data);
    let mut mac_data = hash_message(integrity_key, message);

    let mut all_data = vec![];
    all_data.append(&mut iv_data);
    all_data.append(&mut global_sequence_data);
    all_data.append(&mut encrypted_data);
    all_data.append(&mut mac_data);

    // add padding
    if all_data.len() % TOTAL_DATA != 0 {
        let padding = TOTAL_DATA - (all_data.len() % TOTAL_DATA);
        all_data.append(vec![0; padding]);
    }

    // add FEC
    let k: f32 = (all_data.len() / TOTAL_DATA) as f32;
    let m: u32 = ((k * (1.0 / (1.0 - possible_loss.as_float()))).round() / 2.0).ceil() as u32;
    // TODO: implement Zfec

    Ok(())
}
fn generate_iv() -> Vec<u8> {
    let mut ret_array = vec![];
    for i in 0..16 {
        ret_array.push(rand::random());
    }
    ret_array
}

fn encrypt_message(encryption_key: [u8; 16], iv_data: &Vec<u8>, message: Vec<u8>) -> Vec<u8> {
    let cipher = Aes128Cbc::new_from_slices(&encryption_key, &iv_data).unwrap();
    cipher.encrypt_vec(&message[..])
}

fn hash_message(integrity_key: Vec<u8>, message: Vec<u8>) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(&integrity_key[..]).expect("Could not create mac");
    mac.update(&message[..]);
    mac.finalize().into_bytes()[..].to_vec()
}
