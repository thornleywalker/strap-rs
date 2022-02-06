#[cfg(test)]
mod tests;

use aes::Aes128;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use hmac::{Hmac, Mac};
use pnet;
use rand;
use sha2::Sha256;
use std::time::SystemTime;
use zfec_rs::Fec;

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
    let k = (all_data.len() / TOTAL_DATA) as usize;
    let m = ((k as f32 * (1.0 / (1.0 - possible_loss.as_float()))).round() / 2.0).ceil() as usize;
    let fec = Fec::new(k, m);

    let encoded_data = fec.encode(&mut all_data);
    let all_encoded_data = vec![];

    for chunk in encoded_data {
        all_encoded_data.append(&mut chunk);
    }

    if all_encoded_data.len() % TOTAL_DATA != 0 {
        return Err(Error::DataLen);
    }

    let total_packets = all_encoded_data.len() / TOTAL_DATA;

    if total_packets % 2 != 0 {
        return Err(Error::DataLen);
    }
    if total_packets >= 128 {
        return Err(Error::DataLen);
    }

    // iiii ii10 fnnt tttt t000 0000
    let header = (id << 18) as u32
        + (0x10 << 16) as u32
        + ((send_flag as u32) << 15)
        + ((possible_loss as u32) << 13)
        + ((total_packets as u32 >> 1) << 7);

    for (sequence, group) in grouper(&all_encoded_data, TOTAL_DATA).iter().enumerate() {
        let packet_header = header + sequence as u32;

        let src = pnet::datalink::MacAddr(
            ((packet_header & 0xFF0000) >> 16) as u8,
            ((packet_header & 0x00FF00) >> 8) as u8,
            ((packet_header & 0x0000FF) >> 0) as u8,
            group[0],
            group[1],
            group[2],
        );
        let dst = pnet::datalink::MacAddr(0x33, 0x33, group[3], group[4], group[5], group[6]);
    }
    Ok(())
}
fn grouper(data: &Vec<u8>, n: usize) -> Vec<Vec<u8>> {
    let mut ret_vec = vec![];
    for i in 0..data.len() / n {
        ret_vec.push(data[i * n..(i + 1) * n].to_vec());
    }
    ret_vec
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
