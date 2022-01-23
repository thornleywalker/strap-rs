#[cfg(test)]
mod tests;

use std::net;

pub struct Config {
    ssid: String,
    pass: String,
    encryption_key: String,
    initialization_vector: String,
}
