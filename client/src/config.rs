use serde::Deserialize;
use std::io::{self, Error};

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct Config {
    pub interface: Interface,
    #[serde(rename = "Peer")]
    pub peers: Vec<Peer>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct Interface {
    pub address: String,
    pub private_key: String,
    pub listen_port: Option<u16>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct Peer {
    pub public_key: String,
    pub allowed_ips: String,
}

pub(crate) fn read_from_file(path: &String) -> io::Result<Config> {
    let config = std::fs::read_to_string(path)?;
    toml::from_str(&config).map_err(|e| {
        Error::other(
            format!("Config file parsing error: {e}"),
        )
    })
}
