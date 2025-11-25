use serde::Deserialize;
use std::io::{self, Error};

static CONFIG_PATH: &str = "/etc/wpcod.conf";

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct Config {
    pub wp_listen_on: String,
    pub stun_listen_on: Vec<String>,
    pub cert_path: String,
    pub key_path: String,
}

pub(crate) fn read_from_file() -> io::Result<Config> {
    let config = std::fs::read_to_string(CONFIG_PATH)?;
    toml::from_str(&config).map_err(|e| Error::other(format!("Config file parsing error: {e}")))
}
