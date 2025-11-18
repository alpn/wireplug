use serde::{Deserialize, Serialize};
use std::io::Error;
use wireguard_control::Key;

static CONFIG_PATH: &str = "/etc/wireplugd";

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct Config {
    pub interface: Interface,
    #[serde(rename = "Peer")]
    pub peers: Vec<Peer>,
}

impl Config {
    pub(crate) fn new_example_with_random_key() -> Self {
        Self {
            interface: Interface::new_example_with_random_key(),
            peers: vec![Peer::new_example()],
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct Interface {
    pub address: String,
    pub private_key: String,
    pub public_key: Option<String>,
}

impl Interface {
    pub(crate) fn new_example_with_random_key() -> Self {
        let key = Key::generate_private();
        Self {
            address: String::from("10.0.0.1/24"),
            private_key: key.to_base64(),
            public_key: Some(key.get_public().to_base64()),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct Peer {
    pub public_key: String,
    pub allowed_ips: String,
}

impl Peer {
    pub(crate) fn new_example() -> Self {
        Self {
            public_key: String::from("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            allowed_ips: String::from("10.0.0.2"),
        }
    }
}

#[cfg(not(target_os = "openbsd"))]
pub(crate) fn read_from_file(ifname: &String) -> std::io::Result<Config> {
    let path = format!("{CONFIG_PATH}.{ifname}");
    let config = std::fs::read_to_string(path)?;
    toml::from_str(&config).map_err(|e| Error::other(format!("Config file parsing error: {e}")))
}

pub(crate) fn generate_example_to_file(ifname: &str) -> std::io::Result<()> {
    let path = format!("{CONFIG_PATH}.{ifname}");
    if std::fs::exists(&path)? {
        return Err(Error::other(format!("{path} already exists")));
    }
    let config = Config::new_example_with_random_key();
    let config = toml::to_string(&config)
        .map_err(|e| std::io::Error::other(format!("serialization error: {e}")))?;
    std::fs::write(&path, &config)
}
