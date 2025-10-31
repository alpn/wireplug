use bincode::{Decode, Encode};
use std::{collections::HashMap, net::SocketAddr};

const WIREPLUG_PROTOCOL_VERSION: &str = "Wireplug_V1";

fn is_valid_wgkey(s: &str) -> bool {
    if s.len() != 44 {
        return false;
    }
    for c in s.chars() {
        if !c.is_ascii_alphanumeric() && c != '+' && c != '/' && c != '=' {
            return false;
        }
    }
    true
}

#[derive(Encode, Decode, PartialEq, Debug)]
pub struct WireplugAnnouncement {
    proto: String,
    pub initiator_pubkey: String,
    pub peer_pubkeys: Vec<String>,
    pub listen_port: u16,
    pub lan_addrs: Option<Vec<String>>,
}

impl WireplugAnnouncement {
    pub fn new(
        initiator_pubkey: &String,
        peer_pubkeys: Vec<String>,
        listen_port: u16,
        lan_addrs: Option<Vec<String>>,
    ) -> Self {
        WireplugAnnouncement {
            proto: String::from(WIREPLUG_PROTOCOL_VERSION),
            initiator_pubkey: initiator_pubkey.to_owned(),
            peer_pubkeys,
            listen_port,
            lan_addrs,
        }
    }
    pub fn valid(&self) -> bool {
        self.proto.eq(WIREPLUG_PROTOCOL_VERSION)
            && is_valid_wgkey(&self.initiator_pubkey)
            && self.peer_pubkeys.iter().all(|p| is_valid_wgkey(p))
            && self.listen_port >= 1024
    }
}

#[derive(Encode, Decode, PartialEq, Debug)]
pub enum WireplugEndpoint {
    Unknown,
    LocalNetwork {
        lan_addrs: Vec<String>,
        listen_port: u16,
    },
    RemoteNetwork(SocketAddr),
}

#[derive(Encode, Decode, PartialEq, Debug)]
pub struct WireplugResponse {
    proto: String,
    pub peer_endpoints: HashMap<String, WireplugEndpoint>,
}

impl WireplugResponse {
    pub fn from_peer_endpoints(peer_endpoints: HashMap<String, WireplugEndpoint>) -> Self {
        WireplugResponse {
            proto: WIREPLUG_PROTOCOL_VERSION.to_string(),
            peer_endpoints,
        }
    }
    pub fn valid(&self) -> bool {
        self.proto.eq(WIREPLUG_PROTOCOL_VERSION)
    }
}

#[derive(Encode, Decode, PartialEq, Debug)]
pub struct WireplugStunRequest {
    proto: String,
    pub port: u16,
}

impl WireplugStunRequest {
    pub fn new(port: u16) -> Self {
        WireplugStunRequest {
            proto: String::from(WIREPLUG_PROTOCOL_VERSION),
            port,
        }
    }
}

#[derive(Encode, Decode, PartialEq, Debug)]
pub enum WireplugStunResult {
    SamePort,
    DifferentPort(u16),
}

#[derive(Encode, Decode, PartialEq, Debug)]
pub struct WireplugStunResponse {
    pub result: WireplugStunResult,
}

impl WireplugStunResponse {
    pub fn new(port: Option<u16>) -> Self {
        let res = match port {
            Some(p) => WireplugStunResult::DifferentPort(p),
            None => WireplugStunResult::SamePort,
        };
        WireplugStunResponse { result: res }
    }
}
