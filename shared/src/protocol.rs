use ipnet::IpNet;
use std::{
    collections::HashMap,
    net::{Ipv6Addr, SocketAddr},
};

pub const WIREPLUG_PROTOCOL_MAGIC: [u8; 3] = [0xFD, 0xAC, 0xAF];
pub const WIREPLUG_PROTOCOL_VERSION_X: [u8; 1] = [0x1];
const WIREPLUG_PROTOCOL_VERSION: &str = "Wireplug_V0.0.2";

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

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
pub struct WireplugAnnouncement {
    proto: String,
    pub initiator_pubkey: String,
    pub peer_pubkeys: Vec<String>,
    pub listen_port: u16,
    pub lan_addrs: Vec<IpNet>,
    pub ip6: Option<Ipv6Addr>,
    pub needs_relay: bool,
}

impl WireplugAnnouncement {
    pub fn new(
        initiator_pubkey: &String,
        peer_pubkeys: Vec<String>,
        listen_port: u16,
        lan_addrs: Vec<IpNet>,
        ip6: Option<Ipv6Addr>,
        need_relay: bool,
    ) -> Self {
        WireplugAnnouncement {
            proto: String::from(WIREPLUG_PROTOCOL_VERSION),
            initiator_pubkey: initiator_pubkey.to_owned(),
            peer_pubkeys,
            listen_port,
            lan_addrs,
            ip6,
            needs_relay: need_relay,
        }
    }
    pub fn valid(&self) -> bool {
        self.proto.eq(WIREPLUG_PROTOCOL_VERSION)
            && is_valid_wgkey(&self.initiator_pubkey)
            && self.peer_pubkeys.iter().all(|p| is_valid_wgkey(p))
            && self.listen_port >= 1024
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, Debug)]
pub enum WireplugEndpoint {
    Unknown,
    LocalNetwork {
        lan_addrs: Vec<IpNet>,
        listen_port: u16,
    },
    RemoteNetwork(SocketAddr),
    Relay {
        id: usize,
        port: u16,
    },
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
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

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
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

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
pub enum WireplugStunResult {
    SamePort,
    DifferentPort(u16),
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
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
