use ipnet::IpNet;
use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
};

pub const WIREPLUG_PROTOCOL_MAGIC: [u8; 3] = [0xFD, 0xAC, 0xAF];
pub const WIREPLUG_PROTOCOL_VERSION: [u8; 1] = [0x1];

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
    pub initiator_pubkey: String,
    pub peer_pubkeys: Vec<String>,
    pub ipv6: Option<Ipv6Addr>,
    pub wg_port: u16,
    pub lan_addrs: Vec<IpNet>,
    pub needs_relay: bool,
}

impl WireplugAnnouncement {
    pub fn new(
        initiator_pubkey: &String,
        peer_pubkeys: Vec<String>,
        ipv6: Option<Ipv6Addr>,
        wg_port: u16,
        lan_addrs: Vec<IpNet>,
        need_relay: bool,
    ) -> Self {
        WireplugAnnouncement {
            initiator_pubkey: initiator_pubkey.to_owned(),
            peer_pubkeys,
            ipv6,
            wg_port,
            lan_addrs,
            needs_relay: need_relay,
        }
    }
    pub fn valid(&self) -> bool {
        is_valid_wgkey(&self.initiator_pubkey)
            && self.peer_pubkeys.iter().all(|p| is_valid_wgkey(p))
            && self.wg_port >= 1024
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, Debug)]
pub enum WireplugEndpoint {
    Unknown,
    LocalNetwork {
        ipv6: Option<Ipv6Addr>,
        lan_addrs: Vec<IpNet>,
        wg_port: u16,
    },
    RemoteNetwork {
        ipv4: Option<Ipv4Addr>,
        ipv6: Option<Ipv6Addr>,
        wg_port: u16,
    },
    Relay {
        id: usize,
        port: u16,
    },
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
pub struct WireplugResponse {
    pub peer_endpoints: HashMap<String, WireplugEndpoint>,
}

impl WireplugResponse {
    pub fn from_peer_endpoints(peer_endpoints: HashMap<String, WireplugEndpoint>) -> Self {
        WireplugResponse { peer_endpoints }
    }
    pub fn valid(&self) -> bool {
        // XXX
        true
    }
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
pub struct WireplugStunRequest {
    pub port: u16,
}

impl WireplugStunRequest {
    pub fn new(port: u16) -> Self {
        WireplugStunRequest { port }
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
