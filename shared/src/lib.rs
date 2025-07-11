use bincode::config::Configuration;
use bincode::{Decode, Encode};
use std::net::SocketAddr;

const PROTOCOL: &str = "Wireplug_V1";
pub const COMMON_PKA: u16 = 25;

pub const BINCODE_CONFIG: Configuration<
    bincode::config::LittleEndian,
    bincode::config::Fixint,
    bincode::config::Limit<256>,
> = bincode::config::standard()
    .with_fixed_int_encoding()
    .with_limit::<256>();

fn is_valid_wgkey(s: &String) -> bool {
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
pub struct WireplugAnnounce {
    proto: String,
    pub initiator_pubkey: String,
    pub peer_pubkey: String,
    pub listen_port: u16,
}

impl WireplugAnnounce {
    pub fn new(initiator_pubkey: &String, peer_pubkey: &String, port: u16) -> Self {
        WireplugAnnounce {
            proto: String::from(PROTOCOL),
            initiator_pubkey: initiator_pubkey.to_owned(),
            peer_pubkey: peer_pubkey.to_owned(),
            listen_port: port,
        }
    }
    pub fn valid(&self) -> bool {
        self.proto.eq(PROTOCOL)
            && is_valid_wgkey(&self.initiator_pubkey)
            && is_valid_wgkey(&self.peer_pubkey)
            && self.listen_port >= 1024
    }
}

#[derive(Encode, Decode, PartialEq, Debug)]
pub struct WireplugResponse {
    pub peer_endpoint: Option<SocketAddr>,
}

impl WireplugResponse {
    pub fn new(endpoint: Option<SocketAddr>) -> Self {
        WireplugResponse {
            peer_endpoint: endpoint,
        }
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
            proto: String::from(PROTOCOL),
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

/*
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let announce = WireplugAnnounce::new(
            "alicealicealicealicealicealicealicealicealic",
            "bobbobbobbobbobbobbobbobbobbobbobbobbobbobbo",
        );
        println!("{:?}", announce);
        let config = bincode::config::standard();
        let v = bincode::encode_to_vec(&announce, config).unwrap();
        println!("{:?}", &v);
        let (hello2, size): (WireplugAnnounce, usize) =
            bincode::decode_from_slice(&v[..], config).unwrap();
        println!("{:?}", hello2);
        assert_eq!(announce, hello2);
    }
}
*/
