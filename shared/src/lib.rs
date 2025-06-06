use bincode::{Decode, Encode};
use std::net::IpAddr;

const PROTOCOL: &str = "Wireplug_V1";

#[derive(Encode, Decode, PartialEq, Debug)]
pub struct WireplugAnnounce {
    proto: String,
    pub initiator_pubkey: String,
    pub peer_pubkey: String,
}

impl WireplugAnnounce {
    pub fn new(pubkey: &str, peer: &str) -> Self {
        WireplugAnnounce {
            proto: String::from(PROTOCOL),
            initiator_pubkey: pubkey.to_string(),
            peer_pubkey: peer.to_string(),
        }
    }
    pub fn valid(&self) -> bool {
        self.proto.eq(PROTOCOL) && self.initiator_pubkey.len() == 44 && self.peer_pubkey.len() == 44
    }
}

#[derive(Encode, Decode, PartialEq, Debug)]
pub struct WireplugResponse {
    ip: Option<IpAddr>,
}

impl WireplugResponse {
    pub fn new(ip: Option<IpAddr>) -> Self {
        WireplugResponse { ip: ip }
    }
}

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
