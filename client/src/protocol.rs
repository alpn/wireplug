use shared::{BINCODE_CONFIG, WireplugAnnounce, WireplugResponse};
use std::{
    io::{Read, Write},
    net::TcpStream,
    time::{Duration, SystemTime},
};
use wireguard_control::{Backend, Device, Key};

use crate::wg_interface;
const WIREPLUG_ORG: &str = "wireplug.org:4455";

pub(crate) const MONITORING_INTERVAL: u64 = 30;
// WireGuard's rekey interval, and some
const LAST_HANDSHAKE_MAX: u64 = 125;
const RETRY_INTERVAL_SEC: u64 = 10;

fn send_announcement(
    initiator_pubkey: &Key,
    peer_pubkey: &Key,
    port: u16,
) -> Option<WireplugResponse> {
    match TcpStream::connect(WIREPLUG_ORG) {
        Ok(mut stream) => {
            let announcement = WireplugAnnounce::new(
                &initiator_pubkey.to_base64(),
                &peer_pubkey.to_base64(),
                port,
            );
            let buf = bincode::encode_to_vec(&announcement, BINCODE_CONFIG).unwrap();
            stream.write_all(&buf).unwrap();
            let mut res = [0u8; 1024];
            stream.read(&mut res).ok().unwrap();
            let (response, _): (WireplugResponse, usize) =
                bincode::decode_from_slice(&res[..], BINCODE_CONFIG).unwrap();
            return Some(response);
        }
        Err(e) => eprintln!("error: {:?}", e),
    }
    None
}

pub(crate) fn monitor_interface(if_name: &String) {
    let iface = if_name.parse().unwrap();
    let device = Device::get(&iface, Backend::default()).unwrap();
    if device.public_key.is_none() {
        println!("{} is not configured", if_name);
        return;
    }

    let pubkey = &device.public_key.clone().unwrap();
    let port = device.listen_port.unwrap();
    let now = SystemTime::now();

    for peer in device.peers {
        print!("\tpeer: {} .. ", &peer.config.public_key.to_base64());
        let annouce;
        if let Some(last_handshake) = peer.stats.last_handshake_time {
            let duration = now.duration_since(last_handshake).unwrap();
            print!("last handshake {} seconds ago => ", duration.as_secs(),);
            annouce = duration > Duration::from_secs(LAST_HANDSHAKE_MAX);
        } else {
            print!("no previous handshakes => ");
            annouce = true;
        }
        if annouce {
            print!("sending announcement.. ");
            match send_announcement(&pubkey, &peer.config.public_key, port) {
                Some(r) => {
                    if let Some(ip) = r.ip {
                        println!("| wireplug.org: peer is @{}", ip);
                        wg_interface::update(&iface, &peer, ip);
                    } else {
                        println!("| wireplug.org: peer is unknown");
                    }
                }
                None => (),
            }
        } else {
            println!("doing nothing");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_nothing() {
        let alice = Key::from_base64("5SpMF4Wozu4e2lapOq7frNaJBNyTuW4kwfBEDicgrxs=").unwrap();
        let bob = Key::from_base64("lCN7vqk1TlzncMwLmJJKMCtDICUChxc2JnI/QtXKm38=").unwrap();
        println!("announcing {:?} - {:?}", alice, bob);
        let res = send_announcement(&bob, &alice).unwrap();
        println!("res= {:?}", res);
    }
}