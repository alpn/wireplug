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
const _RETRY_INTERVAL_SEC: u64 = 10;

fn send_announcement(
    initiator_pubkey: &Key,
    peer_pubkey: &Key,
    port: u16,
) -> Result<WireplugResponse, std::io::Error> {
    let mut stream = TcpStream::connect(WIREPLUG_ORG)?;
    let announcement = WireplugAnnounce::new(
        &initiator_pubkey.to_base64(),
        &peer_pubkey.to_base64(),
        port,
    );

    let buf = bincode::encode_to_vec(&announcement, BINCODE_CONFIG).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::Other, format!("encoding error: {e}"))
    })?;

    stream.write_all(&buf)?;
    let mut res = [0u8; 1024];
    stream.read(&mut res)?;
    let (response, _): (WireplugResponse, usize) =
        bincode::decode_from_slice(&res[..], BINCODE_CONFIG).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, format!("encoding error: {e}"))
        })?;

    Ok(response)
}

pub(crate) fn monitor_interface(if_name: &String) -> Result<(), std::io::Error> {
    let iface = if_name.parse()?;
    let device = Device::get(&iface, Backend::default())?;
    let Some(pubkey) = &device.public_key.clone() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("{} is not configured", if_name),
        ));
    };

    let Some(port) = device.listen_port else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("{} is not configured", if_name),
        ));
    };
    let now = SystemTime::now();

    for peer in device.peers {
        print!("\tpeer: {} .. ", &peer.config.public_key.to_base64());
        let annouce;
        if let Some(last_handshake) = peer.stats.last_handshake_time {
            let duration = now
                .duration_since(last_handshake)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{e}")))?;


            annouce = duration > Duration::from_secs(LAST_HANDSHAKE_MAX);
        } else {
            print!("no previous handshakes => ");
            annouce = true;
        }
        if annouce {
            print!("sending announcement.. ");
            match send_announcement(&pubkey, &peer.config.public_key, port)?.peer_endpoint {
                Some(endpoint) => {
                    println!("| wireplug.org: peer is @{}", endpoint);
                    wg_interface::update(&iface, &peer, endpoint)?;
                }
                None => println!("| wireplug.org: peer is unknown"),
            }
        } else {
            println!("doing nothing");
        }
    }
    Ok(())
}

/*
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
*/