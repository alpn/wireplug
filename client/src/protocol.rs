use ipnet::IpNet;
use shared::{BINCODE_CONFIG, WireplugAnnounce, WireplugResponse};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    str::FromStr,
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
    lan_addrs: &Option<Vec<String>>,
) -> Result<WireplugResponse, std::io::Error> {
    let mut stream = TcpStream::connect(WIREPLUG_ORG)?;
    let announcement = WireplugAnnounce::new(
        &initiator_pubkey.to_base64(),
        &peer_pubkey.to_base64(),
        port,
        lan_addrs.to_owned(),
    );

    let buf = bincode::encode_to_vec(&announcement, BINCODE_CONFIG)
        .map_err(|e| std::io::Error::other(format!("encoding error: {e}")))?;

    stream.write_all(&buf)?;
    let mut res = [0u8; 1024];
    let _ = stream.read(&mut res)?;
    let (response, _): (WireplugResponse, usize) =
        bincode::decode_from_slice(&res[..], BINCODE_CONFIG)
            .map_err(|e| std::io::Error::other(format!("encoding error: {e}")))?;

    Ok(response)
}

pub(crate) fn get_inactive_peers(if_name: &String) -> Result<Vec<Key>, std::io::Error> {
    let iface = if_name.parse()?;
    let device = Device::get(&iface, Backend::default())?;
    let now = SystemTime::now();

    let mut inactive_peers = vec![];
    for peer in device.peers {
        print!("\tpeer: {} .. ", &peer.config.public_key.to_base64());
        if let Some(last_handshake) = peer.stats.last_handshake_time {
            let duration = now
                .duration_since(last_handshake)
                .map_err(|e| std::io::Error::other(format!("{e}")))?;

            if duration > Duration::from_secs(std::cmp::max(
                    peer.config.persistent_keepalive_interval.unwrap_or(0) as u64,
                    LAST_HANDSHAKE_MAX,
                ))
            {
                inactive_peers.push(peer.config.public_key);
                println!("INACTIVE");
            } else {
                println!("OK");
            }
        } else {
            inactive_peers.push(peer.config.public_key);
            println!("INACTIVE");
        }
    }
    Ok(inactive_peers)
}

pub(crate) fn announce_and_update_peers(
    if_name: &String,
    peers: Vec<Key>,
    announcement_port: u16,
    lan_addrs: Option<Vec<String>>,
) -> Result<(), std::io::Error> {
    let iface = if_name.parse()?;
    let device = Device::get(&iface, Backend::default())?;
    let Some(initiator_pubkey) = &device.public_key.clone() else {
        return Err(std::io::Error::other(format!(
            "{if_name} is not configured"
        )));
    };

    for peer in peers {
        print!("announcing ourselves to {} .. ", &peer.to_base64());
        let response = send_announcement(initiator_pubkey, &peer, announcement_port, &lan_addrs)?;
        if !response.valid() {
            return Err(std::io::Error::other("invalid response"));
        }
        match response.peer_endpoint {
            shared::WireplugEndpoint::Unknown => println!("| wireplug.org: peer is unknown"),
            shared::WireplugEndpoint::LocalNetwork {
                lan_addrs,
                listen_port,
            } => {
                if let Some(addr) = lan_addrs.get(0) {
                    println!("| wireplug.org: peer is on our local network @{addr}");
                    let ipnet = IpNet::from_str(&addr.as_str())
                        .map_err(|e| std::io::Error::other(format!("{e}")))?;
                    let addr = SocketAddr::new(ipnet.addr(), listen_port);
                    wg_interface::update_peer(&iface, &peer, addr)?;
                }
            }
            shared::WireplugEndpoint::RemoteNetwork(wan_addr) => {
                println!("| wireplug.org: peer is @{wan_addr}");
                wg_interface::update_peer(&iface, &peer, wan_addr)?;
            }
        }
    }
    Ok(())
}
