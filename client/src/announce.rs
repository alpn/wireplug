use ipnet::IpNet;
use shared::{
    self, BINCODE_CONFIG,
    protocol,
};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    str::FromStr,
};
use wireguard_control::{Backend, Device, Key};

use crate::wg_interface;
const WIREPLUG_ORG: &str = "wireplug.org:4455";

const _RETRY_INTERVAL_SEC: u64 = 10;

fn send_announcement<S : Read + Write>(
    stream: &mut S,
    announcement: protocol::WireplugAnnounce,
) -> Result<protocol::WireplugResponse, std::io::Error> {

    let buf = bincode::encode_to_vec(&announcement, BINCODE_CONFIG)
        .map_err(|e| std::io::Error::other(format!("encoding error: {e}")))?;

    stream.write_all(&buf)?;
    let mut res = [0u8; 1024];
    let _ = stream.read(&mut res)?;
    let (response, _): (protocol::WireplugResponse, usize) =
        bincode::decode_from_slice(&res[..], BINCODE_CONFIG)
            .map_err(|e| std::io::Error::other(format!("encoding error: {e}")))?;

    Ok(response)
}

pub(crate) fn announce_and_update_peers(
    if_name: &String,
    peers: Vec<Key>,
    announcement_port: u16,
    lan_addrs: Option<Vec<String>>,
) -> Result<bool, std::io::Error> {

    let iface = if_name.parse()?;
    let device = Device::get(&iface, Backend::default())?;
    let Some(initiator_pubkey) = &device.public_key.clone() else {
        return Err(std::io::Error::other(format!(
            "{if_name} is not configured"
        )));
    };

    let mut stream = TcpStream::connect(WIREPLUG_ORG)?;

    let mut updated_some = false;
    for peer in peers {
        let announcement = protocol::WireplugAnnounce::new(
            &initiator_pubkey.to_base64(),
            &peer.to_base64(),
            announcement_port,
            lan_addrs.to_owned(),
        );

        print!("announcing ourselves to {} .. ", &peer.to_base64());
        let response = send_announcement(&mut stream, announcement)?;
        if !response.valid() {
            return Err(std::io::Error::other("invalid response"));
        }
        match response.peer_endpoint {
            protocol::WireplugEndpoint::Unknown => println!("| wireplug.org: peer is unknown"),
            protocol::WireplugEndpoint::LocalNetwork {
                lan_addrs,
                listen_port,
            } => {
                if let Some(addr) = lan_addrs.get(0) {
                    println!("| wireplug.org: peer is on our local network @{addr}");
                    let ipnet = IpNet::from_str(&addr.as_str())
                        .map_err(|e| std::io::Error::other(format!("{e}")))?;
                    let addr = SocketAddr::new(ipnet.addr(), listen_port);
                    wg_interface::update_peer(&iface, &peer, addr)?;
                    updated_some = true;
                }
            }
            protocol::WireplugEndpoint::RemoteNetwork(wan_addr) => {
                println!("| wireplug.org: peer is @{wan_addr}");
                wg_interface::update_peer(&iface, &peer, wan_addr)?;
                updated_some = true;
            }
        }
    }
    Ok(updated_some)
}
