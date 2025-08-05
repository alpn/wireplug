use crate::wg_interface;
use ipnet::IpNet;
use shared::{self, BINCODE_CONFIG, WP_WIREPLUG_ORG, protocol};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    str::FromStr,
};
use wireguard_control::{Backend, Device, Key};

const _RETRY_INTERVAL_SEC: u64 = 10;

fn send_announcement<S: Read + Write>(
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

fn get_tls_client_connection() -> anyhow::Result<rustls::ClientConnection> {
    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_safe_default_protocol_versions()?
    .with_root_certificates(root_store)
    .with_no_client_auth();
    let config = std::sync::Arc::new(config);
    Ok(rustls::ClientConnection::new(
        config,
        shared::WIREPLUG_ORG_DOMAIN_TMP.try_into()?,
    )?)
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

    let mut socket = TcpStream::connect(WP_WIREPLUG_ORG)?;
    let mut client_connection = get_tls_client_connection()
        .map_err(|e| std::io::Error::other(format!("failed to create TLS client: {e}")))?;
    let mut stream = rustls::Stream::new(&mut client_connection, &mut socket);

    let announcement = protocol::WireplugAnnounce::new(
        &initiator_pubkey.to_base64(),
        peers.iter().map(|p| p.to_base64()).collect(),
        announcement_port,
        lan_addrs.to_owned(),
    );

    let response = send_announcement(&mut stream, announcement)?;
    if !response.valid() {
        return Err(std::io::Error::other("invalid response"));
    }

    let mut updated_some = false;
    for (peer, peer_endpoint) in response.peer_endpoints {
        let Ok(peer_pubkey) = Key::from_base64(&peer) else {
            eprintln!("bad peer pubkey");
            continue;
        };
        match peer_endpoint {
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
                    wg_interface::update_peer(&iface, &peer_pubkey, addr)?;
                    updated_some = true;
                }
            }
            protocol::WireplugEndpoint::RemoteNetwork(wan_addr) => {
                println!("| wireplug.org: peer is @{wan_addr}");
                wg_interface::update_peer(&iface, &peer_pubkey, wan_addr)?;
                updated_some = true;
            }
        }
    }
    Ok(updated_some)
}
