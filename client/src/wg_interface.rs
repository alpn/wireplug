#[cfg(not(target_os = "linux"))]
use std::io;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    time::{Duration, SystemTime},
};

use ipnet::IpNet;
use shared::protocol::{self};
use wireguard_control::{
    Backend, Device, DeviceUpdate, InterfaceName, Key, KeyPair, PeerConfigBuilder, PeerInfo,
};

use crate::config::Config;

pub const COMMON_PKA: u16 = 25;
// WireGuard's rekey interval, and some
pub const LAST_HANDSHAKE_MAX: u64 = 180;

pub struct PeersActivity {
    activity: HashMap<Key, u64>,
}

impl PeersActivity {
    pub fn new() -> Self {
        Self {
            activity: HashMap::new(),
        }
    }

    fn update(&mut self, peer: &PeerInfo) -> bool {
        let new_rx = peer.stats.rx_bytes;
        let msg = format!("\tpeer: {} .. ", &peer.config.public_key.to_base64());
        match self.activity.get_mut(&peer.config.public_key) {
            Some(prev_rx) => {
                if new_rx > *prev_rx {
                    *prev_rx = new_rx;
                    log::trace!("{msg} OK");
                    return true;
                }
            }
            None => {
                self.activity
                    .insert(peer.config.public_key.to_owned(), new_rx);
                log::trace!("{msg} NEW");
                return true;
            }
        }
        log::trace!("{msg} INACTIVE");
        false
    }
}

pub(crate) fn show_config(ifname: &str) -> Result<(), std::io::Error> {
    log::trace!("=========== if: {ifname} ===========");
    let ifname: InterfaceName = ifname.parse()?;
    let dev = Device::get(&ifname, Backend::default())?;
    if let Some(public_key) = dev.public_key {
        log::trace!("public key: {}", public_key.to_base64());
    }
    if let Some(port) = dev.listen_port {
        log::trace!("listen port: {port}");
    }
    log::trace!("peers:");
    for peer in dev.peers {
        log::trace!("\tpublic key: {}", peer.config.public_key.to_base64());
        if let Some(endpoint) = peer.config.endpoint {
            log::trace!("\tendpoint: {endpoint}");
        }
        log::trace!("\tallowed IPs:");
        for aip in peer.config.allowed_ips {
            log::trace!("\t\t{}/{}", aip.address, aip.cidr);
        }
        log::trace!("\t---------------------------------");
    }

    Ok(())
}

pub(crate) fn show_peers(ifname: &str) -> anyhow::Result<()> {
    let ifname: InterfaceName = ifname.parse()?;
    let dev = Device::get(&ifname, Backend::default())?;
    log::debug!("peers:");
    let now = SystemTime::now();
    for peer in dev.peers {
        let last_handshake = match peer.stats.last_handshake_time {
            Some(last_handshake_time) => now
                .duration_since(last_handshake_time)?
                .as_secs()
                .to_string(),
            None => "NA".to_string(),
        };
        log::debug!(
            "\t{} last handshake: {last_handshake}",
            peer.config.public_key.to_base64()
        );
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "openbsd"))]
fn cmd(bin: &str, args: &[&str]) -> Result<std::process::Output, io::Error> {
    let output = std::process::Command::new(bin).args(args).output()?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(io::Error::other(format!(
            "failed to run {} {} command: {}",
            bin,
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        )))
    }
}

#[cfg(target_os = "linux")]
use crate::netlink::set_addr;

#[cfg(any(target_os = "macos", target_os = "openbsd"))]
pub fn set_addr(
    ifname: &InterfaceName,
    addr: IpNet,
) -> Result<std::process::Output, std::io::Error> {
    let real_interface = wireguard_control::backends::userspace::resolve_tun(ifname)?;
    log::trace!("set_addr: {addr:?}");
    let output = cmd(
        "ifconfig",
        &[
            &real_interface,
            "inet",
            &addr.to_string(),
            &addr.addr().to_string(),
            "alias",
        ],
    )?;
    Ok(output)
}

#[cfg(target_os = "linux")]
use crate::netlink::add_route;

#[cfg(target_os = "macos")]
pub fn add_route(ifname: &InterfaceName, cidr: IpNet) -> Result<bool, io::Error> {
    let real_interface = wireguard_control::backends::userspace::resolve_tun(ifname)?;
    let output = cmd(
        "route",
        &[
            "-n",
            "add",
            if matches!(cidr, IpNet::V4(_)) {
                "-inet"
            } else {
                "-inet6"
            },
            &cidr.to_string(),
            "-interface",
            &real_interface,
        ],
    )?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        Err(io::Error::other(format!(
            "failed to add route for device {}: {}",
            &real_interface, stderr
        )))
    } else {
        Ok(!stderr.contains("File exists"))
    }
}

fn configure_inet(ifname: &InterfaceName, config: &Config) -> anyhow::Result<()> {
    let addr = IpNet::from_str(config.interface.address.as_str())
        .map_err(|e| std::io::Error::other(format!("Parsing Error: {e}")))?;
    set_addr(ifname, addr)?;

    #[cfg(target_os = "linux")]
    crate::netlink::set_up(ifname, 1420)?;

    #[cfg(not(target_os = "openbsd"))]
    add_route(ifname, addr)?;

    Ok(())
}

pub(crate) fn configure(ifname: &str, config: Option<Config>) -> anyhow::Result<()> {
    let ifname: InterfaceName = ifname.parse()?;
    match config {
        Some(config) => {
            log::debug!("{ifname}: configuring using config file");
            let mut peers = vec![];
            for peer in &config.peers {
                let peer_config = PeerConfigBuilder::new(
                    &Key::from_base64(&peer.public_key)
                        .map_err(|e| std::io::Error::other(format!("Could not parse key: {e}")))?,
                )
                .set_persistent_keepalive_interval(COMMON_PKA)
                .add_allowed_ip(IpAddr::from_str(peer.allowed_ips.as_str())?, 32);
                peers.push(peer_config);
            }

            let update = DeviceUpdate::new()
                .set_keypair(KeyPair::from_private(Key::from_base64(
                    &config.interface.private_key,
                )?))
                .add_peers(&peers);

            log::debug!("{ifname}: setting wgpka={} on all peers", COMMON_PKA);
            update.apply(&ifname, Backend::default())?;

            configure_inet(&ifname, &config)?;
        }
        None => {
            let device = Device::get(&ifname, Backend::default())?;
            let update = DeviceUpdate::new().add_peers(
                &device
                    .peers
                    .iter()
                    .map(|p| {
                        PeerConfigBuilder::new(&p.config.public_key)
                            .set_persistent_keepalive_interval(COMMON_PKA)
                    })
                    .collect::<Vec<_>>(),
            );
            log::debug!("{ifname}: setting wgpka={} on all peers", COMMON_PKA);
            update.apply(&ifname, Backend::default())?;
        }
    };

    Ok(())
}

fn update_peer(
    iface: &InterfaceName,
    peer: &Key,
    new_endpoint: SocketAddr,
) -> Result<(), std::io::Error> {
    log::trace!(
        "updating if:{} peer {} @ {}",
        iface.as_str_lossy(),
        peer.to_base64(),
        new_endpoint,
    );

    let peer_config = PeerConfigBuilder::new(peer).set_endpoint(new_endpoint);
    let update = DeviceUpdate::new().add_peers(&[peer_config]);
    update.apply(iface, Backend::default())?;

    Ok(())
}

pub(crate) fn update_peers(
    if_name: &str,
    peer_endpoints: HashMap<String, protocol::WireplugEndpoint>,
) -> Result<Vec<Key>, std::io::Error> {
    let iface = if_name.parse()?;
    let mut peers_updated = vec![];
    for (peer, peer_endpoint) in peer_endpoints {
        let Ok(peer_pubkey) = Key::from_base64(&peer) else {
            log::error!("bad peer pubkey");
            continue;
        };
        match peer_endpoint {
            protocol::WireplugEndpoint::Unknown => log::debug!("wireplug.org: {peer} is unknown"),
            protocol::WireplugEndpoint::LocalNetwork {
                lan_addrs,
                listen_port,
            } => {
                if let Some(addr) = lan_addrs.first() {
                    log::debug!("wireplug.org: {peer} is on our local network @{addr}");
                    let ipnet = IpNet::from_str(addr.as_str())
                        .map_err(|e| std::io::Error::other(format!("{e}")))?;
                    let addr = SocketAddr::new(ipnet.addr(), listen_port);
                    update_peer(&iface, &peer_pubkey, addr)?;
                    peers_updated.push(peer_pubkey);
                }
            }
            protocol::WireplugEndpoint::RemoteNetwork(wan_addr) => {
                log::debug!("wireplug.org: {peer} is @{wan_addr}");
                update_peer(&iface, &peer_pubkey, wan_addr)?;
                peers_updated.push(peer_pubkey);
            }
        }
    }
    Ok(peers_updated)
}

pub(crate) fn update_port(ifname: &str, new_port: u16) -> Result<(), std::io::Error> {
    let iface: InterfaceName = ifname.parse()?;
    let update = DeviceUpdate::new().set_listen_port(new_port);
    update.apply(&iface, Backend::default())?;
    Ok(())
}

pub(crate) fn get_port(ifname: &str) -> Option<u16> {
    let ifname: InterfaceName = ifname.parse().ok()?;
    let dev = Device::get(&ifname, Backend::default()).ok()?;
    dev.listen_port
}

pub(crate) fn init_peers_activity(
    if_name: &str,
    peers_activity: &mut PeersActivity,
) -> Result<(), std::io::Error> {
    log::trace!("init_peers_activity()");
    let iface = if_name.parse()?;
    let device = Device::get(&iface, Backend::default())?;
    device.peers.iter().for_each(|p| {
        let _ = peers_activity.update(p);
    });
    Ok(())
}

#[allow(dead_code)]
pub(crate) fn get_inactive_peers_by_last_handshake(if_name: &str) -> anyhow::Result<Vec<Key>> {
    log::trace!("get_inactive_peers_by_handshake()");
    let iface = if_name.parse()?;
    let device = Device::get(&iface, Backend::default())?;
    log::trace!("{if_name} has {} peers", device.peers.len());
    let now = SystemTime::now();
    Ok(device
        .peers
        .iter()
        .filter(|p| match p.stats.last_handshake_time {
            Some(last_handshake) => match now.duration_since(last_handshake) {
                Ok(duration) => duration > Duration::from_secs(LAST_HANDSHAKE_MAX),
                Err(e) => {
                    log::warn!("failed to get duration since last handshake ({e})");
                    true
                }
            },
            None => true,
        })
        .map(|p| p.config.public_key.to_owned())
        .collect::<Vec<_>>())
}

pub(crate) fn get_inactive_peers_by_rx(
    if_name: &str,
    peers_activity: &mut PeersActivity,
) -> Result<Vec<Key>, std::io::Error> {
    log::trace!("get_inactive_peers_by_txrx()");
    let iface = if_name.parse()?;
    let device = Device::get(&iface, Backend::default())?;
    log::trace!("{if_name} has {} peers", device.peers.len());
    Ok(device
        .peers
        .iter()
        .filter(|p| p.stats.last_handshake_time.is_none() || !peers_activity.update(p))
        .map(|p| p.config.public_key.to_owned())
        .collect::<Vec<_>>())
}

pub(crate) fn get_all_peers(if_name: &str) -> Result<Vec<Key>, std::io::Error> {
    log::trace!("get_all_peers()");
    let iface = if_name.parse()?;
    let device = Device::get(&iface, Backend::default())?;
    log::trace!("{if_name} has {} peers", device.peers.len());
    Ok(device
        .peers
        .iter()
        .map(|p| p.config.public_key.to_owned())
        .collect::<Vec<_>>())
}
