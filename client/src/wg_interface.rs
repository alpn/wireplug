use rand::Rng;
#[cfg(any(target_os = "macos", target_os = "openbsd"))]
use std::io;
use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use ipnet::IpNet;
use wireguard_control::{
    Backend, Device, DeviceUpdate, InterfaceName, Key, KeyPair, PeerConfigBuilder, PeerInfo,
};

use crate::{config::{self, Config}, utils};

pub(crate) fn show_config(ifname: &String) -> Result<(), std::io::Error> {
    println!("=========== if: {ifname} ===========");
    let ifname: InterfaceName = ifname.parse()?;
    let dev = Device::get(&ifname, Backend::default())?;
    if let Some(public_key) = dev.public_key {
        println!("public key: {}", public_key.to_base64());
    }
    if let Some(port) = dev.listen_port {
        println!("listen port: {}", port);
    }
    println!("peers:");
    for peer in dev.peers {
        println!("\tpublic key: {}", peer.config.public_key.to_base64());
        if let Some(endpoint) = peer.config.endpoint {
            println!("\tendpoint: {endpoint}");
        }
        println!("\tallowed IPs:");
        for aip in peer.config.allowed_ips {
            println!("\t\t{}/{}", aip.address, aip.cidr);
        }
        println!("\t---------------------------------");
    }
    println!("\n\n");

    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "openbsd"))]
fn cmd(bin: &str, args: &[&str]) -> Result<std::process::Output, io::Error> {
    let output = std::process::Command::new(bin).args(args).output()?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "failed to run {} {} command: {}",
                bin,
                args.join(" "),
                String::from_utf8_lossy(&output.stderr)
            ),
        ))
    }
}
pub fn set_addr(
    interface: &InterfaceName,
    addr: IpNet,
) -> Result<std::process::Output, std::io::Error> {
    let output = cmd(
        "ifconfig",
        &[
            &interface.to_string(),
            "inet",
            &addr.to_string(),
            &addr.addr().to_string(),
            "alias",
        ],
    )?;
    println!("set_addr: {:?}", output);
    Ok(output)
}

#[cfg(target_os = "macos")]
pub fn add_route(interface: &InterfaceName, cidr: IpNet) -> Result<bool, io::Error> {
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
            &interface.to_string(),
        ],
    )?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "failed to add route for device {} ({}): {}",
                &interface,
                interface.to_string(),
                stderr
            ),
        ))
    } else {
        Ok(!stderr.contains("File exists"))
    }
}

pub(crate) fn configure(ifname: &String, config: &Config) -> Result<(), std::io::Error> {
    println!("configuring interface {}..", ifname);
    let ifname: InterfaceName = ifname.parse()?;

    let mut peers = vec![];
    for peer in &config.peers {
        let peer_config =
            PeerConfigBuilder::new(&Key::from_base64(&peer.public_key).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Could not parse key: {e}"),
                )
            })?)
            .set_persistent_keepalive_interval(shared::COMMON_PKA)
            .add_allowed_ip(IpAddr::from_str(peer.allowed_ips.as_str()).unwrap(), 32);
        peers.push(peer_config);
    }

    let listen_port = match config.interface.listen_port {
        Some(port) => port,
        None => utils::get_random_port()
    };

    let update = DeviceUpdate::new()
        .set_keypair(KeyPair::from_private(
            Key::from_base64(&config.interface.private_key).unwrap(),
        ))
        .set_listen_port(listen_port)
        .add_peers(&peers);
    update.apply(&ifname, Backend::default())?;
    let addr = IpNet::from_str(config.interface.address.as_str()).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::Other, format!("Parsing Error: {e}"))
    })?;
    set_addr(&ifname, addr)?;
    #[cfg(target_os = "macos")]
    add_route(&ifname, addr)?;

    Ok(())
}

pub(crate) fn update_peer(
    iface: &InterfaceName,
    peer: &Key,
    new_endpoint: SocketAddr,
) -> Result<(), std::io::Error> {
    println!(
        "updating if:{} peer {} @ {}",
        iface.as_str_lossy(),
        peer.to_base64(),
        new_endpoint.to_string(),
    );

    let peer_config = PeerConfigBuilder::new(&peer).set_endpoint(new_endpoint);
    let update = DeviceUpdate::new().add_peers(&[peer_config]);
    update.apply(iface, Backend::default())?;

    Ok(())
}
