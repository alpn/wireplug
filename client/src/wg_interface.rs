#[cfg(any(target_os = "macos", target_os = "openbsd"))]
use std::io;
use std::net::SocketAddr;

use ipnet::IpNet;
use wireguard_control::{
    Backend, Device, DeviceUpdate, InterfaceName, PeerConfigBuilder, PeerInfo,
};

use crate::config;

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
                &interface, interface.to_string(), stderr
            ),
        ))
    } else {
        Ok(!stderr.contains("File exists"))
    }
}

pub(crate) fn configure(ifname: &String) -> Result<(), std::io::Error> {
    println!("configuring interface {}..", ifname);
    let ifname: InterfaceName = ifname.parse()?;
    let update = config::create_interface_config();
    update.apply(&ifname, Backend::default())?;

    let addr = config::get_addr();
    set_addr(&ifname, addr)?;
    add_route(&ifname, addr)?;

    Ok(())
}

pub(crate) fn update(iface: &InterfaceName, peer: &PeerInfo, new_endpoint: SocketAddr) -> Result<(), std::io::Error> {
    println!(
        "updating if:{} peer {} @ {}",
        iface.as_str_lossy(),
        peer.config.public_key.to_base64(),
        new_endpoint.to_string(),
    );

    let peer_config = PeerConfigBuilder::new(&peer.config.public_key).set_endpoint(new_endpoint);
    let update = DeviceUpdate::new().add_peers(&[peer_config]);
    update.apply(iface, Backend::default())?;

    Ok(())
}
