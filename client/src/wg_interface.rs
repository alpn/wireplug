use std::net::{IpAddr, SocketAddr};

use ipnet::IpNet;
use wireguard_control::{
    Backend, Device, DeviceUpdate, InterfaceName, PeerConfigBuilder, PeerInfo,
};

use crate::config;

pub(crate) fn show_config(ifname: &String) {
    println!("=========== if: {ifname} ===========");
    let ifname: InterfaceName = ifname.parse().unwrap();
    let dev = Device::get(&ifname, Backend::default()).unwrap();
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
}

//fn cmd(bin: &str, args: &[&str]) { //-> Result<std::process::Output, io::Error> {
fn cmd(bin: &str, args: &[&str]) -> Option<std::process::Output> {
    let output = std::process::Command::new(bin).args(args).output().unwrap();
    if output.status.success() {
        return Some(output);
    } else {
        println!(
            "failed to run {} {} command: {}",
            bin,
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    None
}

pub fn set_addr(interface: &InterfaceName, addr: IpNet) {
    let output = cmd(
        "ifconfig",
        &[
            &interface.to_string(),
            "inet",
            &addr.to_string(),
            &addr.addr().to_string(),
            "alias",
        ],
    )
    .unwrap();
    println!("output: {:?}", output);
}

pub fn add_route(interface: &InterfaceName, cidr: IpNet) {
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
    )
    .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        println!(
            "failed to add route for device {} ({}): {}",
            &interface, interface, stderr
        );
    }
}

pub(crate) fn configure(ifname: &String) {
    println!("configuring interface {}..", ifname);
    let ifname: InterfaceName = ifname.parse().unwrap();
    let update = config::create_interface_config();
    update.apply(&ifname, Backend::default()).unwrap();

    let addr = config::get_addr();
    set_addr(&ifname, addr);
    add_route(&ifname, addr);
}

pub(crate) fn update(iface: &InterfaceName, peer: &PeerInfo, new_endpoint: SocketAddr) {

    println!(
        "updating if:{} peer {} @ {}",
        iface.as_str_lossy(),
        peer.config.public_key.to_base64(),
        new_endpoint.to_string(),
    );

    let peer_config = PeerConfigBuilder::new(&peer.config.public_key).set_endpoint(new_endpoint);
    let update = DeviceUpdate::new().add_peers(&[peer_config]);
    update.apply(iface, Backend::default()).unwrap();
}
