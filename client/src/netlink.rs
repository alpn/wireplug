use ipnet::IpNet;
use netlink_packet_core::{
    NLM_F_ACK, NLM_F_CREATE, NLM_F_REPLACE, NLM_F_REQUEST,
};
use netlink_packet_route::{
    AddressFamily, RouteNetlinkMessage,
    address::{self, AddressHeader, AddressMessage},
    link::{self, LinkFlags, LinkHeader, LinkMessage},
    route::{self, RouteHeader, RouteMessage},
};
use netlink_request::netlink_request_rtnl;
use std::{io, net::IpAddr};
use wireguard_control::InterfaceName;

fn if_nametoindex(interface: &InterfaceName) -> Result<u32, io::Error> {
    match unsafe { libc::if_nametoindex(interface.as_ptr()) } {
        0 => Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("couldn't find interface '{interface}'."),
        )),
        index => Ok(index),
    }
}

pub fn set_up(interface: &InterfaceName, mtu: u32) -> Result<(), io::Error> {
    let index = if_nametoindex(interface)?;
    let header = LinkHeader {
        index,
        flags: LinkFlags::Up,
        ..Default::default()
    };
    let mut message = LinkMessage::default();
    message.header = header;
    message.attributes = vec![link::LinkAttribute::Mtu(mtu)];
    netlink_request_rtnl(RouteNetlinkMessage::SetLink(message), None)?;
    log::debug!("set interface {} up with mtu {}", interface, mtu);
    Ok(())
}

pub fn set_addr(interface: &InterfaceName, addr: IpNet) -> Result<(), io::Error> {
    let index = if_nametoindex(interface)?;
    let (family, nlas) = match addr {
        IpNet::V4(network) => {
            let addr = IpAddr::V4(network.addr());
            (
                AddressFamily::Inet,
                vec![
                    address::AddressAttribute::Local(addr),
                    address::AddressAttribute::Address(addr),
                ],
            )
        }
        IpNet::V6(network) => (
            AddressFamily::Inet6,
            vec![address::AddressAttribute::Address(IpAddr::V6(
                network.addr(),
            ))],
        ),
    };
    let header = AddressHeader {
        index,
        family,
        prefix_len: addr.prefix_len(),
        scope: address::AddressScope::Universe,
        ..Default::default()
    };

    let mut message = AddressMessage::default();
    message.header = header;
    message.attributes = nlas;
    netlink_request_rtnl(
        RouteNetlinkMessage::NewAddress(message),
        Some(NLM_F_REQUEST | NLM_F_ACK | NLM_F_REPLACE | NLM_F_CREATE),
    )?;
    log::debug!("set address {} on interface {}", addr, interface);
    Ok(())
}

pub fn add_route(interface: &InterfaceName, cidr: IpNet) -> Result<bool, io::Error> {
    let if_index = if_nametoindex(interface)?;
    let (address_family, dst) = match cidr {
        IpNet::V4(network) => (
            AddressFamily::Inet,
            route::RouteAttribute::Destination(route::RouteAddress::Inet(network.network())),
        ),
        IpNet::V6(network) => (
            AddressFamily::Inet6,
            route::RouteAttribute::Destination(route::RouteAddress::Inet6(network.network())),
        ),
    };
    let header = RouteHeader {
        table: RouteHeader::RT_TABLE_MAIN,
        protocol: route::RouteProtocol::Boot,
        scope: route::RouteScope::Link,
        kind: route::RouteType::Unicast,
        destination_prefix_length: cidr.prefix_len(),
        address_family,
        ..Default::default()
    };
    let mut message = RouteMessage::default();
    message.header = header;
    message.attributes = vec![dst, route::RouteAttribute::Oif(if_index)];

    match netlink_request_rtnl(RouteNetlinkMessage::NewRoute(message), None) {
        Ok(_) => {
            log::debug!("added route {} to interface {}", cidr, interface);
            Ok(true)
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            log::debug!("route {} already existed.", cidr);
            Ok(false)
        }
        Err(e) => Err(e),
    }
}