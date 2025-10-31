use shared::{BINCODE_CONFIG, protocol};
use std::{
    net::{SocketAddr, ToSocketAddrs, UdpSocket},
    time::Duration,
};

#[derive(Debug)]
pub(crate) struct PortMappingNat {
    pub _listen_port: u16,
    pub obsereved_port: u16,
}

impl PortMappingNat {
    fn new(listen_port: u16, observed_port: u16) -> Self {
        Self {
            _listen_port: listen_port,
            obsereved_port: observed_port,
        }
    }
}

#[derive(Debug)]
pub(crate) enum NatKind {
    Easy,
    FixedPortMapping(PortMappingNat),
    Hard,
}

fn send_stun_request(
    dst: SocketAddr,
    local_port: u16,
) -> Result<protocol::WireplugStunResponse, std::io::Error> {
    let request = protocol::WireplugStunRequest::new(local_port);
    let buf = bincode::encode_to_vec(&request, BINCODE_CONFIG)
        .map_err(|e| std::io::Error::other(format!("encoding error: {e}")))?;

    let socket = UdpSocket::bind(format!("0.0.0.0:{local_port}"))?;
    socket.set_read_timeout(Some(Duration::from_millis(500)))?;
    let _ = socket.send_to(&buf, dst)?;

    let mut res = [0u8; 1024];
    let _ = socket.recv(&mut res)?;
    let (response, _): (protocol::WireplugStunResponse, usize) =
        bincode::decode_from_slice(&res[..], BINCODE_CONFIG)
            .map_err(|e| std::io::Error::other(format!("encoding error: {e}")))?;

    Ok(response)
}

fn detect_port_mapping(local_port: u16) -> Result<NatKind, std::io::Error> {
    let stun1 = (shared::WIREPLUG_ORG_STUN1, shared::WIREPLUG_STUN_PORT)
        .to_socket_addrs()?
        .next()
        .expect("could not resolve STUN address");
    let stun2 = (shared::WIREPLUG_ORG_STUN2, shared::WIREPLUG_STUN_PORT)
        .to_socket_addrs()?
        .next()
        .expect("could not resolve STUN address");
    let nat = match (
        send_stun_request(stun1, local_port)?.result,
        send_stun_request(stun2, local_port)?.result,
    ) {
        (protocol::WireplugStunResult::SamePort, protocol::WireplugStunResult::SamePort) => {
            NatKind::Easy
        }
        (
            protocol::WireplugStunResult::DifferentPort(port1),
            protocol::WireplugStunResult::DifferentPort(port2),
        ) => {
            if port1 == port2 {
                let observed_port = port1;
                NatKind::FixedPortMapping(PortMappingNat::new(local_port, observed_port))
            } else {
                NatKind::Hard
            }
        }
        (
            protocol::WireplugStunResult::SamePort,
            protocol::WireplugStunResult::DifferentPort(_),
        )
        | (
            protocol::WireplugStunResult::DifferentPort(_),
            protocol::WireplugStunResult::SamePort,
        ) => {
            return Err(std::io::Error::other("NAT inconsistent result"));
        }
    };
    Ok(nat)
}

pub fn get_observed_port(port: u16) -> Option<u16> {
    log::trace!("get_observed_port({port})");
    let nat = match detect_port_mapping(port) {
        Ok(nat) => nat,
        Err(e) => {
            log::error!("NAT dection failed: {e}");
            return None;
        }
    };

    log::debug!("NAT: {nat:?}");
    match nat {
        NatKind::Easy => Some(port),
        NatKind::FixedPortMapping(port_mapping_nat) => Some(port_mapping_nat.obsereved_port),
        NatKind::Hard => {
            log::trace!("Destination-Dependent NAT detected");
            log::warn!("NAT traversal failed");
            None
        }
    }
}
