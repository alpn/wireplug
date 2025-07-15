use shared::{protocol, BINCODE_CONFIG};
use std::net::{SocketAddr, UdpSocket};

#[derive(Debug)]
pub(crate) struct PortMappingNat {
    pub listen_port: u16,
    pub obsereved_port: u16,
}

impl PortMappingNat {
    fn new(listen_port: u16, observed_port: u16) -> Self {
        Self {
            listen_port,
            obsereved_port: observed_port,
        }
    }
}

#[derive(Debug)]
pub(crate) enum NatKind {
    Easy,
    Manageable(PortMappingNat),
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
    let _ = socket.send_to(&buf, dst)?;

    let mut res = [0u8; 1024];
    let _ = socket.recv(&mut res)?;
    let (response, _): (protocol::WireplugStunResponse, usize) =
        bincode::decode_from_slice(&res[..], BINCODE_CONFIG)
            .map_err(|e| std::io::Error::other(format!("encoding error: {e}")))?;

    Ok(response)
}

pub(crate) fn detect_kind(local_port: u16) -> Result<NatKind, std::io::Error> {
    let stun1: SocketAddr = shared::WIREPLUG_ORG_STUN1
        .parse()
        .map_err(|e| std::io::Error::other(format!("{e}")))?;

    let stun2: SocketAddr = shared::WIREPLUG_ORG_STUN2
        .parse()
        .map_err(|e| std::io::Error::other(format!("{e}")))?;

    let nat = match (
        send_stun_request(stun1, local_port)?.result,
        send_stun_request(stun2, local_port)?.result,
    ) {
        (protocol::WireplugStunResult::SamePort, protocol::WireplugStunResult::SamePort) => NatKind::Easy,
        (protocol::WireplugStunResult::DifferentPort(port1), protocol::WireplugStunResult::DifferentPort(port2)) => {
            if port1 == port2 {
                let observed_port = port1;
                NatKind::Manageable(PortMappingNat::new(local_port, observed_port))
            } else {
                NatKind::Hard
            }
        }
        (protocol::WireplugStunResult::SamePort, protocol::WireplugStunResult::DifferentPort(_)) => todo!(),
        (protocol::WireplugStunResult::DifferentPort(_), protocol::WireplugStunResult::SamePort) => todo!(),
    };
    Ok(nat)
}
