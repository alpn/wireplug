use std::net::IpAddr;
use tokio::net::UdpSocket;
const RETRIES: usize = 5;

pub(crate) async fn detect_source_port(ip: &IpAddr, peer_port: u16) -> std::io::Result<u16> {
    let bind_to = format!("0.0.0.0:{}", peer_port);
    let socket = UdpSocket::bind(bind_to).await?;
    let mut buf = [0u8; 1024];
    for _ in 1..RETRIES {
        let (len, addr) = socket.recv_from(&mut buf).await?;
        if addr.ip() != *ip {
            continue;
        }
        // XXX detect wireguard
        return Ok(addr.port());
    }
    Err(std::io::Error::other(""))
}
