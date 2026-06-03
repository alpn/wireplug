use std::{
    io::{Read, Write},
    net::{Ipv4Addr, TcpStream},
    time::Duration,
};

use getifaddrs::{InterfaceFlags, getifaddrs};
use ipnet::IpNet;
use rand::Rng;

pub(crate) fn get_random_port() -> u16 {
    let mut rng = rand::rng();
    rng.random_range(1024..=u16::MAX)
}

pub(crate) fn get_lan_addrs(if_wg: &str) -> std::io::Result<Vec<IpNet>> {
    let mut lan_ips = vec![];

    for ifa in getifaddrs()?.filter(|ifa| {
        ifa.flags.contains(InterfaceFlags::UP)
            && !ifa.flags.contains(InterfaceFlags::LOOPBACK)
            && !ifa.name.eq(if_wg)
            && ifa.address.is_ipv4()
            && !ifa.name.contains("wg")
            && !ifa.name.contains("utun")
    }) {
        let ipnet = match (ifa.address.ip_addr(), ifa.address.netmask()) {
            (Some(ip), Some(netmask)) => IpNet::with_netmask(ip, netmask),
            (Some(ip), None) => IpNet::new(
                ip,
                match ip.is_ipv4() {
                    true => 32,
                    false => 64,
                },
            ),
            _ => continue,
        }
        .map_err(|e| std::io::Error::other(format!("{e}")))?;
        lan_ips.push(ipnet);
    }
    Ok(lan_ips)
}

pub(crate) fn get_tls_client_connection(name: &str) -> anyhow::Result<rustls::ClientConnection> {
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
        name.to_owned().try_into()?,
    )?)
}

pub(crate) fn addrs_on_link(a: &IpNet, b: &IpNet) -> bool {
    a.contains(&b.addr()) && b.contains(&a.addr())
}

pub(crate) fn find_lan_candidates(if_wg: &str, peer_lan_addrs: &Vec<IpNet>) -> Vec<IpNet> {
    let mut candidates = vec![];
    match get_lan_addrs(if_wg) {
        Ok(our_lan_addrs) => {
            for addr in our_lan_addrs {
                for peer_addr in peer_lan_addrs {
                    if addrs_on_link(&addr, peer_addr) {
                        candidates.push(peer_addr.clone());
                    }
                }
            }
        }
        Err(e) => log::warn!("failed to get LAN addresses: {e}"),
    }
    candidates
}

fn get_ip_over_https(api_url: &str) -> Option<String> {
    let mut socket = TcpStream::connect((api_url, 443)).ok()?;
    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok();
    let mut client_connection = get_tls_client_connection(api_url).ok()?;
    let mut stream = rustls::Stream::new(&mut client_connection, &mut socket);

    let buf = "GET / HTTP/1.1\r\n\
        Host: api.ipify.org\r\n\
        User-Agent: wireplugd/0.1\r\n\
        Accept: */*\r\n\
        \r\n"
        .as_bytes();
    stream.write_all(buf).ok()?;
    let mut buf = [0u8; 1024];

    let n = stream.read(&mut buf).ok()?;
    let res = &buf[..n];
    let s = String::from_utf8_lossy(res);
    let (_, body) = s.split_once("\r\n\r\n")?;
    let s = body.trim_ascii();
    Some(s.to_owned())
}

pub(crate) fn get_ip64_over_https() -> (Option<Ipv4Addr>, Option<std::net::Ipv6Addr>) {
    let ipv4 = get_ip_over_https("api.ipify.org").and_then(|s| s.parse().ok());
    let ipv6 = get_ip_over_https("api6.ipify.org").and_then(|s| s.parse().ok());
    (ipv4, ipv6)
}

#[cfg(test)]
mod tests {
    use crate::utils::get_ip64_over_https;

    #[test]
    fn it_works() {
        let (ipv4, ipv6) = get_ip64_over_https();
        assert!(
            ipv4.is_some() || ipv6.is_some(),
            "get_ip64_over_https() failed"
        );
    }
}
