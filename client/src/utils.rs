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

pub(crate) fn get_lan_addrs(if_wg: &String) -> std::io::Result<Vec<String>> {
    let mut lan_ips = vec![];
    for ifa in getifaddrs()?.filter(|ifa| {
        ifa.flags.contains(InterfaceFlags::UP)
            && !ifa.flags.contains(InterfaceFlags::LOOPBACK)
            && ifa.address.is_ipv4()
            && !ifa.name.eq(if_wg)
    }) {
        let ipnet = match ifa.netmask {
            Some(mask) => IpNet::with_netmask(ifa.address, mask)
                .map_err(|e| std::io::Error::other(format!("{e}")))?,
            None => IpNet::from(ifa.address),
        };
        lan_ips.push(ipnet.to_string());
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

pub(crate) fn get_ip_over_https() -> Option<Ipv4Addr> {
    let ipify_api = "api.ipify.org";
    let mut socket = TcpStream::connect((ipify_api, 443)).ok()?;
    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok();
    let mut client_connection = get_tls_client_connection(ipify_api).ok()?;
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
    s.parse().ok()
}

#[cfg(test)]
mod tests {
    use crate::utils::get_ip_over_https;

    #[test]
    fn it_works() {
        let ip = get_ip_over_https();
        println!("ip: {:?}", ip);
    }
}
