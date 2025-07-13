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
