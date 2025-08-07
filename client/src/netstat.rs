use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, PartialEq)]
struct NetInfo {
    wan_ip4: Option<Ipv4Addr>,
    wan_ip6: Option<Ipv6Addr>,
    /*
    lan_addr: String,
    default_gateway: String,
    dns_server: String,
     */
}

impl NetInfo {
    fn new() -> Self {
        Self {
            wan_ip4: None,
            wan_ip6: None,
        }
    }
    fn detect() -> Self {
        let (wan_ip4, wan_ip6) = publicip::get_both();
        NetInfo { wan_ip4, wan_ip6 }
    }
}

pub(crate) struct NetworkMonitor {
    info: NetInfo,
}

impl NetworkMonitor {
    pub fn new() -> Self {
        Self {
            info: NetInfo::new(),
        }
    }
    pub fn has_changed(&mut self) -> bool {
        let new_info = NetInfo::detect();
        if new_info == self.info {
            return false;
        }
        log::debug!("netstat: {:?}" ,new_info);

        self.info = new_info;
        true
    }
}
