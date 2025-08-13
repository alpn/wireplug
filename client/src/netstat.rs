use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, PartialEq, Copy, Clone)]
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
        //let (wan_ip4, wan_ip6) = publicip::get_both();
        //NetInfo { wan_ip4, wan_ip6 }

        let wan_ip4 = publicip::get_v4_with_timout(1000);
        NetInfo {
            wan_ip4,
            wan_ip6: None,
        }
    }
    fn online(&self) -> bool {
        self.wan_ip4.is_some()
    }
    fn offline(&self) -> bool {
        !self.online()
    }
}

#[derive(Copy, Clone)]
pub(crate) struct NetworkMonitor {
    current: NetInfo,
    last_good: NetInfo,
}

pub(crate) enum NetStatus {
    ChangedToNew,
    ChangedToPrev,
    NoChange,
    Offline,
}

impl NetworkMonitor {
    pub fn new() -> Self {
        let current = NetInfo::new();
        log::info!("NetInfo: {current:?}");
        Self {
            current,
            last_good: current,
        }
    }
    pub fn status(&mut self) -> NetStatus {
        let new_info = NetInfo::detect();
        if new_info.offline() {
            if self.current.online() {
                self.last_good = self.current;
                self.current = new_info;
                log::trace!("Network: changed to Offline");
            }
            return NetStatus::Offline;
        }
        if new_info == self.current {
            return NetStatus::NoChange;
        }
        if self.last_good == new_info {
            log::trace!("Network: changed to previous");
            return NetStatus::ChangedToPrev;
        }
        log::trace!("Network: changed to new");
        log::debug!("Network: {:?}", new_info.wan_ip4);
        self.current = new_info;
        NetStatus::ChangedToNew
    }
}
