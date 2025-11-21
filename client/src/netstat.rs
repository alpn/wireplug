use std::net::{Ipv4Addr, Ipv6Addr};

use crate::utils;

#[derive(Debug, Copy, Clone)]
struct NetInfo {
    wan_ip4: Option<Ipv4Addr>,
    wan_ip6: Option<Ipv6Addr>,
    /*
    lan_addr: String,
    default_gateway: String,
    dns_server: String,
     */
}

impl PartialEq for NetInfo {
    fn eq(&self, other: &Self) -> bool {
        self.wan_ip4 == other.wan_ip4
    }
}

impl NetInfo {
    fn new() -> Self {
        Self {
            wan_ip4: None,
            wan_ip6: None,
        }
    }
    fn detect() -> Self {
        let (mut wan_ip4, wan_ip6) = innernet_publicip::get_both();
        if wan_ip4.is_none() {
            wan_ip4 = utils::get_ip_over_https();
            if wan_ip4.is_some() {
                log::warn!(
                    "Network: quad9 is unreachable, ip found via HTTPS {:?}",
                    wan_ip4
                );
            }
        }
        NetInfo { wan_ip4, wan_ip6 }
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
    last_online: NetInfo,
    hard_nat: bool,
}

pub(crate) enum NetStatus {
    ChangedToNew,
    ChangedToPrev,
    Online,
    HardNat,
    Offline,
}

impl NetworkMonitor {
    pub fn new() -> Self {
        let current = NetInfo::new();
        log::info!("NetInfo: {current:?}");
        Self {
            current,
            last_online: current,
            hard_nat: false,
        }
    }
    pub fn set_hard_nat(&mut self, hard_nat: bool) {
        self.hard_nat = hard_nat;
    }
    pub fn status(&mut self) -> NetStatus {
        let new_info = NetInfo::detect();
        log::trace!("Network: {new_info:?}");

        if new_info.offline() {
            if self.current.online() {
                self.last_online = self.current;
                self.current = new_info;
                log::trace!("Network: changed to Offline");
            }
            return NetStatus::Offline;
        }
        if new_info == self.current {
            return match self.hard_nat {
                true => NetStatus::HardNat,
                false => NetStatus::Online,
            };
        }
        if self.last_online == new_info {
            log::trace!("Network: changed to previous");
            self.current = new_info;
            return match self.hard_nat {
                true => NetStatus::HardNat,
                false => NetStatus::ChangedToPrev,
            };
        }
        log::trace!("Network: changed to new");
        log::debug!("Network: {:?}", new_info.wan_ip4);
        self.current = new_info;
        self.hard_nat = false;
        NetStatus::ChangedToNew
    }
}
